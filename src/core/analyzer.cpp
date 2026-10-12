#include "paper/core/analyzer.hpp"

#include "paper/core/x86_decoder.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <charconv>
#include <future>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

namespace paper {
namespace {

struct SectionWork {
    std::vector<Instruction> instructions;
    std::uint64_t executable_bytes = 0;
};

struct FunctionWork {
    Function function;
    std::vector<BasicBlock> blocks;
};

Json address_json(Address address) {
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << address;
    return Json(out.str());
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool contains_case_insensitive(std::string_view text, std::string_view query) {
    if (query.empty()) return true;
    const auto text_lower = lower(std::string(text));
    const auto query_lower = lower(std::string(query));
    return text_lower.find(query_lower) != std::string::npos;
}

std::optional<Address> parse_address_value(const Json* value) {
    if (!value) return std::nullopt;
    if (value->is_number()) return value->as_u64();
    if (!value->is_string()) return std::nullopt;
    const auto text = value->as_string();
    if (text.empty()) return std::nullopt;
    std::uint64_t result = 0;
    const char* first = text.data();
    const char* last = text.data() + text.size();
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) first += 2;
    const auto parsed = std::from_chars(first, last, result, 16);
    if (parsed.ec != std::errc{} || parsed.ptr != last) return std::nullopt;
    return result;
}

Json bytes_json(const Instruction& instruction) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t i = 0; i < instruction.byte_count; ++i) out << std::setw(2) << static_cast<unsigned>(instruction.bytes[i]);
    return Json(out.str());
}

Json instruction_json(const Instruction& instruction) {
    Json result = Json::object();
    result["address"] = address_json(instruction.address);
    result["length"] = static_cast<std::uint64_t>(instruction.length);
    result["bytes"] = bytes_json(instruction);
    result["mnemonic"] = instruction.mnemonic;
    result["operands"] = instruction.operands;
    result["kind"] = std::string(to_string(instruction.kind));
    if (instruction.target) result["target"] = address_json(*instruction.target);
    result["target_indirect"] = instruction.target_indirect;
    result["rip_relative"] = instruction.rip_relative;
    return result;
}

Json xref_json(const Xref& xref) {
    Json result = Json::object();
    result["from"] = address_json(xref.from);
    result["to"] = address_json(xref.to);
    result["kind"] = std::string(to_string(xref.kind));
    if (!xref.symbol.empty()) result["symbol"] = xref.symbol;
    return result;
}

bool is_prologue(const Instruction& instruction) {
    if (instruction.byte_count == 0) return false;
    // CET-enabled MSVC builds commonly put ENDBR64 at every public entry.
    if (instruction.byte_count >= 4 && instruction.bytes[0] == 0xf3 && instruction.bytes[1] == 0x0f &&
        instruction.bytes[2] == 0x1e && instruction.bytes[3] == 0xfa) return true;
    if (instruction.bytes[0] == 0x55) return true;
    if (instruction.byte_count >= 2 && instruction.bytes[0] >= 0x40 && instruction.bytes[0] <= 0x4f && instruction.bytes[1] >= 0x50 && instruction.bytes[1] <= 0x57) return true;
    if (instruction.bytes[0] >= 0x50 && instruction.bytes[0] <= 0x57) return true;
    // Common stack-frame setup sequences. The boundary check at the call
    // site below keeps an interior stack adjustment from becoming a function.
    if (instruction.byte_count >= 4 && instruction.bytes[0] == 0x48 && instruction.bytes[1] == 0x83 &&
        instruction.bytes[2] == 0xec) return true;
    if (instruction.byte_count >= 7 && instruction.bytes[0] == 0x48 && instruction.bytes[1] == 0x81 &&
        instruction.bytes[2] == 0xec) return true;
    if (instruction.byte_count >= 4 && instruction.bytes[0] == 0x48 && instruction.bytes[1] == 0x89 &&
        instruction.bytes[2] == 0x5c && instruction.bytes[3] == 0x24) return true;
    return false;
}

std::vector<std::uint8_t> parse_hex_bytes(std::string_view input) {
    std::vector<std::uint8_t> result;
    int high = -1;
    for (std::size_t index = 0; index < input.size(); ++index) {
        const char c = input[index];
        if (c == '0' && index + 1 < input.size() && (input[index + 1] == 'x' || input[index + 1] == 'X') && high < 0) {
            ++index;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c)) || c == ',' || c == '_') continue;
        const auto digit = std::isdigit(static_cast<unsigned char>(c)) ? c - '0' :
            (std::tolower(static_cast<unsigned char>(c)) >= 'a' && std::tolower(static_cast<unsigned char>(c)) <= 'f' ? std::tolower(static_cast<unsigned char>(c)) - 'a' + 10 : -1);
        if (digit < 0) return {};
        if (high < 0) high = digit;
        else {
            result.push_back(static_cast<std::uint8_t>((high << 4) | digit));
            high = -1;
        }
    }
    if (high >= 0) return {};
    return result;
}

} // namespace

Analyzer::Analyzer() = default;

bool Analyzer::open_file(const std::string& path, std::string& error) {
    PeImage image;
    if (!image.load_file(path, error)) return false;
    std::unique_lock lock(mutex_);
    image_ = std::move(image);
    instructions_.clear();
    instruction_index_.clear();
    functions_.clear();
    function_index_.clear();
    blocks_.clear();
    block_index_.clear();
    xrefs_to_.clear();
    xrefs_from_.clear();
    strings_.clear();
    stats_ = {};
    analyze();
    return true;
}

void Analyzer::clear() {
    std::unique_lock lock(mutex_);
    image_ = PeImage{};
    instructions_.clear();
    instruction_index_.clear();
    functions_.clear();
    function_index_.clear();
    blocks_.clear();
    block_index_.clear();
    xrefs_to_.clear();
    xrefs_from_.clear();
    strings_.clear();
    stats_ = {};
}

void Analyzer::analyze() {
    const auto started = std::chrono::steady_clock::now();
    const auto& sections = image_.sections();
    std::vector<SectionWork> work(sections.size());
    const std::size_t hardware = std::max(1u, std::thread::hardware_concurrency());
    const std::size_t worker_count = std::min<std::size_t>(hardware, std::max<std::size_t>(1, sections.size()));
    std::atomic<std::size_t> next_section{0};
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::size_t worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&] {
            X86Decoder decoder;
            while (true) {
                const auto index = next_section.fetch_add(1, std::memory_order_relaxed);
                if (index >= sections.size()) return;
                const Section& section = sections[index];
                if (!section.executable || section.bytes.empty()) continue;
                auto& result = work[index];
                result.executable_bytes = section.bytes.size();
                std::size_t offset = 0;
                while (offset < section.bytes.size()) {
                    if (section.bytes[offset] == 0x00 || section.bytes[offset] == 0x90 || section.bytes[offset] == 0xcc) {
                        std::size_t padding = offset;
                        while (padding < section.bytes.size() && section.bytes[padding] == section.bytes[offset]) ++padding;
                        if (padding - offset >= 8) {
                            offset = padding;
                            continue;
                        }
                    }
                    const auto window = std::span<const std::uint8_t>(section.bytes.data() + offset,
                        std::min<std::size_t>(16, section.bytes.size() - offset));
                    Instruction instruction = decoder.decode(section.start + offset, window);
                    if (instruction.length == 0 || instruction.length > section.bytes.size() - offset) instruction.length = 1;
                    result.instructions.push_back(std::move(instruction));
                    offset += result.instructions.back().length;
                }
            }
        });
    }
    for (auto& worker : workers) worker.join();

    for (auto& section_work : work) {
        instructions_.insert(instructions_.end(),
                             std::make_move_iterator(section_work.instructions.begin()),
                             std::make_move_iterator(section_work.instructions.end()));
        stats_.executable_bytes += section_work.executable_bytes;
    }
    std::sort(instructions_.begin(), instructions_.end(), [](const Instruction& a, const Instruction& b) { return a.address < b.address; });
    instructions_.erase(std::unique(instructions_.begin(), instructions_.end(), [](const Instruction& a, const Instruction& b) { return a.address == b.address; }), instructions_.end());
    instruction_index_.reserve(instructions_.size() * 2 + 1);
    for (std::size_t i = 0; i < instructions_.size(); ++i) instruction_index_.emplace(instructions_[i].address, i);

    std::vector<Address> function_starts;
    function_starts.reserve(instructions_.size() / 16 + image_.exports().size() + 4);
    function_starts.push_back(image_.info().entry_point);
    for (const auto& symbol : image_.exports()) function_starts.push_back(symbol.address);
    for (const auto& instruction : instructions_) {
        if ((instruction.kind == InstructionKind::Call || instruction.kind == InstructionKind::Jump) &&
            instruction.target && !instruction.target_indirect) {
            if (const auto* section = image_.section_for_address(*instruction.target); section && section->executable) function_starts.push_back(*instruction.target);
        }
        if (is_prologue(instruction)) {
            const auto it = instruction_index_.find(instruction.address);
            const bool at_boundary = it != instruction_index_.end() &&
                (it->second == 0 ||
                 (instructions_[it->second - 1].kind == InstructionKind::Return ||
                  instructions_[it->second - 1].kind == InstructionKind::Jump ||
                  instructions_[it->second - 1].kind == InstructionKind::IndirectJump ||
                  instructions_[it->second - 1].address + instructions_[it->second - 1].length != instruction.address));
            if (at_boundary) function_starts.push_back(instruction.address);
        }
    }
    // On x64, the PE exception directory is emitted by MSVC and LLVM for
    // most non-stripped images. These ranges are more reliable than looking
    // only for prologues and also recover leaf functions without a call site.
    for (const auto& runtime : image_.runtime_functions()) function_starts.push_back(runtime.start);
    build_functions_and_cfg(function_starts);

    std::unordered_map<Address, std::string> import_names;
    xrefs_from_.reserve(instructions_.size() * 2 + 1);
    xrefs_to_.reserve(instructions_.size() * 2 + 1);
    import_names.reserve(image_.imports().size() * 2 + 1);
    for (const auto& symbol : image_.imports()) import_names.emplace(symbol.thunk, symbol.library + "!" + symbol.name);
    for (const auto& instruction : instructions_) {
        if (!instruction.target) continue;
        Xref xref;
        xref.from = instruction.address;
        xref.to = *instruction.target;
        // A RIP-relative memory operand can still be the target of an
        // indirect call/jump (for example, a normal PE import thunk). Keep
        // the control-flow kind first so import calls participate in xrefs
        // and the call graph instead of being mislabeled as plain data.
        if (instruction.kind == InstructionKind::Call || instruction.kind == InstructionKind::IndirectCall) xref.kind = XrefKind::Call;
        else if (instruction.kind == InstructionKind::ConditionalJump) xref.kind = XrefKind::ConditionalJump;
        else if (instruction.kind == InstructionKind::Jump || instruction.kind == InstructionKind::IndirectJump) xref.kind = XrefKind::Jump;
        else if (instruction.rip_relative) xref.kind = XrefKind::Data;
        else xref.kind = XrefKind::Jump;
        if (const auto it = import_names.find(xref.to); it != import_names.end()) xref.symbol = it->second;
        xrefs_from_[xref.from].push_back(xref);
        xrefs_to_[xref.to].push_back(xref);
    }
    for (auto& [address, refs] : xrefs_to_) std::sort(refs.begin(), refs.end(), [](const Xref& a, const Xref& b) { return a.from < b.from; });
    for (auto& [address, refs] : xrefs_from_) std::sort(refs.begin(), refs.end(), [](const Xref& a, const Xref& b) { return a.to < b.to; });
    build_strings();

    stats_.file_size = image_.bytes().size();
    stats_.instruction_count = instructions_.size();
    stats_.function_count = functions_.size();
    stats_.basic_block_count = blocks_.size();
    stats_.xref_count = 0;
    for (const auto& [address, refs] : xrefs_to_) stats_.xref_count += refs.size();
    const auto function_workers = std::min<std::size_t>(std::max(1u, std::thread::hardware_concurrency()), std::max<std::size_t>(1, functions_.size()));
    stats_.worker_count = std::max(worker_count, function_workers);
    stats_.analysis_millis = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count());
}

void Analyzer::build_functions_and_cfg(const std::vector<Address>& starts) {
    std::vector<Address> sorted;
    sorted.reserve(starts.size());
    for (const auto start : starts) {
        const auto* section = image_.section_for_address(start);
        if (section && section->executable && instruction_index_.contains(start)) sorted.push_back(start);
    }
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());
    std::unordered_map<Address, std::string> export_names;
    for (const auto& symbol : image_.exports()) export_names[symbol.address] = symbol.name;
    std::unordered_map<Address, Address> runtime_ends;
    runtime_ends.reserve(image_.runtime_functions().size() * 2 + 1);
    for (const auto& runtime : image_.runtime_functions()) runtime_ends.emplace(runtime.start, runtime.end);

    std::vector<FunctionWork> work(sorted.size());
    std::atomic<std::size_t> next_function{0};
    const std::size_t worker_count = std::min<std::size_t>(std::max(1u, std::thread::hardware_concurrency()), std::max<std::size_t>(1, sorted.size()));
    auto build_one = [&](std::size_t function_number) {
        const Address start = sorted[function_number];
        const auto* section = image_.section_for_address(start);
        if (!section) return;
        Address end = section->end;
        bool has_runtime_boundary = false;
        if (const auto runtime = runtime_ends.find(start); runtime != runtime_ends.end() && runtime->second > start) {
            end = std::min(runtime->second, section->end);
            has_runtime_boundary = true;
        }
        for (std::size_t next = function_number + 1; next < sorted.size(); ++next) {
            if (sorted[next] > start && sorted[next] < end && image_.section_for_address(sorted[next]) == section) {
                end = sorted[next];
                break;
            }
        }
        // A terminal return is a useful local boundary when no later function
        // start is known. This keeps alignment padding out of the function's
        // CFG while still allowing larger functions to use the next start.
        if (!has_runtime_boundary && end == section->end) {
            const auto scan_begin = std::lower_bound(instructions_.begin(), instructions_.end(), start, [](const Instruction& instruction, Address value) { return instruction.address < value; });
            const auto scan_end = std::lower_bound(instructions_.begin(), instructions_.end(), end, [](const Instruction& instruction, Address value) { return instruction.address < value; });
            for (auto it = scan_begin; it != scan_end; ++it) {
                if (it->kind == InstructionKind::Return) {
                    end = it->address + it->length;
                    break;
                }
            }
        }
        Function function;
        function.start = start;
        function.end = end;
        function.exported = export_names.contains(start);
        function.name = function.exported ? export_names[start] : "sub_" + address_string(start).substr(2);

        std::vector<Address> block_starts{start};
        const auto begin_it = std::lower_bound(instructions_.begin(), instructions_.end(), start, [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end_it = std::lower_bound(instructions_.begin(), instructions_.end(), end, [](const Instruction& instruction, Address value) { return instruction.address < value; });
        for (auto it = begin_it; it != end_it; ++it) {
            if ((it->kind == InstructionKind::Jump || it->kind == InstructionKind::ConditionalJump) && it->target && *it->target >= start && *it->target < end && instruction_index_.contains(*it->target)) block_starts.push_back(*it->target);
            const auto next_it = std::next(it);
            if ((it->kind == InstructionKind::Jump || it->kind == InstructionKind::ConditionalJump || it->kind == InstructionKind::Return || it->kind == InstructionKind::IndirectJump) && next_it != end_it) block_starts.push_back(next_it->address);
        }
        std::sort(block_starts.begin(), block_starts.end());
        block_starts.erase(std::unique(block_starts.begin(), block_starts.end()), block_starts.end());
        std::vector<BasicBlock> local_blocks;
        local_blocks.reserve(block_starts.size());
        for (std::size_t block_number = 0; block_number < block_starts.size(); ++block_number) {
            const Address block_start = block_starts[block_number];
            const Address next_block = block_number + 1 < block_starts.size() ? block_starts[block_number + 1] : end;
            const auto block_begin = std::lower_bound(instructions_.begin(), instructions_.end(), block_start, [](const Instruction& instruction, Address value) { return instruction.address < value; });
            const auto block_end = std::lower_bound(instructions_.begin(), instructions_.end(), next_block, [](const Instruction& instruction, Address value) { return instruction.address < value; });
            if (block_begin == block_end) continue;
            BasicBlock block;
            block.start = block_start;
            const Instruction* last = &*std::prev(block_end);
            block.end = last->address + last->length;
            if (last->kind == InstructionKind::Jump) {
                if (last->target && *last->target >= start && *last->target < end) block.successors.push_back(*last->target);
            } else if (last->kind == InstructionKind::ConditionalJump) {
                if (last->target && *last->target >= start && *last->target < end) block.successors.push_back(*last->target);
                const auto fallthrough = last->address + last->length;
                if (fallthrough < end && instruction_index_.contains(fallthrough)) block.successors.push_back(fallthrough);
            } else if (last->kind != InstructionKind::Return && last->kind != InstructionKind::IndirectJump) {
                const auto fallthrough = last->address + last->length;
                if (fallthrough < end && instruction_index_.contains(fallthrough)) block.successors.push_back(fallthrough);
            }
            std::sort(block.successors.begin(), block.successors.end());
            block.successors.erase(std::unique(block.successors.begin(), block.successors.end()), block.successors.end());
            local_blocks.push_back(std::move(block));
        }
        function.thunk = local_blocks.size() == 1 && local_blocks.front().end - local_blocks.front().start <= 16;
        work[function_number] = FunctionWork{std::move(function), std::move(local_blocks)};
    };

    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::size_t worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&] {
            while (true) {
                const auto index = next_function.fetch_add(1, std::memory_order_relaxed);
                if (index >= sorted.size()) return;
                build_one(index);
            }
        });
    }
    for (auto& worker : workers) worker.join();

    for (auto& function_work : work) {
        if (function_work.function.name.empty()) continue;
        const auto function_index = functions_.size();
        functions_.push_back(std::move(function_work.function));
        function_index_[functions_.back().start] = function_index;
        for (auto& block : function_work.blocks) {
            const auto block_index = blocks_.size();
            functions_.back().blocks.push_back(block.start);
            block_index_[block.start] = block_index;
            blocks_.push_back(BlockRecord{std::move(block), function_index});
        }
    }
    for (auto& record : blocks_) {
        for (const auto successor : record.block.successors) {
            const auto it = block_index_.find(successor);
            if (it != block_index_.end()) blocks_[it->second].block.predecessors.push_back(record.block.start);
        }
    }
}

void Analyzer::build_strings() {
    for (const auto& section : image_.sections()) {
        if (section.executable || section.bytes.empty()) continue;
        std::size_t start = 0;
        while (start < section.bytes.size()) {
            while (start < section.bytes.size() && (section.bytes[start] < 0x20 || section.bytes[start] > 0x7e)) ++start;
            const auto begin = start;
            while (start < section.bytes.size() && section.bytes[start] >= 0x20 && section.bytes[start] <= 0x7e) ++start;
            if (start - begin >= 4) strings_.push_back({section.start + begin, std::string(reinterpret_cast<const char*>(section.bytes.data() + begin), start - begin)});
            if (start < section.bytes.size()) ++start;
        }
        for (std::size_t offset = 0; offset + 8 <= section.bytes.size(); ++offset) {
            std::size_t cursor = offset;
            std::string value;
            while (cursor + 1 < section.bytes.size() && section.bytes[cursor] >= 0x20 && section.bytes[cursor] <= 0x7e && section.bytes[cursor + 1] == 0) {
                value.push_back(static_cast<char>(section.bytes[cursor]));
                cursor += 2;
            }
            if (value.size() >= 4) {
                strings_.push_back({section.start + offset, std::move(value)});
                offset = cursor;
            }
        }
    }
    std::sort(strings_.begin(), strings_.end(), [](const StringLiteral& a, const StringLiteral& b) { return a.address < b.address; });
}

const Instruction* Analyzer::instruction_at(Address address) const {
    const auto it = instruction_index_.find(address);
    return it == instruction_index_.end() ? nullptr : &instructions_[it->second];
}

const Function* Analyzer::function_at(Address address) const {
    if (functions_.empty()) return nullptr;
    const auto it = std::upper_bound(functions_.begin(), functions_.end(), address, [](Address value, const Function& function) { return value < function.start; });
    if (it == functions_.begin()) return nullptr;
    const auto& function = *std::prev(it);
    return address >= function.start && address < function.end ? &function : nullptr;
}

const Section* Analyzer::section_at(Address address) const { return image_.section_for_address(address); }

Address Analyzer::argument_address(const Json& arguments, std::string_view key) {
    return parse_address_value(arguments.find(key)).value_or(0);
}

std::size_t Analyzer::argument_size(const Json& arguments, std::string_view key, std::size_t fallback) {
    const auto* value = arguments.find(key);
    if (!value || !value->is_number()) return fallback;
    return static_cast<std::size_t>(std::min<double>(value->as_number(), 1'000'000.0));
}

std::string Analyzer::address_string(Address address) {
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

Json Analyzer::module_info() const {
    std::shared_lock lock(mutex_);
    Json result = Json::object();
    if (image_.info().path.empty()) { result["loaded"] = false; return result; }
    result["loaded"] = true;
    result["path"] = image_.info().path;
    result["format"] = image_.info().format;
    result["architecture"] = image_.info().architecture;
    result["image_base"] = address_json(image_.info().image_base);
    result["entry_point"] = address_json(image_.info().entry_point);
    result["entry_rva"] = image_.info().entry_rva;
    result["image_size"] = image_.info().image_size;
    result["pe32_plus"] = image_.info().pe32_plus;
    result["runtime_function_count"] = static_cast<std::uint64_t>(image_.runtime_functions().size());
    return result;
}

Json Analyzer::list_sections() const {
    std::shared_lock lock(mutex_);
    Json result = Json::array();
    for (const auto& section : image_.sections()) {
        Json item = Json::object();
        item["name"] = section.name;
        item["rva"] = section.rva;
        item["start"] = address_json(section.start);
        item["end"] = address_json(section.end);
        item["virtual_size"] = section.virtual_size;
        item["raw_size"] = section.raw_size;
        item["executable"] = section.executable;
        item["readable"] = section.readable;
        item["writable"] = section.writable;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_functions(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 200), 10'000);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    Json result = Json::array();
    std::size_t skipped = 0;
    for (const auto& function : functions_) {
        if (!contains_case_insensitive(function.name, query)) continue;
        if (skipped++ < offset) continue;
        if (result.array_items().size() >= limit) break;
        Json item = Json::object();
        item["address"] = address_json(function.start);
        item["end"] = address_json(function.end);
        item["name"] = function.name;
        item["exported"] = function.exported;
        item["thunk"] = function.thunk;
        item["block_count"] = static_cast<std::uint64_t>(function.blocks.size());
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::get_function(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const Function* function = address ? function_at(address) : nullptr;
    if (!function) {
        const auto query = arguments.find("name") ? arguments.find("name")->string_or("") : "";
        for (const auto& candidate : functions_) if (candidate.name == query) { function = &candidate; break; }
    }
    if (!function) return Json::object();
    Json result = Json::object();
    result["address"] = address_json(function->start);
    result["end"] = address_json(function->end);
    result["name"] = function->name;
    result["exported"] = function->exported;
    result["thunk"] = function->thunk;
    Json block_list = Json::array();
    for (const auto address_value : function->blocks) block_list.push_back(address_json(address_value));
    result["blocks"] = std::move(block_list);
    return result;
}

Json Analyzer::disassemble(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto count = std::min<std::size_t>(argument_size(arguments, "count", 32), 10'000);
    Json result = Json::array();
    auto it = std::lower_bound(instructions_.begin(), instructions_.end(), address, [](const Instruction& instruction, Address value) { return instruction.address < value; });
    for (std::size_t i = 0; it != instructions_.end() && i < count; ++it, ++i) result.push_back(instruction_json(*it));
    return result;
}

Json Analyzer::read_bytes(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto requested = std::min<std::size_t>(argument_size(arguments, "count", 64), 1'000'000);
    Json result = Json::object();
    const auto* section = section_at(address);
    if (!section || address < section->start || address - section->start >= section->bytes.size()) return result;
    const auto offset = static_cast<std::size_t>(address - section->start);
    const auto count = std::min(requested, section->bytes.size() - offset);
    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < count; ++i) hex << std::setw(2) << static_cast<unsigned>(section->bytes[offset + i]);
    result["address"] = address_json(address);
    result["count"] = static_cast<std::uint64_t>(count);
    result["bytes"] = hex.str();
    result["section"] = section->name;
    result["file_offset"] = static_cast<std::uint64_t>(section->raw_offset + offset);
    return result;
}

Json Analyzer::xrefs_to(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 500), 50'000);
    Json result = Json::array();
    const auto it = xrefs_to_.find(address);
    if (it == xrefs_to_.end()) return result;
    for (std::size_t i = 0; i < it->second.size() && i < limit; ++i) result.push_back(xref_json(it->second[i]));
    return result;
}

Json Analyzer::xrefs_from(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 500), 50'000);
    Json result = Json::array();
    const auto it = xrefs_from_.find(address);
    if (it == xrefs_from_.end()) return result;
    for (std::size_t i = 0; i < it->second.size() && i < limit; ++i) result.push_back(xref_json(it->second[i]));
    return result;
}

Json Analyzer::cfg(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "function_address");
    const auto* function = function_at(address);
    if (!function) return Json::object();
    Json result = Json::object();
    Json function_json = Json::object();
    function_json["address"] = address_json(function->start);
    function_json["end"] = address_json(function->end);
    function_json["name"] = function->name;
    function_json["exported"] = function->exported;
    function_json["thunk"] = function->thunk;
    Json function_blocks = Json::array();
    for (const auto block_address : function->blocks) function_blocks.push_back(address_json(block_address));
    function_json["blocks"] = std::move(function_blocks);
    result["function"] = std::move(function_json);
    Json blocks = Json::array();
    for (const auto block_address : function->blocks) {
        const auto it = block_index_.find(block_address);
        if (it == block_index_.end()) continue;
        const auto& block = blocks_[it->second].block;
        Json item = Json::object();
        item["start"] = address_json(block.start);
        item["end"] = address_json(block.end);
        Json successors = Json::array();
        for (const auto successor : block.successors) successors.push_back(address_json(successor));
        Json predecessors = Json::array();
        for (const auto predecessor : block.predecessors) predecessors.push_back(address_json(predecessor));
        item["successors"] = std::move(successors);
        item["predecessors"] = std::move(predecessors);
        blocks.push_back(std::move(item));
    }
    result["blocks"] = std::move(blocks);
    return result;
}

Json Analyzer::search_strings(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto min_length = argument_size(arguments, "min_length", 4);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 500), 50'000);
    Json result = Json::array();
    for (const auto& literal : strings_) {
        if (literal.value.size() < min_length || !contains_case_insensitive(literal.value, query)) continue;
        Json item = Json::object();
        item["address"] = address_json(literal.address);
        item["value"] = literal.value;
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::search_bytes(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto pattern = arguments.find("pattern") ? parse_hex_bytes(arguments.find("pattern")->string_or("")) : std::vector<std::uint8_t>{};
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 200), 50'000);
    Json result = Json::array();
    if (pattern.empty() || pattern.size() > image_.bytes().size()) return result;
    for (std::size_t offset = 0; offset + pattern.size() <= image_.bytes().size(); ++offset) {
        if (!std::equal(pattern.begin(), pattern.end(), image_.bytes().begin() + offset)) continue;
        Json item = Json::object();
        item["file_offset"] = static_cast<std::uint64_t>(offset);
        for (const auto& section : image_.sections()) {
            if (offset >= section.raw_offset && offset < static_cast<std::size_t>(section.raw_offset) + section.raw_size) {
                item["section"] = section.name;
                item["address"] = address_json(section.start + (offset - section.raw_offset));
                break;
            }
        }
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::list_imports(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    Json result = Json::array();
    for (const auto& symbol : image_.imports()) {
        const auto full = symbol.library + "!" + symbol.name;
        if (!contains_case_insensitive(full, query)) continue;
        Json item = Json::object();
        item["library"] = symbol.library;
        item["name"] = symbol.name;
        item["thunk"] = address_json(symbol.thunk);
        item["by_ordinal"] = symbol.by_ordinal;
        if (symbol.by_ordinal) item["ordinal"] = symbol.ordinal;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_exports(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    Json result = Json::array();
    for (const auto& symbol : image_.exports()) {
        if (!contains_case_insensitive(symbol.name, query)) continue;
        Json item = Json::object();
        item["name"] = symbol.name;
        item["ordinal"] = symbol.ordinal;
        item["address"] = address_json(symbol.address);
        item["forwarded"] = symbol.forwarded;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::call_graph(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto start = argument_address(arguments, "function_address");
    const auto direction = arguments.find("direction") ? arguments.find("direction")->string_or("callees") : "callees";
    const auto depth = std::min<std::size_t>(argument_size(arguments, "depth", 1), 8);
    const auto* root = function_at(start);
    if (!root) return Json::object();
    std::unordered_set<Address> seen{root->start};
    std::queue<std::pair<Address, std::size_t>> pending;
    pending.push({root->start, 0});
    Json nodes = Json::array();
    Json edges = Json::array();
    while (!pending.empty()) {
        const auto [address, current_depth] = pending.front();
        pending.pop();
        const auto* function = function_at(address);
        if (!function) continue;
        Json node = Json::object();
        node["address"] = address_json(function->start);
        node["name"] = function->name;
        node["depth"] = static_cast<std::uint64_t>(current_depth);
        nodes.push_back(std::move(node));
        if (current_depth >= depth) continue;
        std::vector<Address> neighbours;
        if (direction == "callers") {
            const auto refs = xrefs_to_.find(function->start);
            if (refs != xrefs_to_.end()) for (const auto& ref : refs->second) if (ref.kind == XrefKind::Call) {
                if (const auto* caller = function_at(ref.from)) neighbours.push_back(caller->start);
            }
        } else {
            const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start, [](const Instruction& instruction, Address value) { return instruction.address < value; });
            const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end, [](const Instruction& instruction, Address value) { return instruction.address < value; });
            for (auto it = begin; it != end; ++it) if ((it->kind == InstructionKind::Call || it->kind == InstructionKind::IndirectCall) && it->target) {
                if (const auto* callee = function_at(*it->target)) neighbours.push_back(callee->start);
            }
        }
        std::sort(neighbours.begin(), neighbours.end());
        neighbours.erase(std::unique(neighbours.begin(), neighbours.end()), neighbours.end());
        for (const auto neighbour : neighbours) {
            Json edge = Json::object();
            edge["from"] = address_json(direction == "callers" ? neighbour : function->start);
            edge["to"] = address_json(direction == "callers" ? function->start : neighbour);
            edges.push_back(std::move(edge));
            if (seen.insert(neighbour).second) pending.push({neighbour, current_depth + 1});
        }
    }
    Json result = Json::object();
    result["root"] = address_json(root->start);
    result["direction"] = direction;
    result["nodes"] = std::move(nodes);
    result["edges"] = std::move(edges);
    return result;
}

Json Analyzer::analysis_stats() const {
    std::shared_lock lock(mutex_);
    Json result = Json::object();
    result["file_size"] = stats_.file_size;
    result["executable_bytes"] = stats_.executable_bytes;
    result["instruction_count"] = stats_.instruction_count;
    result["function_count"] = stats_.function_count;
    result["basic_block_count"] = stats_.basic_block_count;
    result["xref_count"] = stats_.xref_count;
    result["worker_count"] = stats_.worker_count;
    result["analysis_millis"] = stats_.analysis_millis;
    result["indexed_queries"] = true;
    return result;
}

Json Analyzer::call_tool(std::string_view name, const Json& arguments, bool& ok) const {
    ok = true;
    if (name == "module_info") return module_info();
    if (name == "list_sections") return list_sections();
    if (name == "list_functions") return list_functions(arguments);
    if (name == "get_function") return get_function(arguments);
    if (name == "disassemble") return disassemble(arguments);
    if (name == "read_bytes") return read_bytes(arguments);
    if (name == "xrefs_to") return xrefs_to(arguments);
    if (name == "xrefs_from") return xrefs_from(arguments);
    if (name == "cfg") return cfg(arguments);
    if (name == "search_strings") return search_strings(arguments);
    if (name == "search_bytes") return search_bytes(arguments);
    if (name == "list_imports") return list_imports(arguments);
    if (name == "list_exports") return list_exports(arguments);
    if (name == "call_graph") return call_graph(arguments);
    if (name == "analysis_stats") return analysis_stats();
    ok = false;
    Json error = Json::object();
    error["error"] = "unknown tool: " + std::string(name);
    return error;
}

} // namespace paper

