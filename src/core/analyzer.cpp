#include "paper/core/analyzer.hpp"

#include "paper/core/x86_decoder.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <charconv>
#include <future>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <mutex>
#include <numeric>
#include <queue>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dbghelp.h>
#endif

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
    // Keep the transform's input and output value types identical.  MSVC's
    // STL warns when a `char` from the input range is implicitly converted to
    // the lambda's `unsigned char` parameter (C4244/C4245 under /W4).
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    });
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

bool has_only_keys(const Json& arguments, std::initializer_list<std::string_view> allowed, std::string& error) {
    if (!arguments.is_object()) {
        error = "arguments must be an object";
        return false;
    }
    for (const auto& [key, value] : arguments.object_items()) {
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            error = "unknown argument: " + key;
            return false;
        }
    }
    return true;
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
    if (!instruction.destination_register.empty()) result["destination_register"] = instruction.destination_register;
    if (!instruction.source_register.empty()) result["source_register"] = instruction.source_register;
    if (!instruction.memory_base.empty()) result["memory_base"] = instruction.memory_base;
    if (!instruction.memory_index.empty()) result["memory_index"] = instruction.memory_index;
    if (!instruction.memory_base.empty() || !instruction.memory_index.empty()) {
        result["memory_scale"] = static_cast<std::uint64_t>(instruction.memory_scale);
        result["memory_displacement"] = instruction.memory_displacement;
        result["memory_read"] = instruction.memory_read;
        result["memory_write"] = instruction.memory_write;
    }
    if (instruction.immediate) result["immediate"] = address_json(*instruction.immediate);
    return result;
}

Json basic_xref_json(const Xref& xref) {
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

struct HexPattern {
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> masks;
    bool valid = false;
};

HexPattern parse_hex_pattern(std::string_view input) {
    HexPattern result;
    int high = -1;
    std::uint8_t mask = 0;
    for (std::size_t index = 0; index < input.size(); ++index) {
        const char c = input[index];
        if (c == '0' && index + 1 < input.size() && (input[index + 1] == 'x' || input[index + 1] == 'X') && high < 0) {
            ++index;
            continue;
        }
        if (std::isspace(static_cast<unsigned char>(c)) || c == ',' || c == '_') {
            if (high >= 0) return {};
            continue;
        }
        int digit = -1;
        if (std::isdigit(static_cast<unsigned char>(c))) digit = c - '0';
        else if (std::tolower(static_cast<unsigned char>(c)) >= 'a' && std::tolower(static_cast<unsigned char>(c)) <= 'f') digit = std::tolower(static_cast<unsigned char>(c)) - 'a' + 10;
        const bool wildcard = c == '?';
        if (digit < 0 && !wildcard) return {};
        if (high < 0) {
            high = wildcard ? 0 : digit;
            mask = wildcard ? 0 : 0xf0;
        } else {
            const auto value = static_cast<std::uint8_t>((high << 4) | (wildcard ? 0 : digit));
            result.bytes.push_back(value);
            result.masks.push_back(static_cast<std::uint8_t>(mask | (wildcard ? 0 : 0x0f)));
            high = -1;
            mask = 0;
        }
    }
    if (high >= 0 || result.bytes.empty()) return {};
    result.valid = true;
    return result;
}

#ifdef _WIN32
struct DbghelpSymbolContext {
    std::vector<DebugSymbol>* symbols = nullptr;
};

BOOL CALLBACK collect_dbghelp_symbol(PSYMBOL_INFO symbol, ULONG, PVOID user) {
    auto* context = static_cast<DbghelpSymbolContext*>(user);
    if (!context || !context->symbols || !symbol || symbol->Address == 0) return TRUE;
    DebugSymbol record;
    record.address = static_cast<Address>(symbol->Address);
    record.size = static_cast<std::uint64_t>(symbol->Size);
    record.name.assign(symbol->Name, symbol->NameLen);
    context->symbols->push_back(std::move(record));
    return TRUE;
}
#endif

} // namespace

Analyzer::Analyzer() = default;

Json Analyzer::xref_json(const Xref& xref) const {
    Json result = basic_xref_json(xref);
    if (const auto* instruction = instruction_at(xref.from)) {
        Json metadata = instruction_json(*instruction);
        // The outer xref already carries the site address. Keep the nested
        // object focused on decoded evidence while preserving the complete
        // instruction facts requested by machine clients.
        result["instruction"] = std::move(metadata);
        if (instruction->rip_relative || instruction->memory_displacement != 0) {
            result["displacement"] = instruction->memory_displacement;
        }
    }
    if (const auto* function = function_at(xref.from)) {
        Json owner = Json::object();
        owner["start"] = address_json(function->start);
        owner["end"] = address_json(function->end);
        owner["name"] = function->name;
        result["function"] = std::move(owner);
    }
    return result;
}

bool Analyzer::open_file(const std::string& path, std::string& error) {
    PeImage image;
    if (!image.load_file(path, error)) return false;
    {
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
        symbols_.clear();
        symbol_source_.clear();
        noreturn_targets_.clear();
        noreturn_functions_.clear();
        noreturn_reasons_.clear();
        vtable_cache_.clear();
        vtable_cache_valid_ = false;
        rtti_cache_.clear();
        rtti_cache_valid_ = false;
        {
            std::lock_guard cache_lock(switch_cache_mutex_);
            switch_cache_.clear();
        }
        mnemonic_index_.clear();
        names_.clear();
        comments_.clear();
        bookmarks_.clear();
        stats_ = {};
        database_path_ = image_.info().path + ".paper.json";
        analyze();
    }
    // An existing sidecar is optional. A failed load must not make opening a
    // valid PE fail; the GUI reports the result when the user explicitly asks
    // for a database load.
    load_database(Json::object());
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
    symbols_.clear();
    symbol_source_.clear();
    noreturn_targets_.clear();
    noreturn_functions_.clear();
    noreturn_reasons_.clear();
    vtable_cache_.clear();
    vtable_cache_valid_ = false;
    rtti_cache_.clear();
    rtti_cache_valid_ = false;
    {
        std::lock_guard cache_lock(switch_cache_mutex_);
        switch_cache_.clear();
    }
    mnemonic_index_.clear();
    names_.clear();
    comments_.clear();
    bookmarks_.clear();
    database_path_.clear();
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
    mnemonic_index_.reserve(instructions_.size() / 8 + 1);
    for (std::size_t i = 0; i < instructions_.size(); ++i) {
        instruction_index_.emplace(instructions_[i].address, i);
        mnemonic_index_[lower(instructions_[i].mnemonic)].push_back(i);
    }

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
    // Imported process-terminating APIs are exact noreturn evidence. Keep
    // their IAT slots so the CFG builder can cut the fallthrough edge even
    // before internal propagation has discovered all wrapper functions.
    for (const auto& symbol : image_.imports()) {
        if (known_noreturn_name(symbol.name)) noreturn_targets_.insert(symbol.thunk);
    }
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
    // Resolve register- and IAT-based indirect calls/jumps using the same
    // bounded, block-local facts exposed by function_dataflow.  These edges
    // are added only when the resolved value is an executable instruction,
    // so a missing or runtime-populated pointer remains absent rather than
    // becoming a guessed call edge.
    std::set<std::pair<Address, Address>> indirect_xrefs;
    for (const auto& function : functions_) {
        for (const auto& target : collect_indirect_targets(&function)) {
            if (!indirect_xrefs.insert({target.instruction, target.target}).second) continue;
            Xref xref;
            xref.from = target.instruction;
            xref.to = target.target;
            xref.kind = target.kind == InstructionKind::IndirectCall ? XrefKind::Call : XrefKind::Jump;
            if (const auto it = import_names.find(xref.to); it != import_names.end()) xref.symbol = it->second;
            xrefs_from_[xref.from].push_back(xref);
            xrefs_to_[xref.to].push_back(xref);
        }
    }
    // An indexed indirect jump has one data operand (the table address) but
    // multiple executable case edges. Add those proven edges to the same
    // xref graph used by call/jump queries so switch dispatch is not a dead
    // end in the navigation engine.
    std::set<std::pair<Address, Address>> switch_xrefs;
    for (const auto& function : functions_) {
        for (const auto& switch_record : discover_switches(&function)) {
            for (const auto target : switch_record.targets) {
                if (!switch_xrefs.insert({switch_record.instruction, target}).second) continue;
                Xref xref;
                xref.from = switch_record.instruction;
                xref.to = target;
                xref.kind = XrefKind::Jump;
                xrefs_from_[xref.from].push_back(xref);
                xrefs_to_[xref.to].push_back(xref);
            }
        }
    }
    for (auto& [address, refs] : xrefs_to_) std::sort(refs.begin(), refs.end(), [](const Xref& a, const Xref& b) { return a.from < b.from; });
    for (auto& [address, refs] : xrefs_from_) std::sort(refs.begin(), refs.end(), [](const Xref& a, const Xref& b) { return a.to < b.to; });
    vtable_cache_ = discover_vtables();
    vtable_cache_valid_ = true;
    rtti_cache_ = discover_rtti();
    rtti_cache_valid_ = true;
    propagate_noreturn();
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
        const auto switch_records = discover_switches(&function);
        for (const auto& switch_record : switch_records) {
            for (const auto target : switch_record.targets) {
                if (target >= start && target < end && instruction_index_.contains(target)) block_starts.push_back(target);
            }
        }
        const auto begin_it = std::lower_bound(instructions_.begin(), instructions_.end(), start, [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end_it = std::lower_bound(instructions_.begin(), instructions_.end(), end, [](const Instruction& instruction, Address value) { return instruction.address < value; });
        for (auto it = begin_it; it != end_it; ++it) {
            if ((it->kind == InstructionKind::Jump || it->kind == InstructionKind::ConditionalJump) && it->target && *it->target >= start && *it->target < end && instruction_index_.contains(*it->target)) block_starts.push_back(*it->target);
            const auto next_it = std::next(it);
            const bool terminal_call = (it->kind == InstructionKind::Call || it->kind == InstructionKind::IndirectCall) && it->target && is_noreturn_target(*it->target);
            if ((it->kind == InstructionKind::Jump || it->kind == InstructionKind::ConditionalJump || it->kind == InstructionKind::Return || it->kind == InstructionKind::IndirectJump || terminal_call) && next_it != end_it) block_starts.push_back(next_it->address);
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
            } else if (last->kind == InstructionKind::IndirectJump) {
                for (const auto& switch_record : switch_records) {
                    if (switch_record.instruction != last->address) continue;
                    for (const auto target : switch_record.targets) {
                        if (target >= start && target < end && instruction_index_.contains(target)) block.successors.push_back(target);
                    }
                }
            } else if (last->kind != InstructionKind::Return && last->kind != InstructionKind::IndirectJump &&
                       !((last->kind == InstructionKind::Call || last->kind == InstructionKind::IndirectCall) && last->target && is_noreturn_target(*last->target))) {
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

bool Analyzer::known_noreturn_name(std::string_view name) {
    const auto value = lower(std::string(name));
    static constexpr std::string_view exact[] = {
        "exit", "_exit", "_cexit", "quick_exit", "abort", "terminate",
        "terminateprocess", "exitprocess", "rtlexituserthread", "__fastfail",
        "raisefailfastexception", "__cxxthrowexception", "__cxa_throw",
        "__cxa_rethrow", "fatal", "fatalerror", "panic"
    };
    for (const auto candidate : exact) if (value == candidate) return true;
    return value.find("fastfail") != std::string::npos || value.find("fatal") != std::string::npos;
}

bool Analyzer::is_noreturn_target(Address address) const {
    if (noreturn_targets_.contains(address) || noreturn_functions_.contains(address)) return true;
    for (const auto& symbol : image_.imports()) {
        if (symbol.thunk == address && known_noreturn_name(symbol.name)) return true;
    }
    return false;
}

void Analyzer::propagate_noreturn() {
    noreturn_functions_.clear();
    noreturn_reasons_.clear();
    // Direct calls to known imported terminators and explicit traps are
    // deterministic evidence. Do not classify a function merely because it
    // has no decoded return; incomplete disassembly is common in packed PE
    // files and must remain UNKNOWN.
    for (const auto& function : functions_) {
        const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function.start,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function.end,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        for (auto it = begin; it != end; ++it) {
            if ((it->kind == InstructionKind::Call || it->kind == InstructionKind::IndirectCall) &&
                it->target && is_noreturn_target(*it->target)) {
                noreturn_functions_.insert(function.start);
                noreturn_reasons_[function.start] = "calls a known noreturn target at " + address_string(it->address);
                break;
            }
            if (it->kind == InstructionKind::Trap &&
                (it->mnemonic == "ud2" || it->mnemonic == "hlt" || it->mnemonic == "int3")) {
                noreturn_functions_.insert(function.start);
                noreturn_reasons_[function.start] = "terminates with " + it->mnemonic;
                break;
            }
        }
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& function : functions_) {
            if (noreturn_functions_.contains(function.start)) continue;
            const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function.start,
                [](const Instruction& instruction, Address value) { return instruction.address < value; });
            const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function.end,
                [](const Instruction& instruction, Address value) { return instruction.address < value; });
            for (auto it = begin; it != end; ++it) {
                if ((it->kind != InstructionKind::Call && it->kind != InstructionKind::IndirectCall) || !it->target) continue;
                const auto* callee = function_at(*it->target);
                if (!callee || !noreturn_functions_.contains(callee->start)) continue;
                noreturn_functions_.insert(function.start);
                noreturn_reasons_[function.start] = "calls noreturn function " + address_string(callee->start);
                changed = true;
                break;
            }
        }
    }
    // Rebuild only the affected terminal edges. This preserves the existing
    // CFG partition while making post-call bytes unreachable to callers.
    for (auto& record : blocks_) {
        const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), record.block.start,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), record.block.end,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        if (begin == end) continue;
        const auto& last = *std::prev(end);
        if ((last.kind == InstructionKind::Call || last.kind == InstructionKind::IndirectCall) && last.target && is_noreturn_target(*last.target)) {
            record.block.successors.clear();
        }
    }
    for (auto& record : blocks_) record.block.predecessors.clear();
    for (const auto& record : blocks_) {
        for (const auto successor : record.block.successors) {
            const auto it = block_index_.find(successor);
            if (it != block_index_.end()) blocks_[it->second].block.predecessors.push_back(record.block.start);
        }
    }
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
    result["tls_callback_count"] = static_cast<std::uint64_t>(image_.tls_callbacks().size());
    result["relocation_count"] = static_cast<std::uint64_t>(image_.relocations().size());
    result["resource_count"] = static_cast<std::uint64_t>(image_.resources().size());
    result["rtti_count"] = static_cast<std::uint64_t>(discover_rtti().size());
    Json pdb = Json::object();
    pdb["present"] = image_.pdb_info().present;
    pdb["path"] = image_.pdb_info().path;
    pdb["guid"] = image_.pdb_info().guid;
    pdb["age"] = image_.pdb_info().age;
    result["pdb"] = std::move(pdb);
    result["database_path"] = database_path_;
    result["name_count"] = static_cast<std::uint64_t>(names_.size());
    result["comment_count"] = static_cast<std::uint64_t>(comments_.size());
    result["bookmark_count"] = static_cast<std::uint64_t>(bookmarks_.size());
    result["symbol_count"] = static_cast<std::uint64_t>(symbols_.size());
    result["symbol_source"] = symbol_source_;
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

Json Analyzer::list_segments() const {
    return list_sections();
}

std::vector<Analyzer::VtableRecord> Analyzer::discover_vtables() const {
    if (vtable_cache_valid_) return vtable_cache_;
    std::vector<VtableRecord> tables;
    const std::size_t pointer_size = image_.info().pe32_plus ? 8 : 4;
    for (const auto& section : image_.sections()) {
        if (!section.readable || section.writable || section.executable || section.bytes.size() < pointer_size * 4) continue;
        std::size_t offset = 0;
        while (offset + pointer_size * 4 <= section.bytes.size()) {
            auto read_pointer = [&](std::size_t at) -> Address {
                Address value = 0;
                for (std::size_t byte = 0; byte < pointer_size; ++byte)
                    value |= static_cast<Address>(section.bytes[at + byte]) << (byte * 8);
                return value;
            };
            const auto read_address = [&](Address address) -> std::optional<Address> {
                const auto* target_section = image_.section_for_address(address);
                if (!target_section || address < target_section->start) return std::nullopt;
                const auto target_offset = static_cast<std::size_t>(address - target_section->start);
                if (target_offset > target_section->bytes.size() || pointer_size > target_section->bytes.size() - target_offset) return std::nullopt;
                Address value = 0;
                for (std::size_t byte = 0; byte < pointer_size; ++byte) value |= static_cast<Address>(target_section->bytes[target_offset + byte]) << (byte * 8);
                return value;
            };
            const auto rtti_boundary = [&](Address candidate) {
                if (candidate < pointer_size) return false;
                const auto locator = read_address(candidate - pointer_size);
                if (!locator || !image_.section_for_address(*locator)) return false;
                const auto* locator_section = image_.section_for_address(*locator);
                if (!locator_section->readable || locator_section->executable) return false;
                auto read_u32 = [&](Address address) -> std::optional<std::uint32_t> {
                    const auto* value_section = image_.section_for_address(address);
                    if (!value_section || address < value_section->start) return std::nullopt;
                    const auto value_offset = static_cast<std::size_t>(address - value_section->start);
                    if (value_offset > value_section->bytes.size() || 4 > value_section->bytes.size() - value_offset) return std::nullopt;
                    return static_cast<std::uint32_t>(value_section->bytes[value_offset]) |
                           (static_cast<std::uint32_t>(value_section->bytes[value_offset + 1]) << 8) |
                           (static_cast<std::uint32_t>(value_section->bytes[value_offset + 2]) << 16) |
                           (static_cast<std::uint32_t>(value_section->bytes[value_offset + 3]) << 24);
                };
                if (image_.info().pe32_plus) {
                    const auto type_rva = read_u32(*locator + 12);
                    const auto hierarchy_rva = read_u32(*locator + 16);
                    return type_rva && hierarchy_rva && image_.section_for_rva(*type_rva) && image_.section_for_rva(*hierarchy_rva);
                }
                const auto type = read_address(*locator + 12);
                const auto hierarchy = read_address(*locator + 16);
                return type && hierarchy && image_.section_for_address(*type) && image_.section_for_address(*hierarchy);
            };
            const auto points_to_code = [&](Address address) {
                const auto* target_section = image_.section_for_address(address);
                return target_section && target_section->executable && instruction_index_.contains(address);
            };
            if (!points_to_code(read_pointer(offset))) { ++offset; continue; }
            const std::size_t run_start = offset;
            std::vector<Address> pointers;
            while (offset + pointer_size <= section.bytes.size() && points_to_code(read_pointer(offset))) {
                pointers.push_back(read_pointer(offset));
                offset += pointer_size;
            }
            if (pointers.size() < 4) continue;

            std::size_t table_start = 0;
            for (std::size_t index = 1; index <= pointers.size(); ++index) {
                const bool split = index == pointers.size() || [&] {
                    const Address candidate = section.start + run_start + index * pointer_size;
                    const auto refs = xrefs_to_.find(candidate);
                    const auto installer_count = refs == xrefs_to_.end() ? 0u : static_cast<unsigned>(std::count_if(refs->second.begin(), refs->second.end(), [](const Xref& ref) {
                        return ref.kind == XrefKind::Data;
                    }));
                    // A single data reference can point at an interior slot.
                    // Require two independent installers unless the MSVC RTTI
                    // locator proves that this is a new table.
                    return installer_count >= 2 || rtti_boundary(candidate);
                }();
                if (!split) continue;
                if (index - table_start >= 4) {
                    VtableRecord table;
                    table.start = section.start + run_start + table_start * pointer_size;
                    table.end = table.start + (index - table_start) * pointer_size;
                    table.slots.assign(pointers.begin() + static_cast<std::ptrdiff_t>(table_start),
                                       pointers.begin() + static_cast<std::ptrdiff_t>(index));
                    tables.push_back(std::move(table));
                }
                table_start = index;
            }
        }
    }
    vtable_cache_ = tables;
    vtable_cache_valid_ = true;
    return tables;
}

Json Analyzer::list_vtables(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 50'000);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto rtti_records = discover_rtti();
    std::unordered_map<Address, const RttiRecord*> rtti_by_vtable;
    rtti_by_vtable.reserve(rtti_records.size());
    for (const auto& rtti : rtti_records) rtti_by_vtable.emplace(rtti.vtable, &rtti);
    Json result = Json::array();
    for (const auto& table : discover_vtables()) {
        const auto refs = xrefs_to_.find(table.start);
        Json item = Json::object();
        item["start"] = address_json(table.start);
        item["end"] = address_json(table.end);
        item["count"] = static_cast<std::uint64_t>(table.slots.size());
        item["section"] = image_.section_for_address(table.start) ? image_.section_for_address(table.start)->name : "";
        Json slots = Json::array();
        for (const auto slot : table.slots) slots.push_back(address_json(slot));
        item["slots"] = std::move(slots);
        Json installers = Json::array();
        if (refs != xrefs_to_.end()) for (const auto& ref : refs->second) if (ref.kind == XrefKind::Data) installers.push_back(xref_json(ref));
        item["installers"] = std::move(installers);
        const auto installer_count = static_cast<std::size_t>(refs == xrefs_to_.end() ? 0 : std::count_if(refs->second.begin(), refs->second.end(), [](const Xref& ref) { return ref.kind == XrefKind::Data; }));
        item["installer_count"] = static_cast<std::uint64_t>(installer_count);
        item["boundary_proven"] = installer_count >= 2;
        item["boundary_evidence"] = installer_count >= 2 ? "two_or_more_installers" : "run_terminated_without_two_installers";
        if (const auto rtti = rtti_by_vtable.find(table.start); rtti != rtti_by_vtable.end()) {
            item["rtti_type"] = rtti->second->type_name;
            item["complete_object_locator"] = address_json(rtti->second->complete_object_locator);
            item["boundary_proven"] = true;
            item["boundary_evidence"] = installer_count >= 2 ? "two_or_more_installers+rtti_locator" : "rtti_locator";
        }
        if (!query.empty() && item.dump().find(query) == std::string::npos) continue;
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::vtable_of(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    Json result = Json::array();
    if (!address) return result;
    for (const auto& table : discover_vtables()) {
        for (std::size_t index = 0; index < table.slots.size(); ++index) {
            if (table.slots[index] != address) continue;
            Json item = Json::object();
            item["vtable"] = address_json(table.start);
            item["end"] = address_json(table.end);
            item["slot"] = static_cast<std::uint64_t>(index);
            item["function"] = address_json(address);
            result.push_back(std::move(item));
        }
    }
    return result;
}

std::vector<Analyzer::SwitchRecord> Analyzer::discover_switches(const Function* function) const {
    std::vector<SwitchRecord> result;
    if (!function) return result;
    {
        std::lock_guard cache_lock(switch_cache_mutex_);
        const auto cached = switch_cache_.find(function->start);
        if (cached != switch_cache_.end()) return cached->second;
    }
    const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    auto read_unsigned = [&](Address address, std::size_t width) -> std::optional<std::uint64_t> {
        const auto* section = image_.section_for_address(address);
        if (!section || address < section->start) return std::nullopt;
        const auto offset = static_cast<std::size_t>(address - section->start);
        if (offset > section->bytes.size() || width > section->bytes.size() - offset) return std::nullopt;
        std::uint64_t value = 0;
        for (std::size_t byte = 0; byte < width; ++byte) value |= static_cast<std::uint64_t>(section->bytes[offset + byte]) << (byte * 8);
        return value;
    };
    const auto executable_instruction = [&](Address address) {
        const auto* section = image_.section_for_address(address);
        return section && section->executable && instruction_index_.contains(address);
    };
    enum class RelativeMode { Absolute, Table, Instruction, Image };
    const auto add_signed = [](Address base, std::int32_t displacement) -> Address {
        if (displacement >= 0) return base + static_cast<Address>(displacement);
        const auto magnitude = static_cast<Address>(-(static_cast<std::int64_t>(displacement)));
        return base >= magnitude ? base - magnitude : 0;
    };
    for (auto instruction = begin; instruction != end; ++instruction) {
        if (instruction->kind != InstructionKind::IndirectJump || instruction->memory_index.empty() ||
            (instruction->memory_scale != 4 && instruction->memory_scale != 8) || !instruction->target) continue;
        const auto* table_section = image_.section_for_address(*instruction->target);
        if (!table_section || table_section->executable || !table_section->readable) continue;
        const auto entry_size = static_cast<std::size_t>(instruction->memory_scale);
        const auto table_offset = static_cast<std::size_t>(*instruction->target - table_section->start);
        if (table_offset >= table_section->bytes.size()) continue;
        const auto max_entries = std::min<std::size_t>(4096, (table_section->bytes.size() - table_offset) / entry_size);
        if (max_entries < 2) continue;
        const std::vector<RelativeMode> modes = entry_size == 8
            ? std::vector<RelativeMode>{RelativeMode::Absolute}
            : std::vector<RelativeMode>{RelativeMode::Absolute, RelativeMode::Table,
                                        RelativeMode::Instruction, RelativeMode::Image};
        std::vector<std::pair<RelativeMode, std::vector<Address>>> candidates;
        for (const auto mode : modes) {
            std::vector<Address> targets;
            auto decode_target = [&](std::size_t index) -> std::optional<Address> {
                const auto entry_address = *instruction->target + index * entry_size;
                const auto raw = read_unsigned(entry_address, entry_size);
                if (!raw) return std::nullopt;
                Address target = 0;
                if (entry_size == 8 || mode == RelativeMode::Absolute) {
                    target = static_cast<Address>(*raw);
                } else {
                    const auto displacement = static_cast<std::int32_t>(static_cast<std::uint32_t>(*raw));
                    if (mode == RelativeMode::Table) target = add_signed(*instruction->target, displacement);
                    else if (mode == RelativeMode::Instruction) target = add_signed(instruction->address + instruction->length, displacement);
                    else target = add_signed(image_.info().image_base, displacement);
                }
                return executable_instruction(target) ? std::optional<Address>(target) : std::nullopt;
            };
            // Probe only the first two entries before committing to a mode.
            // This prevents four full 4096-entry scans for every indirect
            // jump while retaining the conservative ambiguity check below.
            for (std::size_t index = 0; index < 2; ++index) {
                const auto target = decode_target(index);
                if (!target) break;
                targets.push_back(*target);
            }
            if (targets.size() < 2) continue;
            for (std::size_t index = 2; index < max_entries; ++index) {
                const auto target = decode_target(index);
                if (!target) break;
                targets.push_back(*target);
            }
            if (targets.size() >= 2) candidates.emplace_back(mode, std::move(targets));
        }
        if (candidates.empty()) continue;
        // If two interpretations produce different executable runs, the
        // table is ambiguous. Returning no fact is safer than choosing a
        // heuristic interpretation.
        const auto& selected = candidates.front();
        bool ambiguous = false;
        for (std::size_t index = 1; index < candidates.size(); ++index) {
            if (candidates[index].second != selected.second) { ambiguous = true; break; }
        }
        if (ambiguous) continue;
        SwitchRecord record;
        record.instruction = instruction->address;
        record.table = *instruction->target;
        record.entry_size = entry_size;
        record.relative = selected.first != RelativeMode::Absolute;
        record.targets = selected.second;
        record.table_end = record.table + record.targets.size() * record.entry_size;
        result.push_back(std::move(record));
    }
    {
        std::lock_guard cache_lock(switch_cache_mutex_);
        switch_cache_[function->start] = result;
    }
    return result;
}

std::vector<Analyzer::IndirectTargetRecord> Analyzer::collect_indirect_targets(const Function* function) const {
    std::vector<IndirectTargetRecord> result;
    if (!function) return result;
    const std::size_t pointer_size = image_.info().pe32_plus ? 8 : 4;
    auto read_pointer = [&](Address address) -> std::optional<Address> {
        const auto* section = image_.section_for_address(address);
        if (!section || address < section->start) return std::nullopt;
        const auto offset = static_cast<std::size_t>(address - section->start);
        if (offset > section->bytes.size() || pointer_size > section->bytes.size() - offset) return std::nullopt;
        Address value = 0;
        for (std::size_t byte = 0; byte < pointer_size; ++byte) value |= static_cast<Address>(section->bytes[offset + byte]) << (byte * 8);
        return value;
    };
    const auto is_code_pointer = [&](Address address) {
        const auto* section = image_.section_for_address(address);
        return section && section->executable && instruction_index_.contains(address);
    };
    std::set<std::pair<Address, Address>> seen;
    for (const auto block_address : function->blocks) {
        const auto block_it = block_index_.find(block_address);
        if (block_it == block_index_.end()) continue;
        const auto& block = blocks_[block_it->second].block;
        const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), block.start,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), block.end,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        std::unordered_map<std::string, Address> known;
        for (auto instruction = begin; instruction != end; ++instruction) {
            const auto& current = *instruction;
            std::optional<Address> value;
            if (current.mnemonic == "mov" && current.immediate && !current.destination_register.empty()) value = *current.immediate;
            if (current.mnemonic == "lea" && current.target && !current.destination_register.empty()) value = *current.target;
            if (current.memory_read && current.target && !current.destination_register.empty()) value = read_pointer(*current.target);
            if (current.mnemonic == "xor" && !current.destination_register.empty() && current.destination_register == current.source_register) value = 0;
            if (value && !current.destination_register.empty()) {
                known[current.destination_register] = *value;
            } else if (current.mnemonic == "mov" && !current.destination_register.empty() && !current.source_register.empty()) {
                const auto source = known.find(current.source_register);
                if (source != known.end()) known[current.destination_register] = source->second;
                else known.erase(current.destination_register);
            } else if ((current.mnemonic == "add" || current.mnemonic == "sub") && current.immediate && !current.destination_register.empty()) {
                const auto source = known.find(current.destination_register);
                if (source != known.end()) {
                    const auto delta = static_cast<Address>(*current.immediate);
                    source->second = current.mnemonic == "add" ? source->second + delta : source->second - delta;
                } else {
                    known.erase(current.destination_register);
                }
            } else if (!current.destination_register.empty() && current.mnemonic != "push" && current.mnemonic != "pop") {
                known.erase(current.destination_register);
            }

            if (current.kind != InstructionKind::IndirectCall && current.kind != InstructionKind::IndirectJump) continue;
            std::optional<Address> target;
            if (!current.source_register.empty()) {
                const auto known_target = known.find(current.source_register);
                if (known_target != known.end()) target = known_target->second;
            }
            if (!target && current.memory_read && current.target) target = read_pointer(*current.target);
            if (!target || !is_code_pointer(*target) || !seen.insert({current.address, *target}).second) continue;
            result.push_back(IndirectTargetRecord{current.address, *target, current.kind});
            if (current.kind == InstructionKind::IndirectCall) {
                for (const auto& register_name : {std::string("rax"), std::string("rcx"), std::string("rdx"), std::string("r8"), std::string("r9"), std::string("r10"), std::string("r11")}) known.erase(register_name);
            }
        }
    }
    return result;
}

std::vector<Analyzer::RttiRecord> Analyzer::discover_rtti() const {
    if (rtti_cache_valid_) return rtti_cache_;
    std::vector<RttiRecord> result;
    const std::size_t pointer_size = image_.info().pe32_plus ? 8 : 4;
    auto read_pointer = [&](Address address) -> std::optional<Address> {
        const auto* section = image_.section_for_address(address);
        if (!section || address < section->start) return std::nullopt;
        const auto offset = static_cast<std::size_t>(address - section->start);
        if (offset > section->bytes.size() || pointer_size > section->bytes.size() - offset) return std::nullopt;
        Address value = 0;
        for (std::size_t byte = 0; byte < pointer_size; ++byte) value |= static_cast<Address>(section->bytes[offset + byte]) << (byte * 8);
        return value;
    };
    auto read_u32 = [&](Address address) -> std::optional<std::uint32_t> {
        const auto* section = image_.section_for_address(address);
        if (!section || address < section->start) return std::nullopt;
        const auto offset = static_cast<std::size_t>(address - section->start);
        if (offset > section->bytes.size() || 4 > section->bytes.size() - offset) return std::nullopt;
        return static_cast<std::uint32_t>(section->bytes[offset]) |
               (static_cast<std::uint32_t>(section->bytes[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(section->bytes[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(section->bytes[offset + 3]) << 24);
    };
    auto rva_address = [&](std::uint32_t rva) -> std::optional<Address> {
        return image_.section_for_rva(rva) ? std::optional<Address>(image_.info().image_base + rva) : std::nullopt;
    };
    auto descriptor_name = [&](Address descriptor) {
        const auto offset = image_.info().pe32_plus ? 16u : 8u;
        const auto* section = image_.section_for_address(descriptor + offset);
        if (!section || descriptor + offset < section->start) return std::string{};
        const auto position = static_cast<std::size_t>(descriptor + offset - section->start);
        if (position >= section->bytes.size()) return std::string{};
        std::string name;
        for (std::size_t index = position; index < section->bytes.size() && index - position < 1024 && section->bytes[index] != 0; ++index) name.push_back(static_cast<char>(section->bytes[index]));
        return name;
    };
    for (const auto& table : discover_vtables()) {
        if (table.start < pointer_size) continue;
        const auto locator = read_pointer(table.start - pointer_size);
        if (!locator || !image_.section_for_address(*locator)) continue;
        std::optional<Address> descriptor;
        std::optional<Address> hierarchy;
        if (image_.info().pe32_plus) {
            const auto type_rva = read_u32(*locator + 12);
            const auto hierarchy_rva = read_u32(*locator + 16);
            if (type_rva) descriptor = rva_address(*type_rva);
            if (hierarchy_rva) hierarchy = rva_address(*hierarchy_rva);
        } else {
            descriptor = read_pointer(*locator + 12);
            hierarchy = read_pointer(*locator + 16);
        }
        if (!descriptor || !hierarchy) continue;
        const auto type_name = descriptor_name(*descriptor);
        if (type_name.empty()) continue;
        RttiRecord record;
        record.vtable = table.start;
        record.complete_object_locator = *locator;
        record.type_descriptor = *descriptor;
        record.type_name = type_name;
        const auto count = read_u32(*hierarchy + 8);
        const auto array_rva = read_u32(*hierarchy + 12);
        if (count && array_rva && *count < 1024) {
            const auto array = image_.info().pe32_plus ? rva_address(*array_rva) : read_pointer(*hierarchy + 12);
            if (array) {
                for (std::uint32_t index = 0; index < *count; ++index) {
                    const auto base = image_.info().pe32_plus
                        ? (read_u32(*array + static_cast<Address>(index) * 4) ? rva_address(*read_u32(*array + static_cast<Address>(index) * 4)) : std::nullopt)
                        : read_pointer(*array + static_cast<Address>(index) * 4);
                    if (base) {
                        const auto base_type = image_.info().pe32_plus
                            ? (read_u32(*base) ? rva_address(*read_u32(*base)) : std::nullopt)
                            : read_pointer(*base);
                        if (base_type) {
                            const auto name = descriptor_name(*base_type);
                            if (!name.empty()) record.bases.push_back(name);
                        }
                    }
                }
            }
        }
        result.push_back(std::move(record));
    }
    rtti_cache_ = result;
    rtti_cache_valid_ = true;
    return result;
}

Json Analyzer::list_switches(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "function_address") ? argument_address(arguments, "function_address") : argument_address(arguments, "address");
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 1'000), 50'000);
    const auto* function = address ? function_at(address) : nullptr;
    Json result = Json::array();
    auto append_record = [&](const Function* owner, const SwitchRecord& record) {
        Json item = Json::object();
        item["function"] = address_json(owner->start);
        item["instruction"] = address_json(record.instruction);
        item["table"] = address_json(record.table);
        item["table_end"] = address_json(record.table_end);
        item["entry_size"] = static_cast<std::uint64_t>(record.entry_size);
        item["relative_entries"] = record.relative;
        item["case_count"] = static_cast<std::uint64_t>(record.targets.size());
        Json targets = Json::array();
        for (const auto target : record.targets) targets.push_back(address_json(target));
        item["targets"] = std::move(targets);
        result.push_back(std::move(item));
    };
    if (function) {
        for (const auto& record : discover_switches(function)) {
            append_record(function, record);
            if (result.array_items().size() >= limit) break;
        }
        return result;
    }
    for (const auto& candidate : functions_) {
        for (const auto& record : discover_switches(&candidate)) {
            append_record(&candidate, record);
            if (result.array_items().size() >= limit) return result;
        }
    }
    return result;
}

Json Analyzer::stack_variables(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "function_address") ? argument_address(arguments, "function_address") : argument_address(arguments, "address");
    const auto* function = function_at(address);
    Json result = Json::array();
    if (!function) return result;
    struct Slot { std::int64_t offset = 0; std::string base; std::size_t reads = 0; std::size_t writes = 0; std::vector<Address> references; };
    std::map<std::int64_t, Slot> slots;
    std::int64_t sp_delta = 0;
    std::int64_t minimum_sp_delta = 0;
    std::optional<std::int64_t> rbp_entry;
    const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    for (auto it = begin; it != end; ++it) {
        if (it->mnemonic == "push") sp_delta -= image_.info().pe32_plus ? 8 : 4;
        else if (it->mnemonic == "pop") sp_delta += image_.info().pe32_plus ? 8 : 4;
        if ((it->mnemonic == "sub" || it->mnemonic == "add") && it->destination_register == "rsp" && it->immediate) {
            const auto value = static_cast<std::int64_t>(*it->immediate);
            sp_delta += it->mnemonic == "sub" ? -value : value;
        }
        minimum_sp_delta = std::min(minimum_sp_delta, sp_delta);
        if (it->destination_register == "rbp" && it->source_register == "rsp") rbp_entry = sp_delta;
        if (it->memory_base != "rsp" && it->memory_base != "rbp") continue;
        std::optional<std::int64_t> logical;
        std::string base = it->memory_base;
        if (base == "rsp") logical = sp_delta + it->memory_displacement;
        else if (rbp_entry) logical = *rbp_entry + it->memory_displacement;
        if (!logical) continue;
        auto& slot = slots[*logical];
        slot.offset = *logical;
        slot.base = base;
        if (it->memory_read) ++slot.reads;
        if (it->memory_write) ++slot.writes;
        slot.references.push_back(it->address);
    }
    for (const auto& [offset, slot] : slots) {
        Json item = Json::object();
        item["offset"] = static_cast<std::int64_t>(offset);
        item["entry_rsp_offset"] = static_cast<std::int64_t>(offset);
        item["frame_offset"] = static_cast<std::int64_t>(offset - minimum_sp_delta);
        item["base"] = slot.base;
        item["reads"] = static_cast<std::uint64_t>(slot.reads);
        item["writes"] = static_cast<std::uint64_t>(slot.writes);
        item["access"] = slot.reads != 0 && slot.writes != 0 ? "read_write" : (slot.writes != 0 ? "write" : "read");
        item["frame_size"] = static_cast<std::uint64_t>(minimum_sp_delta < 0 ? -minimum_sp_delta : 0);
        item["proven_only"] = true;
        Json references = Json::array();
        for (const auto reference : slot.references) references.push_back(address_json(reference));
        item["references"] = std::move(references);
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::function_dataflow(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "function_address") ? argument_address(arguments, "function_address") : argument_address(arguments, "address");
    const auto* function = function_at(address);
    Json result = Json::object();
    Json constants = Json::array();
    Json definitions = Json::array();
    Json uses = Json::array();
    Json indirect_targets = Json::array();
    if (!function) {
        result["constants"] = std::move(constants);
        result["definitions"] = std::move(definitions);
        result["uses"] = std::move(uses);
        result["indirect_targets"] = std::move(indirect_targets);
        result["proven_only"] = true;
        return result;
    }
    auto read_pointer = [&](Address target) -> std::optional<Address> {
        const auto* section = image_.section_for_address(target);
        const auto width = image_.info().pe32_plus ? 8u : 4u;
        if (!section || target < section->start) return std::nullopt;
        const auto offset = static_cast<std::size_t>(target - section->start);
        if (offset > section->bytes.size() || width > section->bytes.size() - offset) return std::nullopt;
        Address value = 0;
        for (std::size_t byte = 0; byte < width; ++byte) value |= static_cast<Address>(section->bytes[offset + byte]) << (byte * 8);
        return value;
    };
    auto append_use = [&](Address instruction, std::string_view register_name) {
        if (register_name.empty()) return;
        Json item = Json::object();
        item["instruction"] = address_json(instruction);
        item["register"] = std::string(register_name);
        uses.push_back(std::move(item));
    };
    auto process_range = [&](Address range_start, Address range_end) {
        const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), range_start,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), range_end,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        std::unordered_map<std::string, Address> known;
        for (auto it = begin; it != end; ++it) {
            if (!it->source_register.empty()) append_use(it->address, it->source_register);
            if (!it->memory_base.empty()) append_use(it->address, it->memory_base);
            if (!it->memory_index.empty()) append_use(it->address, it->memory_index);
            std::optional<Address> value;
            std::string source;
            if (it->mnemonic == "mov" && it->immediate && !it->destination_register.empty()) {
                value = *it->immediate;
                source = "immediate";
            } else if (it->mnemonic == "lea" && it->target && !it->destination_register.empty()) {
                value = *it->target;
                source = "address";
            } else if (it->memory_read && it->target && !it->destination_register.empty()) {
                value = read_pointer(*it->target);
                source = "file_image";
            } else if (it->mnemonic == "xor" && !it->destination_register.empty() && it->destination_register == it->source_register) {
                value = 0;
                source = "self_xor";
            } else if (it->mnemonic == "mov" && !it->destination_register.empty() && !it->source_register.empty()) {
                const auto source_value = known.find(it->source_register);
                if (source_value != known.end()) {
                    value = source_value->second;
                    source = "register:" + it->source_register;
                }
            } else if ((it->mnemonic == "add" || it->mnemonic == "sub") && it->immediate && !it->destination_register.empty()) {
                const auto source_value = known.find(it->destination_register);
                if (source_value != known.end()) {
                    const auto delta = static_cast<Address>(*it->immediate);
                    value = it->mnemonic == "add" ? source_value->second + delta : source_value->second - delta;
                    source = it->mnemonic;
                }
            }
            if (value && !it->destination_register.empty()) {
                known[it->destination_register] = *value;
                Json constant = Json::object();
                constant["instruction"] = address_json(it->address);
                constant["register"] = it->destination_register;
                constant["value"] = address_json(*value);
                constant["source"] = source;
                constants.push_back(std::move(constant));
                Json definition = Json::object();
                definition["instruction"] = address_json(it->address);
                definition["register"] = it->destination_register;
                definition["value"] = address_json(*value);
                definition["source"] = source;
                definitions.push_back(std::move(definition));
            } else if (it->mnemonic == "mov" && !it->destination_register.empty()) {
                known.erase(it->destination_register);
            } else if (!it->destination_register.empty() && it->mnemonic != "push" && it->mnemonic != "pop") {
                known.erase(it->destination_register);
            }
            if (it->kind == InstructionKind::Call || it->kind == InstructionKind::IndirectCall) {
                for (const auto& register_name : {std::string("rax"), std::string("rcx"), std::string("rdx"), std::string("r8"), std::string("r9"), std::string("r10"), std::string("r11")}) known.erase(register_name);
            }
        }
    };
    if (function->blocks.empty()) process_range(function->start, function->end);
    else for (const auto block_address : function->blocks) {
        const auto block_it = block_index_.find(block_address);
        if (block_it != block_index_.end()) process_range(blocks_[block_it->second].block.start, blocks_[block_it->second].block.end);
    }
    for (const auto& target : collect_indirect_targets(function)) {
        Json item = Json::object();
        item["instruction"] = address_json(target.instruction);
        item["kind"] = target.kind == InstructionKind::IndirectCall ? "call" : "jump";
        item["target"] = address_json(target.target);
        item["source"] = "bounded_register_or_memory";
        indirect_targets.push_back(std::move(item));
    }
    result["function"] = address_json(function->start);
    result["scope"] = "block_local";
    result["proven_only"] = true;
    result["constants"] = std::move(constants);
    result["definitions"] = std::move(definitions);
    result["uses"] = std::move(uses);
    result["indirect_targets"] = std::move(indirect_targets);
    return result;
}

Json Analyzer::function_signature(const Json& arguments) const {
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        Json result = Json::array();
        for (const auto& value : addresses->array_items()) {
            Json one = Json::object();
            one["address"] = value;
            Json item = function_signature(one);
            item["address"] = value;
            result.push_back(std::move(item));
        }
        return result;
    }
    Json lookup = Json::object();
    if (const auto* address = arguments.find("address")) lookup["address"] = *address;
    else if (const auto* address = arguments.find("function_address")) lookup["address"] = *address;
    const auto summary = get_function(lookup);
    Json result = Json::object();
    if (!summary.find("address")) return result;
    result["function"] = summary.find("address") ? *summary.find("address") : Json(nullptr);
    result["name"] = summary.find("name") ? *summary.find("name") : Json("");
    const auto module = module_info();
    if (module.find("architecture")) result["architecture"] = *module.find("architecture");
    if (module.find("pe32_plus") && module.find("pe32_plus")->as_bool()) {
        result["calling_convention"] = "microsoft_x64";
        result["return_register"] = "rax";
        result["shadow_space_bytes"] = static_cast<std::uint64_t>(32);
        Json argument_registers = Json::array();
        for (const auto& register_name : {std::string("rcx"), std::string("rdx"), std::string("r8"), std::string("r9")}) {
            argument_registers.push_back(register_name);
        }
        result["argument_registers"] = std::move(argument_registers);
    }
    // Stack slots are included only when an instruction gives an exact
    // RSP/RBP-relative displacement.  No C/C++ type is invented here.
    result["stack_slots"] = stack_variables(arguments);
    result["proven_only"] = true;
    return result;
}

Json Analyzer::object_fields(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "function_address") ? argument_address(arguments, "function_address") : argument_address(arguments, "address");
    const auto* function = function_at(address);
    Json result = Json::array();
    if (!function) return result;
    struct FieldAccess {
        std::string base;
        std::int64_t offset = 0;
        std::size_t reads = 0;
        std::size_t writes = 0;
        std::vector<Address> instructions;
    };
    std::map<std::pair<std::string, std::int64_t>, FieldAccess> fields;
    const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    for (auto instruction = begin; instruction != end; ++instruction) {
        const auto& current = *instruction;
        if (current.memory_base != "rcx" && current.memory_base != "rdx" && current.memory_base != "r8" && current.memory_base != "r9") continue;
        if (!current.memory_read && !current.memory_write) continue;
        auto& field = fields[{current.memory_base, current.memory_displacement}];
        field.base = current.memory_base;
        field.offset = current.memory_displacement;
        if (current.memory_read) ++field.reads;
        if (current.memory_write) ++field.writes;
        field.instructions.push_back(current.address);
    }
    for (const auto& [key, field] : fields) {
        Json item = Json::object();
        item["base_register"] = field.base;
        item["offset"] = field.offset;
        item["access"] = field.reads != 0 && field.writes != 0 ? "read_write" : (field.writes != 0 ? "write" : "read");
        item["reads"] = static_cast<std::uint64_t>(field.reads);
        item["writes"] = static_cast<std::uint64_t>(field.writes);
        item["evidence"] = "direct_memory_operand";
        item["proven_only"] = true;
        Json references = Json::array();
        for (const auto reference : field.instructions) references.push_back(address_json(reference));
        item["references"] = std::move(references);
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::function_xrefs(const Json& arguments) const {
    Json address_arguments = Json::object();
    if (const auto* address = arguments.find("address")) address_arguments["address"] = *address;
    else if (const auto* address = arguments.find("function_address")) address_arguments["address"] = *address;
    Json result = Json::object();
    const auto outgoing = xrefs_from(address_arguments);
    const auto incoming = xrefs_to(address_arguments);
    result["outgoing"] = outgoing;
    result["incoming"] = incoming;
    result["strings"] = function_strings(address_arguments);
    result["proven_only"] = true;
    return result;
}

Json Analyzer::analyze_function(const Json& arguments) const {
    Json result = Json::object();
    Json lookup = Json::object();
    if (const auto* address = arguments.find("address")) lookup["address"] = *address;
    else if (const auto* address = arguments.find("function_address")) lookup["address"] = *address;
    const auto summary = get_function(lookup);
    if (!summary.find("address")) return result;
    result["analysis_scope"] = "single_function";
    result["proven_only"] = true;
    result["function"] = summary;
    // cfg expects function_address; preserve the caller's aliases while
    // avoiding a second address parser in the composition layer.
    Json function_arguments = Json::object();
    if (const auto* address = arguments.find("function_address")) function_arguments["function_address"] = *address;
    else if (const auto* address = arguments.find("address")) function_arguments["function_address"] = *address;
    else if (const auto* address = summary.find("address")) function_arguments["function_address"] = *address;
    result["cfg"] = cfg(function_arguments);
    result["signature"] = function_signature(function_arguments);
    result["stack_variables"] = stack_variables(function_arguments);
    result["dataflow"] = function_dataflow(function_arguments);
    result["object_fields"] = object_fields(function_arguments);
    result["xrefs"] = function_xrefs(function_arguments);
    result["switches"] = list_switches(function_arguments);
    return result;
}

Json Analyzer::list_runtime_functions(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 100'000);
    Json result = Json::array();
    std::size_t skipped = 0;
    for (const auto& runtime : image_.runtime_functions()) {
        if (skipped++ < offset) continue;
        if (result.array_items().size() >= limit) break;
        Json item = Json::object();
        item["start"] = address_json(runtime.start);
        item["end"] = address_json(runtime.end);
        item["unwind"] = address_json(runtime.unwind);
        item["unwind_flags"] = static_cast<std::uint64_t>(runtime.unwind_flags);
        item["unwind_code_count"] = static_cast<std::uint64_t>(runtime.unwind_code_count);
        if (runtime.exception_handler) item["exception_handler"] = address_json(runtime.exception_handler);
        if (runtime.handler_data) item["handler_data"] = address_json(runtime.handler_data);
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_noreturn_functions(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 50'000);
    Json result = Json::array();
    for (const auto& function : functions_) {
        if (!noreturn_functions_.contains(function.start) && !is_noreturn_target(function.start)) continue;
        if (!contains_case_insensitive(function.name, query)) continue;
        Json item = Json::object();
        item["address"] = address_json(function.start);
        item["name"] = function.name;
        item["noreturn"] = true;
        if (const auto reason = noreturn_reasons_.find(function.start); reason != noreturn_reasons_.end()) item["reason"] = reason->second;
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::list_rtti(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 1'000), 50'000);
    const auto include_methods = arguments.find("include_methods") && arguments.find("include_methods")->as_bool();
    const auto tables = discover_vtables();
    std::unordered_map<Address, const VtableRecord*> tables_by_start;
    tables_by_start.reserve(tables.size());
    for (const auto& table : tables) tables_by_start.emplace(table.start, &table);
    Json result = Json::array();
    for (const auto& record : discover_rtti()) {
        if (!query.empty() && !contains_case_insensitive(record.type_name, query)) continue;
        Json item = Json::object();
        item["vtable"] = address_json(record.vtable);
        item["complete_object_locator"] = address_json(record.complete_object_locator);
        item["type_descriptor"] = address_json(record.type_descriptor);
        item["type_name"] = record.type_name;
        if (const auto table = tables_by_start.find(record.vtable); table != tables_by_start.end()) {
            item["method_count"] = static_cast<std::uint64_t>(table->second->slots.size());
            if (include_methods) {
                Json methods = Json::array();
                for (std::size_t slot = 0; slot < table->second->slots.size(); ++slot) {
                    Json method = Json::object();
                    method["slot"] = static_cast<std::uint64_t>(slot);
                    method["address"] = address_json(table->second->slots[slot]);
                    methods.push_back(std::move(method));
                }
                item["methods"] = std::move(methods);
            }
        }
        Json bases = Json::array();
        for (const auto& base : record.bases) bases.push_back(base);
        item["bases"] = std::move(bases);
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::list_exceptions(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 100'000);
    Json result = Json::array();
    std::size_t skipped = 0;
    for (const auto& runtime : image_.runtime_functions()) {
        if (skipped++ < offset) continue;
        if (result.array_items().size() >= limit) break;
        Json item = Json::object();
        item["function_start"] = address_json(runtime.start);
        item["function_end"] = address_json(runtime.end);
        item["unwind"] = address_json(runtime.unwind);
        item["flags"] = static_cast<std::uint64_t>(runtime.unwind_flags);
        item["has_exception_handler"] = runtime.exception_handler != 0;
        if (runtime.exception_handler) item["handler"] = address_json(runtime.exception_handler);
        if (runtime.handler_data) {
            item["handler_data"] = address_json(runtime.handler_data);
            std::ostringstream raw;
            raw << std::hex << std::setfill('0');
            for (const auto byte : runtime.handler_data_bytes) raw << std::setw(2) << static_cast<unsigned>(byte);
            item["handler_data_bytes"] = raw.str();
        }
        // MSVC C++ EH language-specific data starts with a documented
        // FuncInfo magic.  Only expose the fields when the magic and every
        // referenced RVA are valid in this image; otherwise the payload is
        // left as opaque bytes rather than guessed as C++ metadata.
        auto read_u32 = [&](std::size_t offset) -> std::optional<std::uint32_t> {
            if (offset > runtime.handler_data_bytes.size() || 4 > runtime.handler_data_bytes.size() - offset) return std::nullopt;
            return static_cast<std::uint32_t>(runtime.handler_data_bytes[offset]) |
                   (static_cast<std::uint32_t>(runtime.handler_data_bytes[offset + 1]) << 8) |
                   (static_cast<std::uint32_t>(runtime.handler_data_bytes[offset + 2]) << 16) |
                   (static_cast<std::uint32_t>(runtime.handler_data_bytes[offset + 3]) << 24);
        };
        const auto magic = read_u32(0);
        const bool known_magic = magic && (*magic == 0x19930520u || *magic == 0x19930521u || *magic == 0x19930522u || *magic == 0x19930523u || *magic == 0x19930524u);
        if (known_magic && runtime.handler_data_bytes.size() >= 36) {
            const auto max_state = read_u32(4);
            const auto unwind_map = read_u32(8);
            const auto try_count = read_u32(12);
            const auto try_map = read_u32(16);
            const auto ip_count = read_u32(20);
            const auto ip_map = read_u32(24);
            const auto type_list = read_u32(28);
            const auto flags = read_u32(32);
            const auto valid_rva = [&](const std::optional<std::uint32_t>& rva) {
                return rva && (*rva == 0 || image_.section_for_rva(*rva) != nullptr);
            };
            if (max_state && *max_state < 1'000'000 && valid_rva(unwind_map) && valid_rva(try_map) &&
                valid_rva(ip_map) && valid_rva(type_list) && (ip_count && *ip_count < 1'000'000)) {
                Json cpp = Json::object();
                cpp["magic"] = address_json(*magic);
                cpp["max_state"] = static_cast<std::uint64_t>(*max_state);
                cpp["unwind_map_rva"] = static_cast<std::uint64_t>(*unwind_map);
                cpp["try_block_count"] = static_cast<std::uint64_t>(try_count.value_or(0));
                cpp["try_block_map_rva"] = static_cast<std::uint64_t>(*try_map);
                cpp["ip_map_entries"] = static_cast<std::uint64_t>(*ip_count);
                cpp["ip_state_map_rva"] = static_cast<std::uint64_t>(*ip_map);
                cpp["exception_type_list_rva"] = static_cast<std::uint64_t>(*type_list);
                if (flags) cpp["flags"] = static_cast<std::uint64_t>(*flags);
                cpp["format"] = "msvc_func_info";
                item["cpp_eh"] = std::move(cpp);
            }
        }
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_tls_callbacks(const Json&) const {
    std::shared_lock lock(mutex_);
    Json result = Json::array();
    for (const auto& callback : image_.tls_callbacks()) {
        Json item = Json::object();
        item["address"] = address_json(callback.address);
        item["function"] = function_at(callback.address) != nullptr;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_relocations(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 200'000);
    Json result = Json::array();
    for (std::size_t index = offset; index < image_.relocations().size() && result.array_items().size() < limit; ++index) {
        const auto& relocation = image_.relocations()[index];
        Json item = Json::object();
        item["address"] = address_json(relocation.address);
        item["page_rva"] = relocation.page_rva;
        item["type"] = relocation.type;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_resources(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 100'000);
    Json result = Json::array();
    for (const auto& resource : image_.resources()) {
        const auto full = resource.type + "/" + resource.name + "/" + resource.language;
        if (!contains_case_insensitive(full, query)) continue;
        Json item = Json::object();
        item["type"] = resource.type;
        item["name"] = resource.name;
        item["language"] = resource.language;
        item["data_rva"] = resource.data_rva;
        item["address"] = address_json(image_.info().image_base + resource.data_rva);
        item["size"] = resource.size;
        item["codepage"] = resource.codepage;
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::pdb_info(const Json&) const {
    std::shared_lock lock(mutex_);
    const auto& pdb = image_.pdb_info();
    Json result = Json::object();
    result["present"] = pdb.present;
    result["type"] = pdb.debug_type;
    result["path"] = pdb.path;
    result["guid"] = pdb.guid;
    result["age"] = pdb.age;
    result["symbols_loaded"] = false;
    result["note"] = "Paper exposes embedded CodeView identity; it does not invent symbols when a PDB is absent.";
    return result;
}

Json Analyzer::load_symbols(const Json& arguments) {
    std::unique_lock lock(mutex_);
    Json result = Json::object();
    if (image_.info().path.empty()) {
        result["ok"] = false;
        result["error"] = "no open image";
        return result;
    }
#ifdef _WIN32
    const auto search_path = arguments.find("path") ? arguments.find("path")->string_or("") : "";
    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
    // DbgHelp exposes the narrow entry points as the undecorated APIs in the
    // Windows SDK.  The explicit `...A` spellings are not declared by all
    // SDK revisions, so use the SDK-stable names here (the arguments are
    // deliberately narrow strings).
    if (!SymInitialize(process, search_path.empty() ? nullptr : search_path.c_str(), FALSE)) {
        result["ok"] = false;
        result["error"] = "SymInitialize failed: " + std::to_string(GetLastError());
        return result;
    }
    const auto base = SymLoadModuleEx(process, nullptr, image_.info().path.c_str(), nullptr,
                                       image_.info().image_base, image_.info().image_size, nullptr, 0);
    if (base == 0) {
        result["ok"] = false;
        result["error"] = "SymLoadModuleEx failed: " + std::to_string(GetLastError());
        SymCleanup(process);
        return result;
    }
    std::vector<DebugSymbol> symbols;
    DbghelpSymbolContext context{&symbols};
    const bool enumerated = SymEnumSymbols(process, base, nullptr, collect_dbghelp_symbol, &context) != FALSE;
    SymUnloadModule64(process, base);
    SymCleanup(process);
    if (!enumerated) {
        result["ok"] = false;
        result["error"] = "SymEnumSymbols failed: " + std::to_string(GetLastError());
        return result;
    }
    std::sort(symbols.begin(), symbols.end(), [](const DebugSymbol& left, const DebugSymbol& right) {
        return left.address < right.address;
    });
    symbols.erase(std::unique(symbols.begin(), symbols.end(), [](const DebugSymbol& left, const DebugSymbol& right) {
        return left.address == right.address && left.name == right.name;
    }), symbols.end());
    symbols_ = std::move(symbols);
    symbol_source_ = search_path.empty() ? image_.pdb_info().path : search_path;
    result["ok"] = true;
    result["source"] = symbol_source_;
    result["count"] = static_cast<std::uint64_t>(symbols_.size());
#else
    (void)arguments;
    result["ok"] = false;
    result["error"] = "external PDB symbol loading requires Windows DbgHelp";
#endif
    return result;
}

Json Analyzer::list_symbols(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 10'000), 100'000);
    Json result = Json::array();
    std::size_t skipped = 0;
    for (const auto& symbol : symbols_) {
        if (!contains_case_insensitive(symbol.name, query)) continue;
        if (skipped++ < offset) continue;
        if (result.array_items().size() >= limit) break;
        Json item = Json::object();
        item["address"] = address_json(symbol.address);
        item["size"] = symbol.size;
        item["name"] = symbol.name;
        item["source"] = symbol_source_;
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
        item["noreturn"] = noreturn_functions_.contains(function.start) || is_noreturn_target(function.start);
        item["block_count"] = static_cast<std::uint64_t>(function.blocks.size());
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::get_function(const Json& arguments) const {
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        Json result = Json::array();
        for (const auto& value : addresses->array_items()) {
            Json one = Json::object();
            one["address"] = value;
            result.push_back(get_function(one));
        }
        return result;
    }
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
    result["noreturn"] = noreturn_functions_.contains(function->start) || is_noreturn_target(function->start);
    if (const auto reason = noreturn_reasons_.find(function->start); reason != noreturn_reasons_.end()) result["noreturn_reason"] = reason->second;
    if (const auto comment = comments_.find(function->start); comment != comments_.end()) result["comment"] = comment->second;
    Json block_list = Json::array();
    for (const auto address_value : function->blocks) block_list.push_back(address_json(address_value));
    result["blocks"] = std::move(block_list);
    return result;
}

Json Analyzer::disassemble(const Json& arguments) const {
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        const auto count = argument_size(arguments, "count", 32);
        Json result = Json::array();
        for (const auto& value : addresses->array_items()) {
            Json one = Json::object();
            one["address"] = value;
            one["count"] = static_cast<std::uint64_t>(count);
            Json item = Json::object();
            item["address"] = value;
            item["instructions"] = disassemble(one);
            result.push_back(std::move(item));
        }
        return result;
    }
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto count = std::min<std::size_t>(argument_size(arguments, "count", 32), 10'000);
    Json result = Json::array();
    auto it = std::lower_bound(instructions_.begin(), instructions_.end(), address, [](const Instruction& instruction, Address value) { return instruction.address < value; });
    for (std::size_t i = 0; it != instructions_.end() && i < count; ++it, ++i) {
        Json item = instruction_json(*it);
        if (const auto name = names_.find(it->address); name != names_.end()) item["name"] = name->second;
        if (const auto comment = comments_.find(it->address); comment != comments_.end()) item["comment"] = comment->second;
        result.push_back(std::move(item));
    }
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
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        std::set<std::pair<Address, Address>> seen;
        for (const auto& value : addresses->array_items()) {
            const auto target = parse_address_value(&value);
            if (!target) continue;
            const auto it = xrefs_to_.find(*target);
            if (it == xrefs_to_.end()) continue;
            for (const auto& ref : it->second) if (seen.insert({ref.from, ref.to}).second) {
                result.push_back(xref_json(ref));
                if (result.array_items().size() >= limit) return result;
            }
        }
        return result;
    }
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
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        std::set<std::pair<Address, Address>> seen;
        for (const auto& value : addresses->array_items()) {
            const auto source = parse_address_value(&value);
            if (!source) continue;
            const auto it = xrefs_from_.find(*source);
            if (it == xrefs_from_.end()) continue;
            for (const auto& ref : it->second) if (seen.insert({ref.from, ref.to}).second) {
                result.push_back(xref_json(ref));
                if (result.array_items().size() >= limit) return result;
            }
        }
        return result;
    }
    if (const auto* function = function_at(address); function && function->start == address) {
        std::unordered_set<Address> seen;
        const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        for (auto instruction = begin; instruction != end; ++instruction) {
            const auto refs = xrefs_from_.find(instruction->address);
            if (refs == xrefs_from_.end()) continue;
            for (const auto& ref : refs->second) if (seen.insert(ref.to).second) {
                result.push_back(xref_json(ref));
                if (result.array_items().size() >= limit) return result;
            }
        }
        return result;
    }
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
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 500), 50'000);
    const auto referenced_only = arguments.find("referenced_only") && arguments.find("referenced_only")->as_bool();
    Json result = Json::array();
    std::size_t skipped = 0;
    for (const auto& literal : strings_) {
        if (literal.value.size() < min_length || !contains_case_insensitive(literal.value, query)) continue;
        std::size_t reference_count = 0;
        if (const auto refs = xrefs_to_.find(literal.address); refs != xrefs_to_.end()) reference_count = refs->second.size();
        if (referenced_only && reference_count == 0) continue;
        if (skipped++ < offset) continue;
        Json item = Json::object();
        item["address"] = address_json(literal.address);
        item["value"] = literal.value;
        item["referenced_by"] = static_cast<std::uint64_t>(reference_count);
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::list_strings(const Json& arguments) const {
    // Keep both spellings: search_strings is the MCP-friendly action while
    // list_strings is the IDA-style view name used by the GUI.
    return search_strings(arguments);
}

Json Analyzer::find_instructions(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 500), 50'000);
    std::unordered_set<Address> target_filter;
    if (const auto* values = arguments.find("target_in"); values && values->is_array()) {
        for (const auto& value : values->array_items()) if (const auto address = parse_address_value(&value)) target_filter.insert(*address);
    }
    const auto* pattern_value = arguments.find("pattern");
    const auto* sequence_value = arguments.find("sequence");
    if ((!pattern_value || !pattern_value->is_string()) && (!sequence_value || !sequence_value->is_array())) {
        Json error = Json::object();
        error["error"] = "pattern or sequence is required";
        return error;
    }
    const auto address_filter = argument_address(arguments, "address");
    const auto function_filter = argument_address(arguments, "function_address");

    auto trim = [](std::string value) {
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string::npos) return std::string{};
        const auto last = value.find_last_not_of(" \t\r\n");
        return value.substr(first, last - first + 1);
    };
    auto canonical_register = [](std::string value) {
        value = lower(std::move(value));
        if (value == "eax") return std::string("rax");
        if (value == "ebx") return std::string("rbx");
        if (value == "ecx") return std::string("rcx");
        if (value == "edx") return std::string("rdx");
        if (value == "esp") return std::string("rsp");
        if (value == "ebp") return std::string("rbp");
        if (value == "esi") return std::string("rsi");
        if (value == "edi") return std::string("rdi");
        if (value.size() > 2 && value.front() == 'r' && value.back() == 'd') return value.substr(0, value.size() - 1);
        if (value.size() > 2 && value.front() == 'r' && value.back() == 'w') return value.substr(0, value.size() - 1);
        if (value.size() > 2 && value.front() == 'r' && value.back() == 'b') return value.substr(0, value.size() - 1);
        return value;
    };
    auto match = [&](const Instruction& instruction, std::string_view requested) {
        const auto text = lower(trim(std::string(requested)));
        if (text.empty()) return false;
        const auto split = text.find_first_of(" \t");
        const auto mnemonic = text.substr(0, split);
        if (lower(instruction.mnemonic) != mnemonic) return false;
        const auto remainder = split == std::string::npos ? std::string{} : trim(text.substr(split + 1));
        if (remainder.empty()) return true;
        if (remainder.find("rip") != std::string::npos && !instruction.rip_relative) return false;
        if ((remainder.find("{disp}") != std::string::npos || remainder.find("{target}") != std::string::npos) && !instruction.target) return false;
        if ((remainder.find("imm") != std::string::npos || remainder.find("{imm}") != std::string::npos) && !instruction.immediate) return false;
        if ((remainder.find("{reg}") != std::string::npos || remainder.find("{register}") != std::string::npos) && instruction.destination_register.empty()) return false;
        const auto comma = remainder.find(',');
        if (comma != std::string::npos) {
            auto lhs = trim(remainder.substr(0, comma));
            if (!lhs.empty() && lhs.front() != '{' && lhs != "imm" && lhs != "reg" && lhs != "register" &&
                !instruction.destination_register.empty() && canonical_register(lhs) != canonical_register(instruction.destination_register)) return false;
        }
        // Literal register tokens in a memory operand are checked against the
        // structured decoder fields. Placeholders above intentionally avoid
        // requiring a guessed operand spelling.
        for (const auto& register_name : {std::string("rax"), std::string("rbx"), std::string("rcx"), std::string("rdx"),
                                          std::string("r8"), std::string("r9"), std::string("r10"), std::string("r11"),
                                          std::string("rsp"), std::string("rbp")}) {
            if (remainder.find(register_name) == std::string::npos) continue;
            if (instruction.destination_register != register_name && instruction.source_register != register_name &&
                instruction.memory_base != register_name && instruction.memory_index != register_name) return false;
        }
        return true;
    };
    auto append_match = [&](const Instruction& instruction) -> std::optional<Json> {
        if (address_filter && instruction.address != address_filter) return std::nullopt;
        if (!target_filter.empty() && (!instruction.target || !target_filter.contains(*instruction.target))) return std::nullopt;
        const auto* function = function_at(instruction.address);
        if (function_filter && (!function || function->start != function_filter)) return std::nullopt;
        Json item = Json::object();
        item["address"] = address_json(instruction.address);
        item["instruction"] = instruction_json(instruction);
        if (!instruction.destination_register.empty()) item["register"] = instruction.destination_register;
        if (instruction.target) item["target"] = address_json(*instruction.target);
        if (function) {
            Json owner = Json::object();
            owner["start"] = address_json(function->start);
            owner["end"] = address_json(function->end);
            owner["name"] = function->name;
            item["function"] = std::move(owner);
        }
        return item;
    };

    Json result = Json::array();
    if (pattern_value && pattern_value->is_string()) {
        const auto requested = pattern_value->as_string();
        std::vector<std::size_t> candidates;
        const auto mnemonic_end = requested.find_first_of(" \t");
        const auto requested_mnemonic = lower(requested.substr(0, mnemonic_end));
        if (const auto it = mnemonic_index_.find(requested_mnemonic); it != mnemonic_index_.end()) candidates = it->second;
        else if (requested_mnemonic.empty()) {
            candidates.resize(instructions_.size());
            std::iota(candidates.begin(), candidates.end(), 0);
        }
        for (const auto index : candidates) {
            if (index >= instructions_.size() || !match(instructions_[index], requested)) continue;
            if (auto item = append_match(instructions_[index])) result.push_back(std::move(*item));
            if (result.array_items().size() >= limit) break;
        }
        return result;
    }

    std::vector<std::string> sequence;
    for (const auto& item : sequence_value->array_items()) if (item.is_string()) sequence.push_back(item.as_string());
    if (sequence.empty()) return result;
    std::vector<std::size_t> candidates;
    const auto first_mnemonic_end = sequence.front().find_first_of(" \t");
    const auto first_mnemonic = lower(sequence.front().substr(0, first_mnemonic_end));
    if (const auto it = mnemonic_index_.find(first_mnemonic); it != mnemonic_index_.end()) candidates = it->second;
    for (const auto index : candidates) {
        if (index + sequence.size() > instructions_.size()) continue;
        bool matched = true;
        Address expected_address = instructions_[index].address;
        for (std::size_t offset = 0; offset < sequence.size(); ++offset) {
            if (instructions_[index + offset].address != expected_address || !match(instructions_[index + offset], sequence[offset])) {
                matched = false;
                break;
            }
            expected_address += instructions_[index + offset].length;
        }
        if (!matched) continue;
        if (address_filter && instructions_[index].address != address_filter) continue;
        const auto* function = function_at(instructions_[index].address);
        if (function_filter && (!function || function->start != function_filter)) continue;
        auto item_value = append_match(instructions_[index]);
        if (!item_value) continue;
        Json item = std::move(*item_value);
        Json matched_instructions = Json::array();
        for (std::size_t offset = 0; offset < sequence.size(); ++offset) matched_instructions.push_back(instruction_json(instructions_[index + offset]));
        item["sequence"] = std::move(matched_instructions);
        result.push_back(std::move(item));
        if (result.array_items().size() >= limit) break;
    }
    return result;
}

Json Analyzer::source_locations(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    std::vector<const Function*> functions;
    std::unordered_set<Address> seen_functions;
    auto add_address = [&](Address address) {
        if (!address) return;
        if (const auto* function = function_at(address)) {
            if (seen_functions.insert(function->start).second) functions.push_back(function);
            return;
        }
        if (const auto refs = xrefs_to_.find(address); refs != xrefs_to_.end()) {
            for (const auto& ref : refs->second) {
                if (const auto* function = function_at(ref.from); function && seen_functions.insert(function->start).second) functions.push_back(function);
            }
        }
    };
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        for (const auto& value : addresses->array_items()) if (const auto address = parse_address_value(&value)) add_address(*address);
    } else if (const auto address = argument_address(arguments, "address")) add_address(address);
    if (functions.empty()) {
        Json error = Json::object();
        error["error"] = "address or addresses must identify a function or call site";
        return error;
    }

    auto string_value = [&](Address address) -> const std::string* {
        const auto it = std::find_if(strings_.begin(), strings_.end(), [&](const StringLiteral& literal) { return literal.address == address; });
        return it == strings_.end() ? nullptr : &it->value;
    };
    auto imported_name = [&](Address address) -> std::string {
        for (const auto& symbol : image_.imports()) if (symbol.thunk == address) return symbol.name;
        return {};
    };
    auto function_name = [&](Address address) -> std::string {
        if (const auto* function = function_at(address)) return function->name;
        return imported_name(address);
    };
    auto scan_function = [&](const Function* function) {
        Json locations = Json::array();
        std::unordered_map<std::string, Address> string_registers;
        std::unordered_map<std::string, std::uint64_t> immediate_registers;
        const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end,
            [](const Instruction& instruction, Address value) { return instruction.address < value; });
        for (auto it = begin; it != end; ++it) {
            const auto destination = lower(it->destination_register);
            if ((it->mnemonic == "lea" || (it->mnemonic == "mov" && it->memory_read)) && it->target && !destination.empty() && string_value(*it->target)) {
                string_registers[destination] = *it->target;
            } else if (!destination.empty() && it->mnemonic == "mov" && it->immediate) {
                immediate_registers[destination] = *it->immediate;
                string_registers.erase(destination);
            } else if (!destination.empty() && it->mnemonic == "mov" && !it->source_register.empty()) {
                const auto source = lower(it->source_register);
                if (const auto string_it = string_registers.find(source); string_it != string_registers.end()) string_registers[destination] = string_it->second;
                else string_registers.erase(destination);
                if (const auto immediate_it = immediate_registers.find(source); immediate_it != immediate_registers.end()) immediate_registers[destination] = immediate_it->second;
                else immediate_registers.erase(destination);
            } else if (!destination.empty() && it->mnemonic != "push" && it->mnemonic != "pop") {
                string_registers.erase(destination);
                immediate_registers.erase(destination);
            }
            if (it->kind != InstructionKind::Call && it->kind != InstructionKind::IndirectCall) continue;
            const auto callee = it->target ? lower(function_name(*it->target)) : std::string{};
            const auto get_string = [&](std::string_view register_name) -> const std::string* {
                const auto found = string_registers.find(std::string(register_name));
                return found == string_registers.end() ? nullptr : string_value(found->second);
            };
            const auto get_line = [&](std::string_view register_name) -> std::optional<std::uint64_t> {
                const auto found = immediate_registers.find(std::string(register_name));
                return found == immediate_registers.end() ? std::nullopt : std::optional<std::uint64_t>(found->second);
            };
            const auto* check_file = get_string("rcx");
            const auto* check_expression = get_string("r8");
            const auto check_line = get_line("rdx");
            const auto* log_file = get_string("rdx");
            const auto* log_expression = get_string("r9");
            const auto log_line = get_line("r8");
            std::string macro;
            const std::string* file = nullptr;
            const std::string* expression = nullptr;
            std::optional<std::uint64_t> line;
            if ((callee.find("check") != std::string::npos || callee.find("assert") != std::string::npos || callee.find("verify") != std::string::npos) && check_file && check_line) {
                macro = "check"; file = check_file; expression = check_expression; line = check_line;
            } else if ((callee.find("log") != std::string::npos || callee.find("trace") != std::string::npos || callee.find("debug") != std::string::npos) && log_file && log_line) {
                macro = "log"; file = log_file; expression = log_expression; line = log_line;
            } else if (check_file && check_expression && check_line) {
                macro = "check"; file = check_file; expression = check_expression; line = check_line;
            } else if (log_file && log_expression && log_line) {
                macro = "log"; file = log_file; expression = log_expression; line = log_line;
            }
            if (!file || !line || *line == 0 || macro.empty()) continue;
            Json location = Json::object();
            location["file"] = *file;
            location["line"] = *line;
            if (expression) location["expression"] = *expression;
            location["site"] = address_json(it->address);
            location["macro"] = macro;
            locations.push_back(std::move(location));
            for (const auto& register_name : {std::string("rcx"), std::string("rdx"), std::string("r8"), std::string("r9")}) {
                string_registers.erase(register_name);
                immediate_registers.erase(register_name);
            }
        }
        return locations;
    };

    Json result = Json::object();
    result["proven_only"] = true;
    if (functions.size() == 1) {
        result["function"] = address_json(functions.front()->start);
        result["locations"] = scan_function(functions.front());
    } else {
        Json grouped = Json::array();
        for (const auto* function : functions) {
            Json item = Json::object();
            item["function"] = address_json(function->start);
            item["locations"] = scan_function(function);
            grouped.push_back(std::move(item));
        }
        result["functions"] = std::move(grouped);
    }
    return result;
}

Json Analyzer::function_strings(const Json& arguments) const {
    if (const auto* addresses = arguments.find("addresses"); addresses && addresses->is_array()) {
        Json result = Json::array();
        for (const auto& value : addresses->array_items()) {
            Json one = Json::object();
            one["address"] = value;
            Json item = Json::object();
            item["address"] = value;
            item["strings"] = function_strings(one);
            result.push_back(std::move(item));
        }
        return result;
    }
    std::shared_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto* function = function_at(address);
    Json result = Json::array();
    if (!function) return result;
    std::unordered_set<Address> seen;
    const auto begin = std::lower_bound(instructions_.begin(), instructions_.end(), function->start,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    const auto end = std::lower_bound(instructions_.begin(), instructions_.end(), function->end,
        [](const Instruction& instruction, Address value) { return instruction.address < value; });
    for (auto instruction = begin; instruction != end; ++instruction) {
        if (!instruction->target || !seen.insert(*instruction->target).second) continue;
        const auto string = std::find_if(strings_.begin(), strings_.end(), [&](const StringLiteral& literal) {
            return literal.address == *instruction->target;
        });
        if (string == strings_.end()) continue;
        Json item = Json::object();
        item["address"] = address_json(string->address);
        item["value"] = string->value;
        item["reference"] = address_json(instruction->address);
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::search_bytes(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto pattern = arguments.find("pattern") ? parse_hex_pattern(arguments.find("pattern")->string_or("")) : HexPattern{};
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 200), 50'000);
    Json result = Json::array();
    if (!pattern.valid || pattern.bytes.size() > image_.bytes().size()) return result;
    for (std::size_t offset = 0; offset + pattern.bytes.size() <= image_.bytes().size(); ++offset) {
        bool matches = true;
        for (std::size_t index = 0; index < pattern.bytes.size(); ++index) {
            if ((image_.bytes()[offset + index] & pattern.masks[index]) != (pattern.bytes[index] & pattern.masks[index])) {
                matches = false;
                break;
            }
        }
        if (!matches) continue;
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
    const auto summary = arguments.find("summary") && arguments.find("summary")->as_bool();
    Json imports = Json::array();
    for (const auto& symbol : image_.imports()) {
        const auto full = symbol.library + "!" + symbol.name;
        if (!contains_case_insensitive(full, query)) continue;
        Json item = Json::object();
        item["library"] = symbol.library;
        item["name"] = symbol.name;
        item["thunk"] = address_json(symbol.thunk);
        item["by_ordinal"] = symbol.by_ordinal;
        if (symbol.by_ordinal) item["ordinal"] = symbol.ordinal;
        if (symbol.descriptor) item["descriptor"] = address_json(symbol.descriptor);
        item["original_first_thunk"] = static_cast<std::uint64_t>(symbol.original_first_thunk);
        item["first_thunk"] = static_cast<std::uint64_t>(symbol.first_thunk);
        item["names_from_first_thunk"] = symbol.names_from_first_thunk;
        item["names_source"] = symbol.names_from_first_thunk ? "FirstThunk" : "OriginalFirstThunk";
        imports.push_back(std::move(item));
    }
    if (!summary) return imports;
    std::set<Address> descriptors;
    bool saw_descriptor = false;
    bool all_names_from_first_thunk = true;
    for (const auto& symbol : image_.imports()) {
        if (!symbol.descriptor) continue;
        saw_descriptor = true;
        descriptors.insert(symbol.descriptor);
        all_names_from_first_thunk = all_names_from_first_thunk && symbol.names_from_first_thunk;
    }
    Json result = Json::object();
    result["import_count"] = static_cast<std::uint64_t>(imports.array_items().size());
    result["descriptor_count"] = static_cast<std::uint64_t>(descriptors.size());
    if (saw_descriptor && all_names_from_first_thunk) {
        result["note"] = "every descriptor has OriginalFirstThunk == 0; the names are carried in the FirstThunk array itself";
    } else if (saw_descriptor) {
        result["note"] = "import names are carried by the descriptor's OriginalFirstThunk when present; entries with OriginalFirstThunk == 0 use FirstThunk";
    }
    result["imports"] = std::move(imports);
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
        if (symbol.forwarded) item["forwarder"] = symbol.forwarder;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_names(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto query = arguments.find("query") ? arguments.find("query")->string_or("") : "";
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 1000), 50'000);

    struct NameRecord {
        Address address = 0;
        std::string name;
        std::string kind;
    };
    std::unordered_map<Address, NameRecord> records;
    records.reserve(functions_.size() + names_.size() + image_.imports().size() + image_.exports().size());
    for (const auto& function : functions_) records[function.start] = {function.start, function.name, "function"};
    for (const auto& symbol : image_.exports()) records[symbol.address] = {symbol.address, symbol.name, "export"};
    for (const auto& symbol : image_.imports()) records[symbol.thunk] = {symbol.thunk, symbol.library + "!" + symbol.name, "import"};
    for (const auto& [address, name] : names_) records[address] = {address, name, "user"};

    std::vector<NameRecord> sorted;
    sorted.reserve(records.size());
    for (auto& [address, record] : records) {
        if (contains_case_insensitive(record.name, query)) sorted.push_back(std::move(record));
    }
    std::sort(sorted.begin(), sorted.end(), [](const NameRecord& left, const NameRecord& right) {
        return left.address < right.address;
    });

    Json result = Json::array();
    for (std::size_t index = offset; index < sorted.size() && result.array_items().size() < limit; ++index) {
        Json item = Json::object();
        item["address"] = address_json(sorted[index].address);
        item["name"] = sorted[index].name;
        item["kind"] = sorted[index].kind;
        if (const auto comment = comments_.find(sorted[index].address); comment != comments_.end()) item["comment"] = comment->second;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::list_bookmarks(const Json& arguments) const {
    std::shared_lock lock(mutex_);
    const auto offset = argument_size(arguments, "offset", 0);
    const auto limit = std::min<std::size_t>(argument_size(arguments, "limit", 1000), 50'000);
    std::vector<std::pair<Address, std::string>> sorted(bookmarks_.begin(), bookmarks_.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
    Json result = Json::array();
    for (std::size_t index = offset; index < sorted.size() && result.array_items().size() < limit; ++index) {
        Json item = Json::object();
        item["address"] = address_json(sorted[index].first);
        item["comment"] = sorted[index].second;
        result.push_back(std::move(item));
    }
    return result;
}

Json Analyzer::set_name(const Json& arguments) {
    std::unique_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto* name_value = arguments.find("name");
    if (!address || !name_value || !name_value->is_string()) {
        Json error = Json::object();
        error["ok"] = false;
        error["error"] = "address and name are required";
        return error;
    }
    const auto name = name_value->as_string();
    if (name.empty()) {
        names_.erase(address);
        if (const auto function = function_index_.find(address); function != function_index_.end()) {
            auto& record = functions_[function->second];
            record.name = "sub_" + address_string(address).substr(2);
            for (const auto& symbol : image_.exports()) {
                if (symbol.address == address) { record.name = symbol.name; break; }
            }
        }
    } else {
        names_[address] = name;
        if (const auto function = function_index_.find(address); function != function_index_.end()) functions_[function->second].name = name;
    }
    Json result = Json::object();
    result["ok"] = true;
    result["address"] = address_json(address);
    result["name"] = name;
    return result;
}

Json Analyzer::set_comment(const Json& arguments) {
    std::unique_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    const auto* comment_value = arguments.find("comment");
    if (!address || !comment_value || !comment_value->is_string()) {
        Json error = Json::object();
        error["ok"] = false;
        error["error"] = "address and comment are required";
        return error;
    }
    const auto comment = comment_value->as_string();
    if (comment.empty()) comments_.erase(address);
    else comments_[address] = comment;
    Json result = Json::object();
    result["ok"] = true;
    result["address"] = address_json(address);
    result["comment"] = comment;
    return result;
}

Json Analyzer::set_bookmark(const Json& arguments) {
    std::unique_lock lock(mutex_);
    const auto address = argument_address(arguments, "address");
    if (!address) {
        Json error = Json::object();
        error["ok"] = false;
        error["error"] = "address is required";
        return error;
    }
    const bool enabled = !arguments.find("enabled") || arguments.find("enabled")->as_bool(true);
    const auto comment = arguments.find("comment") ? arguments.find("comment")->string_or("") : "";
    if (enabled) bookmarks_[address] = comment;
    else bookmarks_.erase(address);
    Json result = Json::object();
    result["ok"] = true;
    result["address"] = address_json(address);
    result["enabled"] = enabled;
    result["comment"] = comment;
    return result;
}

Json Analyzer::save_database(const Json& arguments) {
    std::unique_lock lock(mutex_);
    std::string path = arguments.find("path") ? arguments.find("path")->string_or("") : "";
    if (path.empty()) path = database_path_;
    Json result = Json::object();
    if (path.empty() || image_.info().path.empty()) {
        result["ok"] = false;
        result["error"] = "no open image or database path";
        return result;
    }

    Json document = Json::object();
    document["version"] = 1;
    document["image"] = image_.info().path;
    Json names = Json::array();
    std::vector<std::pair<Address, std::string>> sorted_names(names_.begin(), names_.end());
    std::sort(sorted_names.begin(), sorted_names.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
    for (const auto& [address, name] : sorted_names) {
        Json item = Json::object();
        item["address"] = address_json(address);
        item["name"] = name;
        names.push_back(std::move(item));
    }
    document["names"] = std::move(names);
    Json comments = Json::array();
    std::vector<std::pair<Address, std::string>> sorted_comments(comments_.begin(), comments_.end());
    std::sort(sorted_comments.begin(), sorted_comments.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
    for (const auto& [address, comment] : sorted_comments) {
        Json item = Json::object();
        item["address"] = address_json(address);
        item["comment"] = comment;
        comments.push_back(std::move(item));
    }
    document["comments"] = std::move(comments);
    Json bookmarks = Json::array();
    std::vector<std::pair<Address, std::string>> sorted_bookmarks(bookmarks_.begin(), bookmarks_.end());
    std::sort(sorted_bookmarks.begin(), sorted_bookmarks.end(), [](const auto& left, const auto& right) { return left.first < right.first; });
    for (const auto& [address, comment] : sorted_bookmarks) {
        Json item = Json::object();
        item["address"] = address_json(address);
        item["comment"] = comment;
        bookmarks.push_back(std::move(item));
    }
    document["bookmarks"] = std::move(bookmarks);

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        result["ok"] = false;
        result["error"] = "cannot write database: " + path;
        return result;
    }
    output << document.dump() << '\n';
    if (!output.good()) {
        result["ok"] = false;
        result["error"] = "database write failed: " + path;
        return result;
    }
    database_path_ = path;
    result["ok"] = true;
    result["path"] = path;
    result["name_count"] = static_cast<std::uint64_t>(names_.size());
    result["comment_count"] = static_cast<std::uint64_t>(comments_.size());
    result["bookmark_count"] = static_cast<std::uint64_t>(bookmarks_.size());
    return result;
}

Json Analyzer::load_database(const Json& arguments) {
    std::string path;
    {
        std::shared_lock lock(mutex_);
        path = arguments.find("path") ? arguments.find("path")->string_or("") : "";
        if (path.empty()) path = database_path_;
        if (path.empty() && !image_.info().path.empty()) path = image_.info().path + ".paper.json";
    }
    Json result = Json::object();
    if (path.empty()) {
        result["ok"] = false;
        result["error"] = "no open image or database path";
        return result;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        result["ok"] = false;
        result["error"] = "database not found: " + path;
        return result;
    }
    try {
        const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        const Json document = Json::parse(text);
        std::unordered_map<Address, std::string> names;
        std::unordered_map<Address, std::string> comments;
        std::unordered_map<Address, std::string> bookmarks;
        auto read_entries = [](const Json* array, auto& output, std::string_view value_key) {
            if (!array || !array->is_array()) return;
            for (const auto& item : array->array_items()) {
                const auto address = parse_address_value(item.find("address"));
                const auto* value = item.find(value_key);
                if (address && value && value->is_string() && *address) output[*address] = value->as_string();
            }
        };
        read_entries(document.find("names"), names, "name");
        read_entries(document.find("comments"), comments, "comment");
        read_entries(document.find("bookmarks"), bookmarks, "comment");

        std::unique_lock lock(mutex_);
        names_ = std::move(names);
        comments_ = std::move(comments);
        bookmarks_ = std::move(bookmarks);
        database_path_ = path;
        for (auto& function : functions_) {
            if (const auto custom = names_.find(function.start); custom != names_.end()) {
                function.name = custom->second;
                continue;
            }
            function.name = "sub_" + address_string(function.start).substr(2);
            for (const auto& symbol : image_.exports()) {
                if (symbol.address == function.start) { function.name = symbol.name; break; }
            }
        }
        result["ok"] = true;
        result["path"] = path;
        result["name_count"] = static_cast<std::uint64_t>(names_.size());
        result["comment_count"] = static_cast<std::uint64_t>(comments_.size());
        result["bookmark_count"] = static_cast<std::uint64_t>(bookmarks_.size());
    } catch (const std::exception& exception) {
        result["ok"] = false;
        result["error"] = std::string("invalid database: ") + exception.what();
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
            for (const auto& resolved : collect_indirect_targets(function)) {
                if (resolved.kind != InstructionKind::IndirectCall) continue;
                if (const auto* callee = function_at(resolved.target)) neighbours.push_back(callee->start);
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

Json Analyzer::call_tool(std::string_view name, const Json& arguments, bool& ok) {
    ok = true;
    std::string argument_error;
    Json validation_error = Json::object();
    auto reject_unknown = [&](std::initializer_list<std::string_view> allowed) -> bool {
        if (has_only_keys(arguments, allowed, argument_error)) return false;
        ok = false;
        validation_error["error"] = argument_error;
        return true;
    };
    if (name == "module_info" || name == "list_sections" || name == "list_segments" || name == "analysis_stats") {
        if (reject_unknown({})) return validation_error;
    } else if (name == "list_functions") {
        if (reject_unknown({"offset", "limit", "query"})) return validation_error;
    } else if (name == "get_function") {
        if (reject_unknown({"address", "addresses", "name"})) return validation_error;
    } else if (name == "disassemble" || name == "read_bytes") {
        if (name == "disassemble") {
            if (reject_unknown({"address", "addresses", "count"})) return validation_error;
        } else if (reject_unknown({"address", "count"})) return validation_error;
    } else if (name == "xrefs_to" || name == "xrefs_from") {
        if (reject_unknown({"address", "addresses", "limit"})) return validation_error;
    } else if (name == "cfg") {
        if (reject_unknown({"function_address"})) return validation_error;
    } else if (name == "search_strings" || name == "list_strings") {
        if (reject_unknown({"query", "min_length", "offset", "limit", "referenced_only"})) return validation_error;
    } else if (name == "find_instructions") {
        if (reject_unknown({"pattern", "sequence", "target_in", "address", "function_address", "limit"})) return validation_error;
    } else if (name == "source_locations") {
        if (reject_unknown({"address", "addresses"})) return validation_error;
    } else if (name == "search_bytes") {
        if (reject_unknown({"pattern", "limit"})) return validation_error;
    } else if (name == "list_imports" || name == "list_exports") {
        if (name == "list_imports") {
            if (reject_unknown({"query", "summary"})) return validation_error;
        } else if (reject_unknown({"query"})) return validation_error;
    } else if (name == "list_names") {
        if (reject_unknown({"query", "offset", "limit"})) return validation_error;
    } else if (name == "list_bookmarks") {
        if (reject_unknown({"offset", "limit", "query"})) return validation_error;
    } else if (name == "list_vtables") {
        if (reject_unknown({"query", "limit"})) return validation_error;
    } else if (name == "vtable_of" || name == "function_strings") {
        if (name == "function_strings") {
            if (reject_unknown({"address", "addresses"})) return validation_error;
        } else if (reject_unknown({"address"})) return validation_error;
    } else if (name == "list_runtime_functions") {
        if (reject_unknown({"offset", "limit"})) return validation_error;
    } else if (name == "list_switches" || name == "stack_variables" || name == "function_dataflow") {
        if (name == "list_switches") {
            if (reject_unknown({"function_address", "address", "limit"})) return validation_error;
        } else if (reject_unknown({"function_address", "address"})) return validation_error;
    } else if (name == "function_signature" || name == "object_fields" || name == "function_xrefs" || name == "analyze_function") {
        if (name == "function_signature") {
            if (reject_unknown({"function_address", "address", "addresses"})) return validation_error;
        } else if (reject_unknown({"function_address", "address"})) return validation_error;
    } else if (name == "list_noreturn_functions" || name == "list_rtti") {
        if (name == "list_rtti") {
            if (reject_unknown({"query", "limit", "include_methods"})) return validation_error;
        } else if (reject_unknown({"query", "limit"})) return validation_error;
    } else if (name == "list_exceptions" || name == "list_relocations") {
        if (reject_unknown({"offset", "limit"})) return validation_error;
    } else if (name == "list_tls_callbacks" || name == "pdb_info") {
        if (reject_unknown({})) return validation_error;
    } else if (name == "list_resources") {
        if (reject_unknown({"query", "limit"})) return validation_error;
    } else if (name == "load_symbols") {
        if (reject_unknown({"path"})) return validation_error;
    } else if (name == "list_symbols") {
        if (reject_unknown({"query", "offset", "limit"})) return validation_error;
    } else if (name == "call_graph") {
        if (reject_unknown({"function_address", "direction", "depth"})) return validation_error;
    } else if (name == "set_name") {
        if (reject_unknown({"address", "name"})) return validation_error;
    } else if (name == "set_comment") {
        if (reject_unknown({"address", "comment"})) return validation_error;
    } else if (name == "set_bookmark") {
        if (reject_unknown({"address", "enabled", "comment"})) return validation_error;
    } else if (name == "save_database" || name == "load_database") {
        if (reject_unknown({"path"})) return validation_error;
    }
    if (name == "module_info") return module_info();
    if (name == "list_sections") return list_sections();
    if (name == "list_segments") return list_segments();
    if (name == "list_functions") return list_functions(arguments);
    if (name == "get_function") return get_function(arguments);
    if (name == "disassemble") return disassemble(arguments);
    if (name == "read_bytes") return read_bytes(arguments);
    if (name == "xrefs_to") return xrefs_to(arguments);
    if (name == "xrefs_from") return xrefs_from(arguments);
    if (name == "cfg") return cfg(arguments);
    if (name == "search_strings") return search_strings(arguments);
    if (name == "list_strings") return list_strings(arguments);
    if (name == "find_instructions") return find_instructions(arguments);
    if (name == "source_locations") return source_locations(arguments);
    if (name == "search_bytes") return search_bytes(arguments);
    if (name == "list_imports") return list_imports(arguments);
    if (name == "list_exports") return list_exports(arguments);
    if (name == "list_names") return list_names(arguments);
    if (name == "list_bookmarks") return list_bookmarks(arguments);
    if (name == "list_vtables") return list_vtables(arguments);
    if (name == "vtable_of") return vtable_of(arguments);
    if (name == "function_strings") return function_strings(arguments);
    if (name == "list_runtime_functions") return list_runtime_functions(arguments);
    if (name == "list_switches") return list_switches(arguments);
    if (name == "stack_variables") return stack_variables(arguments);
    if (name == "function_dataflow") return function_dataflow(arguments);
    if (name == "function_signature") return function_signature(arguments);
    if (name == "object_fields") return object_fields(arguments);
    if (name == "function_xrefs") return function_xrefs(arguments);
    if (name == "analyze_function") return analyze_function(arguments);
    if (name == "list_noreturn_functions") return list_noreturn_functions(arguments);
    if (name == "list_rtti") return list_rtti(arguments);
    if (name == "list_exceptions") return list_exceptions(arguments);
    if (name == "list_tls_callbacks") return list_tls_callbacks(arguments);
    if (name == "list_relocations") return list_relocations(arguments);
    if (name == "list_resources") return list_resources(arguments);
    if (name == "pdb_info") return pdb_info(arguments);
    if (name == "load_symbols") return load_symbols(arguments);
    if (name == "list_symbols") return list_symbols(arguments);
    if (name == "call_graph") return call_graph(arguments);
    if (name == "analysis_stats") return analysis_stats();
    if (name == "set_name") return set_name(arguments);
    if (name == "set_comment") return set_comment(arguments);
    if (name == "set_bookmark") return set_bookmark(arguments);
    if (name == "save_database") return save_database(arguments);
    if (name == "load_database") return load_database(arguments);
    ok = false;
    Json error = Json::object();
    error["error"] = "unknown tool: " + std::string(name);
    return error;
}

} // namespace paper

