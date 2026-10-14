#include "guapseudo/analyzer.hpp"

#include "guapseudo/cfg.hpp"
#include "guapseudo/ghidra_heuristics.hpp"
#include "guapseudo/objdump_decoder.hpp"
#include "guapseudo/ssa.hpp"
#include "guapseudo/structurer.hpp"
#include "guapseudo/x86_decoder.hpp"

#include <algorithm>
#include <atomic>
#include <iomanip>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace guapseudo {
namespace {

std::string address_hex(std::uint64_t address) {
    std::ostringstream out;
    out << std::hex << address;
    return out.str();
}

using InstructionTable = std::unordered_map<std::uint64_t, Instruction>;

std::vector<std::uint64_t> discover_function_starts(const BinaryImage& image,
                                                    const InstructionTable* instruction_table) {
    X86_64Decoder decoder;
    std::set<std::uint64_t> starts;
    if (image.contains(image.entry)) starts.insert(image.entry);

    if (instruction_table != nullptr && !instruction_table->empty()) {
        for (const auto& [address, instruction] : *instruction_table) {
            if (address < image.code_base || address >= image.code_end()) continue;
            if (instruction.kind == InstructionKind::Call && instruction.has_target &&
                image.contains(instruction.target)) {
                starts.insert(instruction.target);
            }
        }
    } else {
        std::uint64_t address = image.code_base;
        while (image.contains(address)) {
            const auto instruction = decoder.decode(image, address);
            if (instruction.kind == InstructionKind::Call && instruction.has_target &&
                image.contains(instruction.target)) {
                starts.insert(instruction.target);
            }
            if (instruction.size == 0) break;
            address += instruction.size;
        }
    }

    for (std::size_t offset = 0; offset + 4 <= image.code.size(); ++offset) {
        if (image.code[offset] == 0x55 && image.code[offset + 1] == 0x48 &&
            image.code[offset + 2] == 0x89 && image.code[offset + 3] == 0xe5) {
            starts.insert(image.code_base + offset);
        }
    }

    return {starts.begin(), starts.end()};
}

Function decode_function(const BinaryImage& image,
                         std::uint64_t start,
                         std::size_t max_bytes,
                         const InstructionTable* instruction_table) {
    X86_64Decoder decoder;
    Function function;
    function.address = start;
    function.name = start == image.entry ? "entry" : "FUN_" + address_hex(start);
    std::set<std::uint64_t> pending{start};
    std::set<std::uint64_t> block_starts{start};
    std::unordered_map<std::uint64_t, Instruction> decoded;
    std::size_t consumed = 0;

    while (!pending.empty() && consumed < max_bytes) {
        const auto block_start = *pending.begin();
        pending.erase(pending.begin());
        if (!image.contains(block_start)) continue;

        auto address = block_start;
        while (image.contains(address) && consumed < max_bytes) {
            if (address != block_start && block_starts.count(address) != 0) break;
            if (decoded.find(address) != decoded.end()) break;
            Instruction instruction;
            if (instruction_table != nullptr) {
                const auto external = instruction_table->find(address);
                instruction = external == instruction_table->end() ? decoder.decode(image, address) : external->second;
            } else {
                instruction = decoder.decode(image, address);
            }
            if (instruction.size == 0 || consumed + instruction.size > max_bytes) break;
            decoded.emplace(address, instruction);
            consumed += instruction.size;

            if ((instruction.kind == InstructionKind::Jump ||
                 instruction.kind == InstructionKind::ConditionalJump) &&
                instruction.has_target && image.contains(instruction.target)) {
                block_starts.insert(instruction.target);
                pending.insert(instruction.target);
            }
            if (instruction.kind == InstructionKind::Jump) {
                for (const auto target : instruction.indirect_targets) {
                    if (image.contains(target)) {
                        block_starts.insert(target);
                        pending.insert(target);
                    }
                }
            }
            const auto fallthrough = address + instruction.size;
            if (instruction.kind == InstructionKind::ConditionalJump && image.contains(fallthrough)) {
                block_starts.insert(fallthrough);
                pending.insert(fallthrough);
            }
            address = fallthrough;
            if (instruction.kind == InstructionKind::Return || instruction.kind == InstructionKind::Jump ||
                instruction.kind == InstructionKind::ConditionalJump) {
                break;
            }
        }
    }

    function.instructions.reserve(decoded.size());
    for (auto& [address, instruction] : decoded) function.instructions.push_back(std::move(instruction));
    std::sort(function.instructions.begin(), function.instructions.end(),
              [](const Instruction& lhs, const Instruction& rhs) { return lhs.address < rhs.address; });
    function.basic_block_starts.assign(block_starts.begin(), block_starts.end());
    function.basic_block_starts.erase(
        std::remove_if(function.basic_block_starts.begin(), function.basic_block_starts.end(),
                       [&](std::uint64_t address) {
                           return std::none_of(function.instructions.begin(), function.instructions.end(),
                                               [&](const Instruction& instruction) {
                                                   return instruction.address == address;
                                               });
                       }),
        function.basic_block_starts.end());
    ControlFlowAnalyzer::build(function);
    SsaTypeAnalyzer::run(function);
    GhidraHeuristics::apply(image, function);
    ControlFlowStructurer::run(function);
    return function;
}

} // namespace

AnalysisResult ParallelAnalyzer::analyze(const BinaryImage& image,
                                         const AnalysisConfig& config) const {
    AnalysisResult result;
    InstructionTable external_instructions;
    const bool request_objdump = config.decoder_backend == DecoderBackend::Objdump ||
                                 (config.decoder_backend == DecoderBackend::Auto && ObjdumpDecoder::available_for(image));
    if (request_objdump) {
        try {
            external_instructions = ObjdumpDecoder::decode(image);
            if (!external_instructions.empty()) result.decoder_backend = DecoderBackend::Objdump;
        } catch (...) {
            if (config.decoder_backend == DecoderBackend::Objdump) throw;
        }
    }
    const InstructionTable* instruction_table = external_instructions.empty() ? nullptr : &external_instructions;
    const auto starts = discover_function_starts(image, instruction_table);
    if (starts.empty()) return result;

    const auto hardware = std::max(1U, std::thread::hardware_concurrency());
    const auto requested = config.thread_count == 0 ? hardware : config.thread_count;
    const auto worker_count = std::max(1U, std::min<unsigned>(requested,
                                                               static_cast<unsigned>(starts.size())));
    result.worker_count = worker_count;
    result.functions.resize(starts.size());

    std::atomic<std::size_t> next{0};
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (unsigned worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&]() {
            for (;;) {
                const auto index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= starts.size()) break;
                result.functions[index] = decode_function(image, starts[index], config.max_function_bytes,
                                                          instruction_table);
            }
        });
    }
    for (auto& worker : workers) worker.join();

    std::sort(result.functions.begin(), result.functions.end(),
              [](const Function& lhs, const Function& rhs) { return lhs.address < rhs.address; });
    for (const auto& function : result.functions) {
        result.decoded_instructions += function.instructions.size();
    }
    return result;
}

} // namespace guapseudo

