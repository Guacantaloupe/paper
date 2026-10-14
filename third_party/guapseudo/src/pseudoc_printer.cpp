#include "guapseudo/pseudoc_printer.hpp"

#include "guapseudo/ghidra_heuristics.hpp"
#include "guapseudo/ssa.hpp"
#include "guapseudo/structurer.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <ostream>
#include <set>
#include <sstream>
#include <map>
#include <unordered_set>

namespace guapseudo {
namespace {

std::string hex_address(std::uint64_t address) {
    std::ostringstream out;
    out << "0x" << std::hex << address;
    return out.str();
}

std::string format_name(ImageFormat format) {
    switch (format) {
    case ImageFormat::Elf64: return "ELF64";
    case ImageFormat::Pe32Plus: return "PE32+";
    case ImageFormat::Raw: return "raw x86-64";
    }
    return "unknown";
}

std::string decoder_name(DecoderBackend backend) {
    switch (backend) {
    case DecoderBackend::Builtin: return "builtin fast decoder";
    case DecoderBackend::Objdump: return "GNU objdump full x86 decoder";
    case DecoderBackend::Auto: return "auto";
    }
    return "unknown";
}

std::string instruction_listing(const Instruction& instruction) {
    if (instruction.operands.empty()) return instruction.mnemonic;
    return instruction.mnemonic + " " + instruction.operands;
}

std::set<std::string> find_locals(const Function& function) {
    std::set<std::string> locals;
    locals.insert(function.signature.locals.begin(), function.signature.locals.end());
    locals.insert(function.ssa.stack_slots.begin(), function.ssa.stack_slots.end());
    for (const auto& instruction : function.instructions) {
        const auto& pseudo = instruction.pseudo;
        std::size_t position = 0;
        while ((position = pseudo.find("local_", position)) != std::string::npos) {
            const auto end = pseudo.find_first_not_of("0123456789abcdefABCDEF_", position + 6);
            locals.insert(pseudo.substr(position, end - position));
            position += 6;
        }
    }
    return locals;
}

std::string local_type(const Function& function, const std::string& local) {
    const auto found = std::find_if(function.ssa.recovered_types.begin(), function.ssa.recovered_types.end(),
                                    [&](const auto& item) { return item.first == local; });
    return found == function.ssa.recovered_types.end() ? "undefined8" : ghidra_type_name(found->second);
}

const SsaStatement* statement_at(const Function& function, std::uint64_t address) {
    const auto found = std::find_if(function.ssa.statements.begin(), function.ssa.statements.end(),
                                    [&](const SsaStatement& statement) { return statement.address == address; });
    return found == function.ssa.statements.end() ? nullptr : &*found;
}

std::string condition_expression(const Function& function, const BasicBlock& block,
                                 const Instruction& instruction) {
    std::string lhs = "condition";
    std::string rhs = "0";
    const Instruction* flags = nullptr;
    for (std::size_t i = 0; i + 1 < block.instructions.size(); ++i) {
        if (block.instructions[i].kind == InstructionKind::Compare || block.instructions[i].kind == InstructionKind::Test) {
            flags = &block.instructions[i];
        }
    }
    if (flags != nullptr) {
        if (const auto* statement = statement_at(function, flags->address); statement != nullptr && !statement->arguments.empty()) {
            lhs = statement->arguments.front();
            if (statement->arguments.size() > 1) rhs = statement->arguments[1];
        }
        const auto comma = flags->operands.find(',');
        if (comma != std::string::npos && statement_at(function, flags->address) != nullptr &&
            statement_at(function, flags->address)->arguments.size() < 2) {
            rhs = flags->operands.substr(comma + 1);
            const auto begin = rhs.find_first_not_of(" \t");
            if (begin != std::string::npos) rhs.erase(0, begin);
        }
        if (flags->kind == InstructionKind::Test) rhs = "0";
    }
    if (instruction.mnemonic == "jne" || instruction.mnemonic == "jnz") return lhs + " != " + rhs;
    if (instruction.mnemonic == "je" || instruction.mnemonic == "jz") return lhs + " == " + rhs;
    if (instruction.mnemonic == "jl") return lhs + " < " + rhs;
    if (instruction.mnemonic == "jle") return lhs + " <= " + rhs;
    if (instruction.mnemonic == "jg") return lhs + " > " + rhs;
    if (instruction.mnemonic == "jge") return lhs + " >= " + rhs;
    if (instruction.mnemonic == "jb") return lhs + " <u " + rhs;
    if (instruction.mnemonic == "jbe") return lhs + " <=u " + rhs;
    if (instruction.mnemonic == "ja") return lhs + " >u " + rhs;
    if (instruction.mnemonic == "jae") return lhs + " >=u " + rhs;
    return instruction.mnemonic.empty() ? "condition" : instruction.mnemonic.substr(1);
}

void print_ssa_block(const Function& function, const BasicBlock& block, std::ostream& out) {
    out << std::dec;
    out << "    /* SSA block B" << block.id << " @ " << hex_address(block.address);
    if (block.loop_header) out << "; loop header";
    out << " */\n";
    if (block.id < function.ssa.phis.size()) {
        for (const auto& phi : function.ssa.phis[block.id]) {
            out << "    /* " << phi.result << " = phi(";
            for (std::size_t i = 0; i < phi.incoming.size(); ++i) {
                if (i != 0) out << ", ";
                out << phi.incoming[i].second << " from B" << phi.incoming[i].first;
            }
            out << ") : " << value_type_name(phi.type) << " */\n";
        }
    }
}

void print_bitvector_annotation(const Instruction& instruction, std::ostream& out) {
    if (instruction.constant_value.has_value()) {
        out << std::dec;
        out << "    /* explicit bitvector: bv<" << instruction.constant_value->width()
            << ">(" << instruction.constant_value->to_hex() << ") */\n";
    }
}

void print_instruction(const Function& function, const Instruction& instruction, std::ostream& out) {
    out << "    /* " << hex_address(instruction.address) << "  " << instruction_listing(instruction) << " */\n";
    if (const auto* statement = statement_at(function, instruction.address); statement != nullptr &&
        !statement->expression.empty()) {
        out << "    " << statement->expression << "\n";
    } else {
        out << "    " << instruction.pseudo << "\n";
    }
    print_bitvector_annotation(instruction, out);
}

void print_block_body(const Function& function, const BasicBlock& block,
                      std::ostream& out, std::uint32_t ignored_terminal = std::numeric_limits<std::uint32_t>::max()) {
    const auto* last = block.instructions.empty() ? nullptr : &block.instructions.back();
    for (const auto& instruction : block.instructions) {
        if (last != nullptr && instruction.address == last->address &&
            (ignored_terminal == block.id || instruction.kind == InstructionKind::Jump ||
             instruction.kind == InstructionKind::ConditionalJump)) continue;
        print_instruction(function, instruction, out);
    }
}

const ControlFlowRegion* region_for(const Function& function, std::uint32_t header) {
    const auto found = std::find_if(function.control_flow.regions.begin(), function.control_flow.regions.end(),
                                    [&](const ControlFlowRegion& region) { return region.header == header && region.safe_to_render; });
    return found == function.control_flow.regions.end() ? nullptr : &*found;
}

bool render_region(const Function& function, const ControlFlowRegion& region,
                   std::ostream& out, std::unordered_set<std::uint32_t>& consumed,
                   std::unordered_set<std::uint32_t>& suppress_labels) {
    const auto& header = function.cfg.blocks[region.header];
    if (header.instructions.empty()) return false;
    const auto& terminal = header.instructions.back();
    if (region.kind == ControlFlowRegionKind::Switch) {
        print_block_body(function, header, out, header.id);
        out << "    switch (" << (region.switch_expression.empty() ? "switch_value" : region.switch_expression) << ") {\n";
        for (const auto& [value, target] : region.switch_cases) {
            out << "    case " << value.to_hex() << ":\n";
            out << "        goto LAB_" << std::hex << function.cfg.blocks[target].address << ";\n";
        }
        out << "    default:\n        break; /* unresolved jump-table index */\n    }\n";
        consumed.insert(region.header);
        return true;
    }
    if (terminal.kind != InstructionKind::ConditionalJump) return false;
    const auto raw_condition = condition_expression(function, header, terminal);
    const auto condition = region.invert_condition ? "!(" + raw_condition + ")" : raw_condition;
    if (region.kind == ControlFlowRegionKind::While) {
        std::vector<std::uint32_t> body;
        for (const auto block : region.body) if (block != region.header) body.push_back(block);
        if (body.size() != 1) return false;
        print_block_body(function, header, out, header.id);
        out << "    while (" << condition << ") {\n";
        print_block_body(function, function.cfg.blocks[body.front()], out, region.header);
        out << "    }\n";
        consumed.insert(region.header);
        consumed.insert(body.front());
        if (region.follow != std::numeric_limits<std::uint32_t>::max()) suppress_labels.insert(region.follow);
        return true;
    }
    if (region.kind == ControlFlowRegionKind::If || region.kind == ControlFlowRegionKind::IfElse) {
        print_block_body(function, header, out, header.id);
        out << "    if (" << condition << ") {\n";
        for (const auto block : region.body) {
            print_block_body(function, function.cfg.blocks[block], out, region.follow);
            consumed.insert(block);
        }
        out << "    }";
        for (const auto block : region.alternate) {
            out << " else {\n";
            print_block_body(function, function.cfg.blocks[block], out, region.follow);
            consumed.insert(block);
            out << "    }";
        }
        out << "\n";
        consumed.insert(region.header);
        if (region.follow != std::numeric_limits<std::uint32_t>::max()) suppress_labels.insert(region.follow);
        return true;
    }
    return false;
}

void print_cfg(const Function& function, std::ostream& out) {
    std::unordered_set<std::uint32_t> consumed;
    std::unordered_set<std::uint32_t> suppress_labels;
    for (const auto& block : function.cfg.blocks) {
        if (consumed.find(block.id) != consumed.end()) continue;
        if (const auto* region = region_for(function, block.id); region != nullptr &&
            render_region(function, *region, out, consumed, suppress_labels)) continue;
        if (block.id != function.cfg.entry && suppress_labels.find(block.id) == suppress_labels.end()) {
            out << "LAB_" << std::hex << block.address << ":;\n";
        }
        for (const auto& region : function.control_flow.regions) {
            if (region.header != block.id) continue;
            out << std::dec << "    /* structured " << control_flow_region_name(region.kind);
            if (region.follow != std::numeric_limits<std::uint32_t>::max()) {
                out << "; follow B" << region.follow;
            }
            if (region.kind == ControlFlowRegionKind::Irreducible) {
                out << "; labels retained for semantic safety";
            }
            out << " */\n";
        }
        print_ssa_block(function, block, out);
        const auto* last = block.instructions.empty() ? nullptr : &block.instructions.back();
        const auto body_end = last == nullptr ? block.instructions.end() : block.instructions.end() - 1;
        for (auto it = block.instructions.begin(); it != body_end; ++it) print_instruction(function, *it, out);
        if (last == nullptr) continue;
        if (last->kind == InstructionKind::ConditionalJump && last->has_target) {
            out << "    /* " << hex_address(last->address) << "  " << instruction_listing(*last) << " */\n";
            const auto region = std::find_if(function.control_flow.regions.begin(),
                                             function.control_flow.regions.end(),
                                             [&](const ControlFlowRegion& candidate) {
                                                 return candidate.header == block.id &&
                                                        (candidate.kind == ControlFlowRegionKind::While ||
                                                         candidate.kind == ControlFlowRegionKind::If ||
                                                         candidate.kind == ControlFlowRegionKind::IfElse);
                                             });
            if (region != function.control_flow.regions.end()) {
                out << "    /* region candidate: " << control_flow_region_name(region->kind)
                    << "; exact CFG edges emitted below */\n";
            }
            out << "    if (" << condition_expression(function, block, *last) << ")\n";
            out << "        goto LAB_" << std::hex << last->target << ";\n";
            for (const auto successor : block.successors) {
                const auto& target = function.cfg.blocks[successor];
                if (target.address != last->target) {
                    out << "    else\n        goto LAB_" << std::hex << target.address << ";\n";
                }
            }
        } else if (last->kind == InstructionKind::Jump && last->has_target) {
            out << "    goto LAB_" << std::hex << last->target << ";\n";
        } else {
            print_instruction(function, *last, out);
        }
    }
}

} // namespace

void PseudoCPrinter::print(const BinaryImage& image,
                           const AnalysisResult& result,
                           std::ostream& out) const {
    out << "/* GuaPseudo-C 0.1.0 | Ghidra-style pseudo-C prototype */\n";
    out << "/* source: " << image.source_name << " | format: " << format_name(image.format) << " */\n";
    out << "/* code: " << hex_address(image.code_base) << " - " << hex_address(image.code_end())
        << " | entry: " << hex_address(image.entry) << " */\n";
    out << "/* analyzed with " << result.worker_count << " worker(s); decoder: "
        << decoder_name(result.decoder_backend)
        << "; SSA + CFG + type recovery enabled */\n\n";

    for (const auto& function : result.functions) {
        out << std::dec;
        out << "/* ==================== " << function.name << " ==================== */\n";
        out << "/* calling convention: " << function.signature.calling_convention
            << "; confidence: " << function.signature.confidence << "% */\n";
        out << function.signature.return_type << " " << function.name << "(";
        for (std::size_t i = 0; i < function.signature.parameters.size(); ++i) {
            if (i != 0) out << ", ";
            out << ghidra_type_name(function.signature.parameters[i].second) << " "
                << function.signature.parameters[i].first;
        }
        out << ")\n{\n";

        out << "    /* CFG blocks: " << function.cfg.blocks.size()
            << ", dominator sets: " << function.cfg.dominators.size()
            << ", SSA statements: " << function.ssa.statements.size() << " */\n";
        std::map<ControlFlowRegionKind, std::size_t> region_counts;
        for (const auto& region : function.control_flow.regions) ++region_counts[region.kind];
        out << "    /* complex control-flow: while=" << region_counts[ControlFlowRegionKind::While]
            << ", do_while=" << region_counts[ControlFlowRegionKind::DoWhile]
            << ", if=" << region_counts[ControlFlowRegionKind::If]
            << ", if_else=" << region_counts[ControlFlowRegionKind::IfElse]
            << ", switch=" << region_counts[ControlFlowRegionKind::Switch]
            << ", irreducible=" << region_counts[ControlFlowRegionKind::Irreducible] << " */\n";
        if (!function.ssa.recovered_types.empty()) {
            out << "    /* recovered types: ";
            for (std::size_t i = 0; i < function.ssa.recovered_types.size(); ++i) {
                if (i != 0) out << ", ";
                out << function.ssa.recovered_types[i].first << " -> "
                    << value_type_name(function.ssa.recovered_types[i].second);
            }
            out << " */\n";
        }

        const auto locals = find_locals(function);
        for (const auto& local : locals) {
            out << "    " << local_type(function, local) << " " << local << " = 0;\n";
        }
        if (!locals.empty()) out << "\n";

        if (!function.cfg.blocks.empty()) print_cfg(function, out);
        else for (const auto& instruction : function.instructions) {
            out << "    /* " << hex_address(instruction.address) << "  "
                << instruction_listing(instruction) << " */\n";
            out << "    " << instruction.pseudo << "\n";
        }
        if (function.instructions.empty() ||
            function.instructions.back().kind != InstructionKind::Return) {
            out << "    return rax;\n";
        }
        out << "}\n\n";
    }

    if (result.functions.empty()) {
        out << "/* no function entry point was found */\n";
    }
}

} // namespace guapseudo

