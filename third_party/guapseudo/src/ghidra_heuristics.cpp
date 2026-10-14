#include "guapseudo/ghidra_heuristics.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <set>

namespace guapseudo {
namespace {

const std::vector<std::string>& argument_registers(const BinaryImage& image) {
    static const std::vector<std::string> sysv = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    static const std::vector<std::string> windows = {"rcx", "rdx", "r8", "r9"};
    return image.format == ImageFormat::Pe32Plus ? windows : sysv;
}

bool contains_register(const std::string& text, const std::string& reg) {
    const auto position = text.find(reg);
    if (position == std::string::npos) return false;
    const bool left_word = position > 0 && std::isalnum(static_cast<unsigned char>(text[position - 1]));
    const auto after = position + reg.size();
    const bool right_word = after < text.size() && std::isalnum(static_cast<unsigned char>(text[after]));
    return !left_word && !right_word;
}

bool defines_register(const Instruction& instruction, const std::string& reg) {
    const auto& operands = instruction.operands;
    const auto comma = operands.find(',');
    const auto destination = comma == std::string::npos ? operands : operands.substr(0, comma);
    if (destination.find('[') != std::string::npos) return false;
    return (instruction.mnemonic == "mov" || instruction.mnemonic == "lea" ||
            instruction.mnemonic == "xor" || instruction.mnemonic == "add" ||
            instruction.mnemonic == "sub") && contains_register(destination, reg);
}

ValueType type_for_register(const Function& function, const std::string& reg) {
    for (const auto& [name, type] : function.ssa.recovered_types) {
        if (name == reg) return type;
    }
    return reg.size() == 3 && reg[0] == 'e' ? ValueType::Int32 : ValueType::Int64;
}

std::string type_name(ValueType type) {
    switch (type) {
    case ValueType::Bool: return "bool";
    case ValueType::Int8: return "char";
    case ValueType::Int16: return "short";
    case ValueType::Int32: return "undefined4";
    case ValueType::Int64: return "undefined8";
    case ValueType::Pointer: return "void *";
    case ValueType::FunctionPointer: return "code *";
    case ValueType::Void: return "void";
    case ValueType::Unknown: return "undefined8";
    }
    return "undefined8";
}

} // namespace

const char* ghidra_type_name(ValueType type) {
    switch (type) {
    case ValueType::Bool: return "bool";
    case ValueType::Int8: return "char";
    case ValueType::Int16: return "short";
    case ValueType::Int32: return "undefined4";
    case ValueType::Int64: return "undefined8";
    case ValueType::Pointer: return "void *";
    case ValueType::FunctionPointer: return "code *";
    case ValueType::Void: return "void";
    case ValueType::Unknown: return "undefined8";
    }
    return "undefined8";
}

void GhidraHeuristics::apply(const BinaryImage& image, Function& function) {
    function.signature = {};
    function.signature.calling_convention = image.format == ImageFormat::Pe32Plus
                                                 ? "__fastcall (Microsoft x64)"
                                                 : "__cdecl (System V AMD64)";

    unsigned score = function.address == image.entry ? 40U : 20U;
    if (!function.instructions.empty()) {
        if (function.instructions.front().kind == InstructionKind::Prologue) score += 20;
        if (function.instructions.back().kind == InstructionKind::Return) score += 20;
    }
    if (function.cfg.blocks.size() > 1) score += 10;
    if (!function.ssa.phis.empty()) score += 5;

    const auto& args = argument_registers(image);
    for (std::size_t argument_index = 0; argument_index < args.size(); ++argument_index) {
        const auto& reg = args[argument_index];
        bool used_before_definition = false;
        for (const auto& instruction : function.instructions) {
            if (contains_register(instruction.operands, reg) && !defines_register(instruction, reg)) {
                used_before_definition = true;
                break;
            }
            if (defines_register(instruction, reg)) break;
        }
        if (used_before_definition) {
            function.signature.parameters.emplace_back("param_" + std::to_string(argument_index + 1),
                                                       type_for_register(function, reg));
            score += 5;
        }
    }

    std::set<std::string> locals;
    for (const auto& instruction : function.instructions) {
        const auto& text = instruction.pseudo;
        std::size_t position = 0;
        while ((position = text.find("local_", position)) != std::string::npos) {
            const auto end = text.find_first_not_of("0123456789abcdefABCDEF_", position + 6);
            locals.insert(text.substr(position, end - position));
            position += 6;
        }
        if (instruction.operands.find("[rbp") != std::string::npos) score += 1;
    }
    function.signature.locals.assign(locals.begin(), locals.end());
    function.signature.return_type = "undefined8";
    for (const auto& [name, type] : function.ssa.recovered_types) {
        if (name == "rax" || name == "eax") {
            function.signature.return_type = type_name(type);
            break;
        }
    }
    function.signature.confidence = std::min(100U, score);
}

} // namespace guapseudo

