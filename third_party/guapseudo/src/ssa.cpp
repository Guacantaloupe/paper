#include "guapseudo/ssa.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <unordered_map>

namespace guapseudo {
namespace {

using Versions = std::unordered_map<std::string, std::string>;

const std::vector<std::string>& register_names() {
    static const std::vector<std::string> names = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
    };
    return names;
}

bool is_word_boundary(char value) {
    return !std::isalnum(static_cast<unsigned char>(value)) && value != '_';
}

bool contains_token(const std::string& text, const std::string& token) {
    std::size_t position = 0;
    while ((position = text.find(token, position)) != std::string::npos) {
        const bool left_ok = position == 0 || is_word_boundary(text[position - 1]);
        const auto end = position + token.size();
        const bool right_ok = end >= text.size() || is_word_boundary(text[end]);
        if (left_ok && right_ok) return true;
        position = end;
    }
    return false;
}

std::vector<std::string> split_operands(const std::string& operands) {
    std::vector<std::string> result;
    std::stringstream stream(operands);
    std::string item;
    while (std::getline(stream, item, ',')) {
        const auto begin = item.find_first_not_of(" \t");
        const auto end = item.find_last_not_of(" \t");
        if (begin != std::string::npos) result.push_back(item.substr(begin, end - begin + 1));
    }
    return result;
}

std::string stack_name(std::int32_t offset) {
    const auto magnitude = offset < 0 ? -static_cast<std::int64_t>(offset) : static_cast<std::int64_t>(offset);
    std::ostringstream out;
    out << "local_" << std::hex << magnitude;
    return out.str();
}

std::string stack_slot_for(const Instruction& instruction) {
    if (instruction.stack_offset.has_value()) return stack_name(*instruction.stack_offset);
    const auto position = instruction.pseudo.find("local_");
    if (position != std::string::npos) {
        std::size_t end = position + 6;
        while (end < instruction.pseudo.size() &&
               (std::isxdigit(static_cast<unsigned char>(instruction.pseudo[end])) || instruction.pseudo[end] == '_')) ++end;
        return instruction.pseudo.substr(position, end - position);
    }
    return {};
}

std::vector<std::string> variables_in(const std::string& text, bool memory_context) {
    std::vector<std::string> result;
    for (const auto& name : register_names()) {
        if ((memory_context && (name == "rbp" || name == "rsp" || name == "ebp" || name == "esp")) ||
            !contains_token(text, name)) continue;
        auto canonical = name;
        if (canonical == "eax" || canonical == "ax" || canonical == "al") canonical = "rax";
        else if (canonical == "ebx" || canonical == "bx" || canonical == "bl") canonical = "rbx";
        else if (canonical == "ecx" || canonical == "cx" || canonical == "cl") canonical = "rcx";
        else if (canonical == "edx" || canonical == "dx" || canonical == "dl") canonical = "rdx";
        else if (canonical == "esi" || canonical == "si" || canonical == "sil") canonical = "rsi";
        else if (canonical == "edi" || canonical == "di" || canonical == "dil") canonical = "rdi";
        else if (canonical == "ebp" || canonical == "bp" || canonical == "bpl") canonical = "rbp";
        else if (canonical == "esp" || canonical == "sp" || canonical == "spl") canonical = "rsp";
        else if (canonical.size() >= 2 && canonical[0] == 'r' && canonical[1] >= '8' && canonical[1] <= '9') {
            canonical.resize(3);
        }
        result.push_back(canonical);
    }
    std::size_t position = 0;
    while ((position = text.find("local_", position)) != std::string::npos) {
        std::size_t end = position + 6;
        while (end < text.size() &&
               (std::isxdigit(static_cast<unsigned char>(text[end])) || text[end] == '_')) ++end;
        result.push_back(text.substr(position, end - position));
        position = end;
    }
    return result;
}

bool is_memory_operand(const std::string& operand) {
    return operand.find('[') != std::string::npos || operand.find("local_") != std::string::npos;
}

std::string destination_location(const Instruction& instruction) {
    if (!instruction.write_operands.empty()) {
        const auto& destination = instruction.write_operands.front();
        const auto slot = stack_slot_for(instruction);
        if (is_memory_operand(destination) || (!slot.empty() && contains_token(destination, "rbp"))) return slot;
        const auto names = variables_in(destination, false);
        if (!names.empty()) return names.front();
        return destination;
    }
    const auto operands = split_operands(instruction.operands);
    if (instruction.kind == InstructionKind::Call) return "rax";
    const bool writes_destination = instruction.mnemonic == "mov" || instruction.mnemonic == "lea" ||
                                    instruction.mnemonic == "xor" || instruction.mnemonic == "add" ||
                                    instruction.mnemonic == "sub" || instruction.mnemonic == "and" ||
                                    instruction.mnemonic == "or" || instruction.mnemonic == "imul" ||
                                    instruction.mnemonic == "shl" || instruction.mnemonic == "shr" ||
                                    instruction.mnemonic == "sar" || instruction.mnemonic == "inc" ||
                                    instruction.mnemonic == "dec" || instruction.mnemonic == "pop";
    if (!writes_destination) return {};
    if (operands.empty()) return {};
    if (is_memory_operand(operands.front())) return stack_slot_for(instruction);
    const auto names = variables_in(operands.front(), false);
    return names.empty() ? std::string() : names.front();
}

std::vector<std::string> read_locations(const Instruction& instruction) {
    std::vector<std::string> result;
    auto add = [&](const std::string& value) {
        if (value.empty() || std::find(result.begin(), result.end(), value) != result.end()) return;
        result.push_back(value);
    };
    if (!instruction.read_operands.empty()) {
        for (const auto& operand : instruction.read_operands) {
            for (const auto& variable : variables_in(operand, is_memory_operand(operand))) add(variable);
        }
    } else {
        const auto operands = split_operands(instruction.operands);
        for (std::size_t index = 0; index < operands.size(); ++index) {
            const auto memory = is_memory_operand(operands[index]);
            const bool destination = index == 0 && !memory &&
                                     (instruction.mnemonic == "mov" || instruction.mnemonic == "lea");
            if (!destination) {
                for (const auto& variable : variables_in(operands[index], memory)) add(variable);
            }
        }
        const auto slot = stack_slot_for(instruction);
        if (!slot.empty()) {
            for (const auto& operand : operands) {
                if (is_memory_operand(operand) && operand.find("local_") == std::string::npos) add(slot);
            }
        }
    }
    const auto slot = stack_slot_for(instruction);
    if (!slot.empty() && instruction.reads_memory) add(slot);
    return result;
}

ValueType infer_type(const Instruction& instruction, const std::string& definition) {
    if (instruction.kind == InstructionKind::LoadAddress || instruction.mnemonic == "lea") return ValueType::Pointer;
    if (instruction.kind == InstructionKind::ConditionalJump ||
        instruction.kind == InstructionKind::Compare || instruction.kind == InstructionKind::Test) return ValueType::Bool;
    if (instruction.constant_value.has_value()) return instruction.constant_value->width() <= 32 ? ValueType::Int32 : ValueType::Int64;
    if (definition.size() >= 2 && definition[0] == 'e') return ValueType::Int32;
    return ValueType::Int64;
}

std::string version_name(const std::string& variable, std::uint64_t address) {
    std::ostringstream out;
    out << variable << "_" << std::hex << address;
    return out.str();
}

std::string phi_name(const std::string& variable, std::uint32_t block) {
    return variable + "_phi_B" + std::to_string(block);
}

std::string operation_name(const Instruction& instruction) {
    if (instruction.kind == InstructionKind::Call) return "call";
    if (instruction.kind == InstructionKind::Return) return "return";
    if (instruction.kind == InstructionKind::ConditionalJump) return "branch_" + instruction.mnemonic;
    if (instruction.kind == InstructionKind::Jump) return "branch";
    return instruction.mnemonic;
}

class ExpressionPool {
public:
    explicit ExpressionPool(SsaFunction& function) : function_(function) { function_.expressions.push_back(ExpressionNode{}); }

    std::uint32_t variable(const std::string& name) { return intern(ExpressionKind::Variable, {}, name, std::nullopt); }
    std::uint32_t constant(const BitVector& value) { return intern(ExpressionKind::Constant, {}, {}, value); }

    std::uint32_t constant_from_text(const std::string& text, std::uint8_t width) {
        try {
            std::size_t consumed = 0;
            const auto value = std::stoll(text, &consumed, 0);
            if (consumed == text.size()) return constant(BitVector::from_signed(width, value));
        } catch (...) {
        }
        return variable(text);
    }

    std::uint32_t unary(const std::string& op, std::uint32_t operand) { return intern(ExpressionKind::Unary, {operand}, op, std::nullopt); }

    std::uint32_t binary(std::string op, std::uint32_t lhs, std::uint32_t rhs) {
        const auto& left = function_.expressions[lhs];
        const auto& right = function_.expressions[rhs];
        if (op == "add" && is_zero(right)) return lhs;
        if (op == "sub" && is_zero(right)) return lhs;
        if (op == "mul" && is_one(right)) return lhs;
        if (op == "mul" && (is_zero(left) || is_zero(right))) return is_zero(left) ? lhs : rhs;
        if (op == "xor" && lhs == rhs) return constant(BitVector(left.constant_value.has_value() ? left.constant_value->width() : 32, 0));
        if (op == "or" && lhs == rhs) return lhs;
        if (left.constant_value.has_value() && right.constant_value.has_value() &&
            left.constant_value->width() == right.constant_value->width()) {
            const auto& a = *left.constant_value;
            const auto& b = *right.constant_value;
            if (op == "add") return constant(a + b);
            if (op == "sub") return constant(a - b);
            if (op == "and") return constant(a & b);
            if (op == "or") return constant(a | b);
            if (op == "xor") return constant(a ^ b);
        }
        return intern(ExpressionKind::Binary, {lhs, rhs}, op, std::nullopt);
    }

    std::string render(std::uint32_t id) const {
        if (id == 0 || id >= function_.expressions.size()) return "undefined";
        const auto& node = function_.expressions[id];
        if (node.kind == ExpressionKind::Constant && node.constant_value.has_value()) return node.constant_value->to_hex();
        if (node.kind == ExpressionKind::Variable) return node.atom;
        if (node.kind == ExpressionKind::Unary) return node.operation + "(" + render(node.operands[0]) + ")";
        if (node.kind == ExpressionKind::Binary && node.operands.size() == 2) {
            static const std::map<std::string, std::string> operators = {
                {"add", "+"}, {"sub", "-"}, {"mul", "*"}, {"imul", "*"},
                {"and", "&"}, {"or", "|"}, {"xor", "^"}, {"shl", "<<"},
                {"shr", ">>"}, {"sar", ">>"}
            };
            const auto found = operators.find(node.operation);
            const auto op = found == operators.end() ? node.operation : found->second;
            return "(" + render(node.operands[0]) + " " + op + " " + render(node.operands[1]) + ")";
        }
        return node.atom;
    }

private:
    bool is_zero(const ExpressionNode& node) const { return node.constant_value.has_value() && node.constant_value->is_zero(); }
    bool is_one(const ExpressionNode& node) const { return node.constant_value.has_value() && node.constant_value->low64() == 1; }
    std::uint32_t intern(ExpressionKind kind, std::vector<std::uint32_t> operands,
                          std::string atom, std::optional<BitVector> constant_value) {
        for (std::size_t i = 1; i < function_.expressions.size(); ++i) {
            const auto& existing = function_.expressions[i];
            if (existing.kind == kind && existing.operation == atom && existing.operands == operands &&
                existing.constant_value.has_value() == constant_value.has_value() &&
                (!constant_value.has_value() || existing.constant_value->to_hex() == constant_value->to_hex())) return static_cast<std::uint32_t>(i);
        }
        ExpressionNode node;
        node.id = static_cast<std::uint32_t>(function_.expressions.size());
        node.kind = kind;
        node.operation = atom;
        node.operands = std::move(operands);
        node.atom = std::move(atom);
        node.constant_value = std::move(constant_value);
        function_.expressions.push_back(std::move(node));
        return static_cast<std::uint32_t>(function_.expressions.size() - 1);
    }
    SsaFunction& function_;
};

Versions incoming_versions(const Function& function, const std::vector<Versions>& outgoing,
                           std::uint32_t block_id, const std::set<std::string>& variables,
                           std::vector<std::vector<SsaPhi>>* phis) {
    const auto& block = function.cfg.blocks[block_id];
    Versions current;
    for (const auto& variable : variables) {
        std::vector<std::string> incoming;
        for (const auto predecessor : block.predecessors) {
            const auto found = outgoing[predecessor].find(variable);
            incoming.push_back(found == outgoing[predecessor].end() ? variable + "_0" : found->second);
        }
        if (incoming.empty() || std::all_of(incoming.begin(), incoming.end(), [&](const std::string& value) { return value == incoming.front(); })) {
            current[variable] = incoming.empty() ? variable + "_0" : incoming.front();
        } else {
            current[variable] = phi_name(variable, block_id);
            if (phis != nullptr) {
                SsaPhi phi;
                phi.variable = variable;
                phi.result = current[variable];
                for (std::size_t i = 0; i < incoming.size(); ++i) phi.incoming.emplace_back(block.predecessors[i], incoming[i]);
                (*phis)[block_id].push_back(std::move(phi));
            }
        }
    }
    return current;
}

} // namespace

const char* value_type_name(ValueType type) {
    switch (type) {
    case ValueType::Unknown: return "unknown";
    case ValueType::Void: return "void";
    case ValueType::Bool: return "bool";
    case ValueType::Int8: return "int8_t";
    case ValueType::Int16: return "int16_t";
    case ValueType::Int32: return "int32_t";
    case ValueType::Int64: return "int64_t";
    case ValueType::Pointer: return "void *";
    case ValueType::FunctionPointer: return "function *";
    }
    return "unknown";
}

void SsaTypeAnalyzer::run(Function& function) {
    function.ssa = {};
    const auto block_count = function.cfg.blocks.size();
    if (block_count == 0) return;
    function.ssa.phis.resize(block_count);

    std::set<std::string> variables;
    for (const auto& block : function.cfg.blocks) {
        for (const auto& instruction : block.instructions) {
            const auto location = destination_location(instruction);
            if (!location.empty()) variables.insert(location);
            for (const auto& variable : read_locations(instruction)) variables.insert(variable);
        }
    }

    Versions initial;
    for (const auto& variable : variables) initial[variable] = variable + "_0";
    std::vector<Versions> outgoing(block_count, initial);
    for (std::size_t iteration = 0; iteration < block_count * 4 + 4; ++iteration) {
        bool changed = false;
        for (std::uint32_t block_id = 0; block_id < block_count; ++block_id) {
            auto current = incoming_versions(function, outgoing, block_id, variables, nullptr);
            for (const auto& instruction : function.cfg.blocks[block_id].instructions) {
                const auto location = destination_location(instruction);
                if (!location.empty()) current[location] = version_name(location, instruction.address);
            }
            if (current != outgoing[block_id]) {
                outgoing[block_id] = std::move(current);
                changed = true;
            }
        }
        if (!changed) break;
    }

    function.ssa.phis.assign(block_count, {});
    std::map<std::string, ValueType> recovered;
    std::set<std::string> stack_slots;
    for (std::uint32_t block_id = 0; block_id < block_count; ++block_id) {
        incoming_versions(function, outgoing, block_id, variables, &function.ssa.phis);
        for (const auto& instruction : function.cfg.blocks[block_id].instructions) {
            const auto slot = stack_slot_for(instruction);
            if (!slot.empty()) stack_slots.insert(slot);
        }
    }

    ExpressionPool expressions(function.ssa);
    for (std::uint32_t block_id = 0; block_id < block_count; ++block_id) {
        auto current = incoming_versions(function, outgoing, block_id, variables, nullptr);
        for (const auto& instruction : function.cfg.blocks[block_id].instructions) {
            const auto location = destination_location(instruction);
            const auto reads = read_locations(instruction);
            const auto type = infer_type(instruction, location);
            SsaStatement statement;
            statement.block = block_id;
            statement.address = instruction.address;
            statement.operation = operation_name(instruction);
            statement.type = type;
            statement.location = location;
            statement.constant_value = instruction.constant_value;
            for (const auto& read : reads) {
                const auto found = current.find(read);
                statement.arguments.push_back(found == current.end() ? read + "_0" : found->second);
            }
            std::vector<std::uint32_t> operands;
            for (const auto& argument : statement.arguments) operands.push_back(expressions.variable(argument));
            if (instruction.constant_value.has_value() && operands.empty()) operands.push_back(expressions.constant(*instruction.constant_value));
            const auto split = split_operands(instruction.operands);
            if (split.size() > 1 && variables_in(split.back(), is_memory_operand(split.back())).empty()) {
                operands.push_back(instruction.constant_value.has_value()
                                       ? expressions.constant(*instruction.constant_value)
                                       : expressions.constant_from_text(split.back(), instruction.operand_width));
            }

            if (instruction.kind == InstructionKind::Return) {
                const auto found = current.find("rax");
                statement.expression = "return " + (found == current.end() ? "rax_0" : found->second) + ";";
            } else if (!location.empty() && instruction.kind != InstructionKind::Compare &&
                       instruction.kind != InstructionKind::Test && instruction.kind != InstructionKind::ConditionalJump &&
                       instruction.kind != InstructionKind::Jump) {
                std::uint32_t expression_id = 0;
                const bool can_build = instruction.mnemonic == "mov" || instruction.mnemonic == "lea" ||
                                       instruction.mnemonic == "xor" || instruction.mnemonic == "add" ||
                                       instruction.mnemonic == "sub" || instruction.mnemonic == "and" ||
                                       instruction.mnemonic == "or" || instruction.mnemonic == "imul" ||
                                       instruction.mnemonic == "shl" || instruction.mnemonic == "shr" ||
                                       instruction.mnemonic == "sar" || instruction.mnemonic == "inc" ||
                                       instruction.mnemonic == "dec";
                if (!can_build) {
                    expression_id = 0;
                } else if (instruction.mnemonic == "mov" && !operands.empty()) expression_id = operands.back();
                else if (instruction.mnemonic == "lea" && !operands.empty()) expression_id = expressions.unary("&", operands.back());
                else if (instruction.mnemonic == "xor" && operands.size() >= 2) expression_id = expressions.binary("xor", operands[0], operands[1]);
                else if (operands.size() >= 2) expression_id = expressions.binary(instruction.mnemonic, operands[0], operands[1]);
                else if (operands.size() == 1) expression_id = expressions.binary(instruction.mnemonic, expressions.variable(current[location]), operands[0]);
                if (expression_id != 0) {
                    statement.expression_id = expression_id;
                    statement.expression = location + " = " + expressions.render(expression_id) + ";";
                }
            }
            if (statement.expression.empty()) statement.expression = instruction.pseudo;
            if (!location.empty()) {
                current[location] = version_name(location, instruction.address);
                recovered[location] = type;
                statement.result = current[location];
            }
            function.ssa.statements.push_back(std::move(statement));
        }
    }
    function.ssa.stack_slots.assign(stack_slots.begin(), stack_slots.end());
    for (const auto& [name, type] : recovered) function.ssa.recovered_types.emplace_back(name, type);
    for (auto& block_phis : function.ssa.phis) {
        for (auto& phi : block_phis) {
            const auto found = recovered.find(phi.variable);
            if (found != recovered.end()) phi.type = found->second;
        }
    }
}

} // namespace guapseudo
