#include "guapseudo/objdump_decoder.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace guapseudo {
namespace {

#ifdef _WIN32
constexpr auto process_open = _popen;
constexpr auto process_close = _pclose;
#else
constexpr auto process_open = popen;
constexpr auto process_close = pclose;
#endif

std::string trim(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

bool is_hex_byte(const std::string& token) {
    return token.size() == 2 && std::isxdigit(static_cast<unsigned char>(token[0])) &&
           std::isxdigit(static_cast<unsigned char>(token[1]));
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool parse_target(const std::string& operands, std::uint64_t& target) {
    std::stringstream stream(operands);
    std::string first;
    if (!(stream >> first) || first.empty() || !std::isxdigit(static_cast<unsigned char>(first.front()))) return false;
    try {
        if (first.size() > 2 && first[0] == '0' && (first[1] == 'x' || first[1] == 'X')) {
            std::size_t consumed = 0;
            target = std::stoull(first, &consumed, 0);
            if (consumed == first.size()) return true;
        }
        std::size_t consumed = 0;
        target = std::stoull(first, &consumed, 16);
        if (consumed == first.size()) return true;
    } catch (...) {
        // Fall through and look for an explicit hexadecimal literal.
    }
    for (std::size_t i = 0; i + 2 < operands.size(); ++i) {
        if (operands[i] == '0' && (operands[i + 1] == 'x' || operands[i + 1] == 'X')) {
            try {
                std::size_t consumed = 0;
                target = std::stoull(operands.substr(i), &consumed, 0);
                return consumed > 2;
            } catch (...) {
                return false;
            }
        }
    }
    return false;
}

std::string c_operand(std::string operand) {
    const auto comment = operand.find(" #");
    if (comment != std::string::npos) operand.erase(comment);
    const char* decorations[] = {"XMMWORD PTR ", "QWORD PTR ", "DWORD PTR ", "WORD PTR ", "BYTE PTR "};
    for (const auto* decoration : decorations) {
        std::size_t position = 0;
        while ((position = operand.find(decoration, position)) != std::string::npos) {
            operand.erase(position, std::char_traits<char>::length(decoration));
        }
    }
    return operand;
}

std::vector<std::string> split_operands(const std::string& operands) {
    std::vector<std::string> result;
    std::stringstream stream(operands);
    std::string item;
    while (std::getline(stream, item, ',')) {
        const auto begin = item.find_first_not_of(" \t");
        const auto end = item.find_last_not_of(" \t");
        if (begin != std::string::npos) result.push_back(c_operand(item.substr(begin, end - begin + 1)));
    }
    return result;
}

std::optional<std::int32_t> stack_offset(const std::string& operand) {
    const auto rbp = operand.find("rbp");
    if (rbp == std::string::npos) return std::nullopt;
    const auto sign = operand.find('-', rbp);
    const auto plus = operand.find('+', rbp);
    const auto marker = sign != std::string::npos ? sign : plus;
    if (marker == std::string::npos) return 0;
    auto value = operand.substr(marker + 1);
    while (!value.empty() && (value.back() == ']' || value.back() == ')')) value.pop_back();
    try {
        return static_cast<std::int32_t>((sign != std::string::npos ? -1 : 1) * std::stoll(value, nullptr, 0));
    } catch (...) {
        return std::nullopt;
    }
}

Instruction convert_instruction(std::uint64_t address,
                                std::uint8_t size,
                                std::string mnemonic,
                                std::string operands) {
    mnemonic = lower(trim(std::move(mnemonic)));
    operands = trim(std::move(operands));
    Instruction instruction;
    instruction.address = address;
    instruction.size = size == 0 ? 1 : size;
    instruction.mnemonic = mnemonic;
    instruction.operands = operands;
    instruction.pseudo = "/* " + mnemonic + (operands.empty() ? "" : " " + operands) + " */";
    const auto parsed_operands = split_operands(operands);
    for (const auto& operand : parsed_operands) {
        if (const auto offset = stack_offset(operand); offset.has_value()) instruction.stack_offset = offset;
    }
    if (mnemonic.size() > 1) {
        const auto suffix = mnemonic.back();
        instruction.operand_width = suffix == 'b' ? 8 : suffix == 'w' ? 16 : suffix == 'l' ? 32 : 64;
    }

    std::uint64_t target = 0;
    const bool target_found = parse_target(operands, target);
    if (mnemonic == "ret" || mnemonic == "retq") {
        instruction.kind = InstructionKind::Return;
        instruction.pseudo = "return rax;";
    } else if (mnemonic == "call" || mnemonic == "callq") {
        instruction.kind = InstructionKind::Call;
        instruction.has_target = target_found;
        instruction.target = target;
        instruction.pseudo = target_found ? "FUN_" + [&]() {
            std::ostringstream out;
            out << std::hex << target;
            return out.str();
        }() + "();" : "indirect_call();";
    } else if (mnemonic == "jmp" || mnemonic == "jmpq") {
        instruction.kind = InstructionKind::Jump;
        instruction.has_target = target_found;
        instruction.target = target;
        instruction.pseudo = target_found ? "goto LAB_" + [&]() {
            std::ostringstream out;
            out << std::hex << target;
            return out.str();
        }() + ";" : "goto indirect_target;";
    } else if (mnemonic.size() >= 2 && mnemonic[0] == 'j' && mnemonic != "jmp") {
        instruction.kind = InstructionKind::ConditionalJump;
        instruction.conditional = true;
        instruction.has_target = target_found;
        instruction.target = target;
        instruction.pseudo = target_found ? "if (condition) goto LAB_" + [&]() {
            std::ostringstream out;
            out << std::hex << target;
            return out.str();
        }() + ";" : "if (condition) goto indirect_target;";
    } else if (mnemonic == "mov" || mnemonic == "movabs") {
        instruction.kind = InstructionKind::Move;
        const auto comma = operands.find(',');
        if (comma != std::string::npos) {
            instruction.pseudo = c_operand(trim(operands.substr(0, comma))) + " = " +
                                 c_operand(trim(operands.substr(comma + 1))) + ";";
            instruction.write_operands.push_back(c_operand(trim(operands.substr(0, comma))));
            instruction.read_operands.push_back(c_operand(trim(operands.substr(comma + 1))));
            instruction.reads_memory = operands.find('[', comma) != std::string::npos;
            instruction.writes_memory = operands.find('[') < comma;
        }
    } else if (mnemonic == "lea") {
        instruction.kind = InstructionKind::LoadAddress;
        if (parsed_operands.size() == 2) {
            instruction.write_operands = {parsed_operands[0]};
            instruction.read_operands = {parsed_operands[1]};
        }
    } else if (mnemonic == "cmp" || mnemonic == "cmpl" || mnemonic == "cmpq") {
        instruction.kind = InstructionKind::Compare;
    } else if (mnemonic == "test" || mnemonic == "testl" || mnemonic == "testq") {
        instruction.kind = InstructionKind::Test;
    } else if (mnemonic == "add" || mnemonic == "sub" || mnemonic == "imul" || mnemonic == "idiv" ||
               mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" || mnemonic == "shl" ||
               mnemonic == "shr" || mnemonic == "sar") {
        instruction.kind = InstructionKind::Arithmetic;
        if (!parsed_operands.empty()) {
            instruction.write_operands = {parsed_operands.front()};
            instruction.read_operands = parsed_operands;
        }
    } else if (mnemonic == "syscall" || mnemonic == "sysenter" || mnemonic == "int") {
        instruction.kind = InstructionKind::System;
    }
    return instruction;
}

} // namespace

bool ObjdumpDecoder::available_for(const BinaryImage& image) {
    return image.source_name != "<hex>" && !image.source_name.empty();
}

std::unordered_map<std::uint64_t, Instruction> ObjdumpDecoder::decode(const BinaryImage& image) {
    std::string command = "objdump -D -M intel ";
    if (image.format == ImageFormat::Raw) {
        std::ostringstream base;
        base << std::hex << image.code_base;
        command = "objdump -D -b binary -m i386:x86-64 --adjust-vma=0x" + base.str() + " ";
    }
    command += "\"" + image.source_name + "\" 2>NUL";
    auto* pipe = process_open(command.c_str(), "r");
    if (pipe == nullptr) throw std::runtime_error("could not start objdump");

    std::unordered_map<std::uint64_t, Instruction> result;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        const std::string line(buffer);
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        const auto address_text = trim(line.substr(0, colon));
        if (address_text.empty() || address_text.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) continue;
        std::uint64_t address = 0;
        try {
            address = std::stoull(address_text, nullptr, 16);
        } catch (...) {
            continue;
        }

        std::istringstream tokens(line.substr(colon + 1));
        std::string token;
        std::string first_non_byte;
        std::size_t byte_count = 0;
        while (tokens >> token) {
            if (is_hex_byte(token)) {
                ++byte_count;
            } else {
                first_non_byte = token;
                break;
            }
        }
        if (byte_count == 0) continue;
        if (first_non_byte.empty()) {
            for (auto& [previous_address, previous] : result) {
                if (previous_address + previous.size == address) {
                    previous.size = static_cast<std::uint8_t>(previous.size + byte_count);
                    break;
                }
            }
            continue;
        }
        std::string rest;
        std::getline(tokens, rest);
        rest = first_non_byte + rest;
        std::istringstream instruction_tokens(rest);
        std::string mnemonic;
        instruction_tokens >> mnemonic;
        std::string operands;
        std::getline(instruction_tokens, operands);
        result[address] = convert_instruction(address, static_cast<std::uint8_t>(byte_count), mnemonic, operands);
    }
    process_close(pipe);
    return result;
}

} // namespace guapseudo

