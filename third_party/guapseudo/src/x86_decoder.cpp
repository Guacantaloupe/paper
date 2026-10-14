#include "guapseudo/x86_decoder.hpp"

#include <array>
#include <iomanip>
#include <sstream>

namespace guapseudo {
namespace {

std::string condition_name(unsigned code) {
    static constexpr std::array<const char*, 16> names = {
        "overflow", "not_overflow", "below", "above_or_equal",
        "equal", "not_equal", "below_or_equal", "above",
        "sign", "not_sign", "parity", "not_parity",
        "less", "greater_or_equal", "less_or_equal", "greater"
    };
    return names[code & 0xfU];
}

std::string condition_mnemonic(unsigned code) {
    static constexpr std::array<const char*, 16> names = {
        "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
        "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
    };
    return names[code & 0xfU];
}

std::string signed_displacement(std::int32_t value) {
    std::ostringstream out;
    if (value < 0) {
        out << "- 0x" << std::hex << -static_cast<std::int64_t>(value);
    } else {
        out << "+ 0x" << std::hex << value;
    }
    return out.str();
}

std::string generic_register_name(unsigned index, unsigned width) {
    static constexpr std::array<const char*, 16> names64 = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    static constexpr std::array<const char*, 16> names32 = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
    };
    static constexpr std::array<const char*, 16> names16 = {
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
    };
    static constexpr std::array<const char*, 16> names8 = {
        "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
    };
    index &= 15U;
    if (width == 8) return names8[index];
    if (width == 16) return names16[index];
    if (width == 32) return names32[index];
    return names64[index];
}

struct ModRmOperand {
    std::size_t size = 0;
    unsigned reg = 0;
    unsigned rm = 0;
    bool memory = false;
    std::string text;
    std::optional<std::int32_t> rbp_offset;
};

bool parse_modrm(const std::uint8_t* p, std::size_t remaining, std::uint8_t rex,
                 unsigned width, ModRmOperand& result) {
    if (remaining < 1) return false;
    const auto modrm = p[0];
    const auto mod = (modrm >> 6U) & 3U;
    const auto reg = ((modrm >> 3U) & 7U) | ((rex & 4U) != 0 ? 8U : 0U);
    const auto rm_low = modrm & 7U;
    unsigned rm = rm_low | ((rex & 1U) != 0 ? 8U : 0U);
    std::size_t cursor = 1;
    std::int32_t displacement = 0;
    unsigned base = rm;
    unsigned index = 16;
    unsigned scale = 1;
    bool rip_relative = false;
    if (mod != 3 && rm_low == 4) {
        if (remaining < cursor + 1) return false;
        const auto sib = p[cursor++];
        scale = 1U << ((sib >> 6U) & 3U);
        index = ((sib >> 3U) & 7U) | ((rex & 2U) != 0 ? 8U : 0U);
        if ((sib >> 3U & 7U) == 4U && (rex & 2U) == 0) index = 16;
        base = (sib & 7U) | ((rex & 1U) != 0 ? 8U : 0U);
        if (mod == 0 && (sib & 7U) == 5U) base = 16;
    } else if (mod == 0 && rm_low == 5 && (rex & 1U) == 0) {
        base = 16;
        rip_relative = true;
    }
    const auto displacement_size = mod == 1 ? 1U : mod == 2 || (mod == 0 && base == 16) ? 4U : 0U;
    if (remaining < cursor + displacement_size) return false;
    if (displacement_size == 1) displacement = static_cast<std::int8_t>(p[cursor]);
    if (displacement_size == 4) {
        const auto raw = static_cast<std::uint32_t>(p[cursor]) |
                         (static_cast<std::uint32_t>(p[cursor + 1]) << 8U) |
                         (static_cast<std::uint32_t>(p[cursor + 2]) << 16U) |
                         (static_cast<std::uint32_t>(p[cursor + 3]) << 24U);
        displacement = static_cast<std::int32_t>(raw);
    }
    cursor += displacement_size;

    result.size = cursor;
    result.reg = reg;
    result.rm = rm;
    result.memory = mod != 3;
    if (!result.memory) {
        result.text = generic_register_name(rm, width);
        return true;
    }
    std::ostringstream address;
    address << '[';
    bool wrote = false;
    if (rip_relative) {
        address << "rip";
        wrote = true;
    } else if (base != 16) {
        address << generic_register_name(base, 64);
        wrote = true;
    }
    if (index != 16) {
        if (wrote) address << " + ";
        address << generic_register_name(index, 64);
        if (scale != 1) address << " * " << scale;
        wrote = true;
    }
    if (displacement != 0 || !wrote) {
        if (wrote) address << (displacement < 0 ? " - 0x" : " + 0x")
                           << std::hex << (displacement < 0 ? -static_cast<std::int64_t>(displacement)
                                                             : static_cast<std::int64_t>(displacement));
        else address << "0x" << std::hex << static_cast<std::uint32_t>(displacement);
    }
    address << ']';
    result.text = address.str();
    if (base == 5 && index == 16 && !rip_relative) result.rbp_offset = displacement;
    return true;
}

std::string stack_name(std::int32_t offset) {
    const auto magnitude = offset < 0 ? -static_cast<std::int64_t>(offset) : static_cast<std::int64_t>(offset);
    std::ostringstream out;
    out << "local_" << std::hex << magnitude;
    return out.str();
}

void set_memory_metadata(Instruction& instruction, const ModRmOperand& operand,
                         bool read, bool write) {
    instruction.reads_memory = read && operand.memory;
    instruction.writes_memory = write && operand.memory;
    if (operand.rbp_offset.has_value()) instruction.stack_offset = operand.rbp_offset;
}

} // namespace

std::int8_t X86_64Decoder::i8(const std::uint8_t* p) {
    return static_cast<std::int8_t>(*p);
}

std::int32_t X86_64Decoder::i32(const std::uint8_t* p) {
    const auto value = static_cast<std::uint32_t>(p[0]) |
                       (static_cast<std::uint32_t>(p[1]) << 8U) |
                       (static_cast<std::uint32_t>(p[2]) << 16U) |
                       (static_cast<std::uint32_t>(p[3]) << 24U);
    return static_cast<std::int32_t>(value);
}

std::uint32_t X86_64Decoder::u32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) |
           (static_cast<std::uint32_t>(p[3]) << 24U);
}

std::uint64_t X86_64Decoder::u64(const std::uint8_t* p) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(p[i]) << (i * 8U);
    }
    return value;
}

std::string X86_64Decoder::register_name(unsigned index, bool wide) {
    static constexpr std::array<const char*, 16> wide_names = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    static constexpr std::array<const char*, 16> narrow_names = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
    };
    return wide ? wide_names[index & 15U] : narrow_names[index & 15U];
}

std::string X86_64Decoder::hex_value(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

bool X86_64Decoder::is_conditional_opcode(std::uint8_t opcode) {
    return opcode >= 0x70 && opcode <= 0x7f;
}

Instruction X86_64Decoder::decode(const BinaryImage& image, std::uint64_t address) const {
    Instruction instruction;
    instruction.address = address;
    instruction.kind = InstructionKind::Unknown;
    instruction.mnemonic = "db";

    if (!image.contains(address)) {
        instruction.operands = "0x00";
        instruction.pseudo = "/* address outside code image */";
        return instruction;
    }

    const auto offset = image.offset_of(address);
    const auto* p = image.code.data() + offset;
    const auto remaining = image.code.size() - offset;
    const auto can_read = [remaining](std::size_t count) { return remaining >= count; };
    const auto unknown = [&]() {
        instruction.size = 1;
        instruction.operands = hex_value(*p);
        instruction.pseudo = "/* unsupported opcode " + hex_value(*p) + " */";
    };

    if (*p == 0xc3) {
        instruction.size = 1;
        instruction.kind = InstructionKind::Return;
        instruction.mnemonic = "ret";
        instruction.pseudo = "return rax;";
        return instruction;
    }
    if (*p == 0xc2 && can_read(3)) {
        instruction.size = 3;
        instruction.kind = InstructionKind::Return;
        instruction.mnemonic = "ret";
        instruction.operands = hex_value(static_cast<std::uint16_t>(p[1] | (p[2] << 8U)));
        instruction.pseudo = "return rax;";
        return instruction;
    }
    if (*p == 0x90) {
        instruction.kind = InstructionKind::Nop;
        instruction.mnemonic = "nop";
        instruction.pseudo = "/* nop */";
        return instruction;
    }
    if (*p == 0x55) {
        instruction.kind = InstructionKind::Prologue;
        instruction.mnemonic = "push";
        instruction.operands = "rbp";
        instruction.pseudo = "/* save frame pointer */";
        return instruction;
    }
    if (*p == 0x5d) {
        instruction.kind = InstructionKind::Epilogue;
        instruction.mnemonic = "pop";
        instruction.operands = "rbp";
        instruction.pseudo = "/* restore frame pointer */";
        return instruction;
    }
    if (*p == 0xc9) {
        instruction.kind = InstructionKind::Epilogue;
        instruction.mnemonic = "leave";
        instruction.pseudo = "/* tear down stack frame */";
        return instruction;
    }
    if (*p == 0xcc) {
        instruction.kind = InstructionKind::Trap;
        instruction.mnemonic = "int3";
        instruction.pseudo = "__builtin_trap();";
        return instruction;
    }
    if (*p == 0x0f && can_read(2) && p[1] == 0x05) {
        instruction.size = 2;
        instruction.kind = InstructionKind::System;
        instruction.mnemonic = "syscall";
        instruction.pseudo = "syscall();";
        return instruction;
    }
    if (*p == 0x0f && can_read(2) && p[1] == 0x0b) {
        instruction.size = 2;
        instruction.kind = InstructionKind::Trap;
        instruction.mnemonic = "ud2";
        instruction.pseudo = "__builtin_trap();";
        return instruction;
    }
    if (*p >= 0x50 && *p <= 0x57) {
        instruction.kind = InstructionKind::Arithmetic;
        instruction.mnemonic = "push";
        instruction.operands = register_name(*p - 0x50);
        instruction.pseudo = "/* push " + instruction.operands + " */";
        return instruction;
    }
    if (*p >= 0x58 && *p <= 0x5f) {
        instruction.kind = InstructionKind::Arithmetic;
        instruction.mnemonic = "pop";
        instruction.operands = register_name(*p - 0x58);
        instruction.pseudo = "/* pop " + instruction.operands + " */";
        return instruction;
    }

    if (*p >= 0xb8 && *p <= 0xbf && can_read(5)) {
        const auto reg = *p - 0xb8;
        const auto value = u32(p + 1);
        instruction.size = 5;
        instruction.kind = InstructionKind::Move;
        instruction.mnemonic = "mov";
        instruction.operands = register_name(reg, false) + ", " + hex_value(value);
        instruction.pseudo = register_name(reg, false) + " = " + hex_value(value) + ";";
        instruction.constant_value = BitVector(32, value);
        return instruction;
    }
    if (*p == 0x48 && can_read(2) && p[1] >= 0xb8 && p[1] <= 0xbf && can_read(10)) {
        const auto reg = p[1] - 0xb8;
        const auto value = u64(p + 2);
        instruction.size = 10;
        instruction.kind = InstructionKind::Move;
        instruction.mnemonic = "mov";
        instruction.operands = register_name(reg) + ", " + hex_value(value);
        instruction.pseudo = register_name(reg) + " = " + hex_value(value) + ";";
        instruction.constant_value = BitVector(64, value);
        return instruction;
    }
    if (*p == 0x31 && can_read(2)) {
        instruction.size = 2;
        instruction.kind = InstructionKind::Move;
        instruction.mnemonic = "xor";
        instruction.operands = register_name((p[1] >> 3U) & 7U, false) + ", " +
                                register_name(p[1] & 7U, false);
        if (p[1] == 0xc0) instruction.pseudo = "eax = 0;";
        else if (p[1] == 0xff) instruction.pseudo = "edi = 0;";
        else instruction.pseudo = "/* zero registers */";
        if (p[1] == 0xc0 || p[1] == 0xff) instruction.constant_value = BitVector(32, 0);
        return instruction;
    }
    if (*p == 0x48 && can_read(3) && p[1] == 0x31) {
        instruction.size = 3;
        instruction.kind = InstructionKind::Move;
        instruction.mnemonic = "xor";
        instruction.operands = "rax, rax";
        instruction.pseudo = "rax = 0;";
        instruction.constant_value = BitVector(64, 0);
        return instruction;
    }

    if (*p == 0xe8 && can_read(5)) {
        const auto relative = i32(p + 1);
        instruction.size = 5;
        instruction.kind = InstructionKind::Call;
        instruction.mnemonic = "call";
        instruction.target = address + instruction.size + relative;
        instruction.has_target = true;
        instruction.operands = hex_value(instruction.target);
        instruction.pseudo = "FUN_" + hex_value(instruction.target).substr(2) + "();";
        return instruction;
    }
    if (*p == 0xe9 && can_read(5)) {
        const auto relative = i32(p + 1);
        instruction.size = 5;
        instruction.kind = InstructionKind::Jump;
        instruction.mnemonic = "jmp";
        instruction.target = address + instruction.size + relative;
        instruction.has_target = true;
        instruction.operands = hex_value(instruction.target);
        instruction.pseudo = "goto LAB_" + hex_value(instruction.target).substr(2) + ";";
        return instruction;
    }
    if (*p == 0xeb && can_read(2)) {
        const auto relative = i8(p + 1);
        instruction.size = 2;
        instruction.kind = InstructionKind::Jump;
        instruction.mnemonic = "jmp";
        instruction.target = address + instruction.size + relative;
        instruction.has_target = true;
        instruction.operands = hex_value(instruction.target);
        instruction.pseudo = "goto LAB_" + hex_value(instruction.target).substr(2) + ";";
        return instruction;
    }
    if (is_conditional_opcode(*p) && can_read(2)) {
        const auto relative = i8(p + 1);
        const auto condition = condition_name(*p - 0x70);
        instruction.size = 2;
        instruction.kind = InstructionKind::ConditionalJump;
        instruction.mnemonic = condition_mnemonic(*p - 0x70);
        instruction.target = address + instruction.size + relative;
        instruction.has_target = true;
        instruction.conditional = true;
        instruction.operands = hex_value(instruction.target);
        instruction.pseudo = "if (" + condition + ") goto LAB_" +
                             hex_value(instruction.target).substr(2) + ";";
        return instruction;
    }
    if (*p == 0x0f && can_read(6) && p[1] >= 0x80 && p[1] <= 0x8f) {
        const auto relative = i32(p + 2);
        const auto condition = condition_name(p[1] - 0x80);
        instruction.size = 6;
        instruction.kind = InstructionKind::ConditionalJump;
        instruction.mnemonic = condition_mnemonic(p[1] - 0x80);
        instruction.target = address + instruction.size + relative;
        instruction.has_target = true;
        instruction.conditional = true;
        instruction.operands = hex_value(instruction.target);
        instruction.pseudo = "if (" + condition + ") goto LAB_" +
                             hex_value(instruction.target).substr(2) + ";";
        return instruction;
    }

    if (*p == 0x48 && can_read(4) && p[1] == 0x89 && p[2] == 0xe5) {
        instruction.size = 3;
        instruction.kind = InstructionKind::Prologue;
        instruction.mnemonic = "mov";
        instruction.operands = "rbp, rsp";
        instruction.pseudo = "rbp = rsp;";
        return instruction;
    }
    if (*p == 0x48 && can_read(4) && p[1] == 0x89 && p[2] == 0xec) {
        instruction.size = 3;
        instruction.kind = InstructionKind::Epilogue;
        instruction.mnemonic = "mov";
        instruction.operands = "rsp, rbp";
        instruction.pseudo = "rsp = rbp;";
        return instruction;
    }
    if (*p == 0x48 && can_read(4) && p[1] == 0x83 && (p[2] == 0xec || p[2] == 0xc4)) {
        const auto amount = p[3];
        instruction.size = 4;
        instruction.kind = InstructionKind::Arithmetic;
        instruction.mnemonic = p[2] == 0xec ? "sub" : "add";
        instruction.operands = "rsp, " + hex_value(amount);
        instruction.pseudo = instruction.mnemonic + "_stack(" + hex_value(amount) + ");";
        instruction.constant_value = BitVector(8, amount);
        return instruction;
    }
    if (*p == 0x48 && can_read(7) && p[1] == 0x81 && (p[2] == 0xec || p[2] == 0xc4)) {
        const auto amount = u32(p + 3);
        instruction.size = 7;
        instruction.kind = InstructionKind::Arithmetic;
        instruction.mnemonic = p[2] == 0xec ? "sub" : "add";
        instruction.operands = "rsp, " + hex_value(amount);
        instruction.pseudo = instruction.mnemonic + "_stack(" + hex_value(amount) + ");";
        instruction.constant_value = BitVector(32, amount);
        return instruction;
    }
    if (*p == 0x48 && can_read(4) && p[1] == 0x85 && p[2] == 0xc0) {
        instruction.size = 3;
        instruction.kind = InstructionKind::Test;
        instruction.mnemonic = "test";
        instruction.operands = "rax, rax";
        instruction.pseudo = "/* test rax for zero */";
        return instruction;
    }
    if (*p == 0x85 && can_read(2) && p[1] == 0xc0) {
        instruction.size = 2;
        instruction.kind = InstructionKind::Test;
        instruction.mnemonic = "test";
        instruction.operands = "eax, eax";
        instruction.pseudo = "/* test eax for zero */";
        return instruction;
    }
    if (*p == 0x83 && can_read(3) && p[1] == 0xf8) {
        instruction.size = 3;
        instruction.kind = InstructionKind::Compare;
        instruction.mnemonic = "cmp";
        instruction.operands = "eax, " + hex_value(p[2]);
        instruction.pseudo = "/* compare eax with " + hex_value(p[2]) + " */";
        instruction.constant_value = BitVector(8, p[2]);
        return instruction;
    }
    if (*p == 0x48 && can_read(7) && p[1] == 0x8d && p[2] == 0x05) {
        const auto relative = i32(p + 3);
        instruction.size = 7;
        instruction.kind = InstructionKind::LoadAddress;
        instruction.mnemonic = "lea";
        instruction.target = address + instruction.size + relative;
        instruction.has_target = true;
        instruction.operands = "rax, [rip + " + hex_value(static_cast<std::uint32_t>(relative)) + "]";
        instruction.pseudo = "rax = &DAT_" + hex_value(instruction.target).substr(2) + ";";
        return instruction;
    }
    if (*p == 0x48 && can_read(4) && p[1] == 0x8d && p[2] == 0x45 && can_read(4)) {
        const auto displacement = i8(p + 3);
        instruction.size = 4;
        instruction.kind = InstructionKind::LoadAddress;
        instruction.mnemonic = "lea";
        instruction.operands = "rax, [rbp " + signed_displacement(displacement) + "]";
        instruction.pseudo = "rax = &local_" + hex_value(static_cast<std::uint8_t>(displacement < 0 ? -displacement : displacement)).substr(2) + ";";
        return instruction;
    }
    if (*p == 0x48 && can_read(4) && p[1] == 0x89 && p[2] == 0x45 && can_read(4)) {
        const auto displacement = i8(p + 3);
        instruction.size = 4;
        instruction.kind = InstructionKind::Move;
        instruction.mnemonic = "mov";
        instruction.operands = "[rbp " + signed_displacement(displacement) + "], rax";
        instruction.pseudo = "local_" + hex_value(static_cast<std::uint8_t>(displacement < 0 ? -displacement : displacement)).substr(2) + " = rax;";
        return instruction;
    }
    if (*p == 0x48 && can_read(4) && p[1] == 0x8b && p[2] == 0x45 && can_read(4)) {
        const auto displacement = i8(p + 3);
        instruction.size = 4;
        instruction.kind = InstructionKind::Move;
        instruction.mnemonic = "mov";
        instruction.operands = "rax, [rbp " + signed_displacement(displacement) + "]";
        instruction.pseudo = "rax = local_" + hex_value(static_cast<std::uint8_t>(displacement < 0 ? -displacement : displacement)).substr(2) + ";";
        return instruction;
    }

    // Fast semantic path for the common ModRM families. It covers register
    // and frame-slot forms without invoking an external disassembler.
    const auto decode_modrm_family = [&]() -> bool {
        std::size_t prefix = 0;
        std::uint8_t rex = 0;
        if (p[0] >= 0x40 && p[0] <= 0x4f) {
            rex = p[0];
            prefix = 1;
        }
        if (remaining <= prefix) return false;
        const auto opcode = p[prefix];
        const auto width = (rex & 8U) != 0 ? 64U : 32U;
        const auto byte_width = opcode == 0x80 || opcode == 0x88 || opcode == 0x8a ? 8U : width;
        const auto text_operand = [](const ModRmOperand& operand) {
            return operand.rbp_offset.has_value() ? stack_name(*operand.rbp_offset) : operand.text;
        };
        const auto emit_binary = [&](const std::string& op, InstructionKind kind,
                                     const ModRmOperand& lhs_info, const std::string& lhs,
                                     const std::string& rhs, bool writes_lhs,
                                     std::size_t length) {
            instruction.size = static_cast<std::uint8_t>(prefix + length);
            instruction.kind = kind;
            instruction.operand_width = static_cast<std::uint8_t>(byte_width);
            instruction.mnemonic = op;
            instruction.operands = lhs + ", " + rhs;
            instruction.read_operands = {lhs, rhs};
            if (writes_lhs) instruction.write_operands = {lhs};
            if (op == "cmp" || op == "test") {
                instruction.pseudo = "/* " + op + " " + lhs + ", " + rhs + " */";
            } else if (op == "imul") {
                instruction.pseudo = lhs + " = " + lhs + " * " + rhs + ";";
            } else {
                instruction.pseudo = lhs + " " + op + "= " + rhs + ";";
            }
            set_memory_metadata(instruction, lhs_info, true, writes_lhs);
        };

        if (opcode >= 0xb8 && opcode <= 0xbf) {
            const auto immediate_size = (rex & 8U) != 0 ? 8U : 4U;
            if (remaining < prefix + 1 + immediate_size) return false;
            const auto reg = (opcode - 0xb8U) | ((rex & 1U) != 0 ? 8U : 0U);
            const auto value = immediate_size == 8 ? u64(p + prefix + 1) : u32(p + prefix + 1);
            const auto destination = generic_register_name(reg, immediate_size == 8 ? 64 : 32);
            instruction.size = static_cast<std::uint8_t>(prefix + 1 + immediate_size);
            instruction.kind = InstructionKind::Move;
            instruction.operand_width = static_cast<std::uint8_t>(immediate_size * 8);
            instruction.mnemonic = "mov";
            instruction.operands = destination + ", " + hex_value(value);
            instruction.pseudo = destination + " = " + hex_value(value) + ";";
            instruction.write_operands = {destination};
            instruction.constant_value = BitVector(immediate_size * 8, value);
            return true;
        }

        if (opcode == 0x05 || opcode == 0x0d || opcode == 0x25 || opcode == 0x2d ||
            opcode == 0x35 || opcode == 0x3d) {
            if (remaining < prefix + 5) return false;
            const std::array<const char*, 6> ops = {"add", "or", "and", "sub", "xor", "cmp"};
            const auto operation = ops[opcode == 0x05 ? 0 : opcode == 0x0d ? 1 : opcode == 0x25 ? 2 :
                                       opcode == 0x2d ? 3 : opcode == 0x35 ? 4 : 5];
            const auto destination = generic_register_name(0, width);
            const auto immediate = u32(p + prefix + 1);
            instruction.size = static_cast<std::uint8_t>(prefix + 5);
            instruction.kind = operation == std::string("cmp") ? InstructionKind::Compare : InstructionKind::Arithmetic;
            instruction.operand_width = static_cast<std::uint8_t>(width);
            instruction.mnemonic = operation;
            instruction.operands = destination + ", " + hex_value(immediate);
            instruction.pseudo = operation == std::string("cmp") ? "/* cmp " + destination + ", " + hex_value(immediate) + " */"
                                                                   : destination + " " + operation + "= " + hex_value(immediate) + ";";
            instruction.read_operands = {destination};
            if (operation != std::string("cmp")) instruction.write_operands = {destination};
            instruction.constant_value = BitVector(width, immediate);
            return true;
        }

        if (opcode == 0x88 || opcode == 0x89 || opcode == 0x8a || opcode == 0x8b ||
            opcode == 0x8d || opcode == 0x01 || opcode == 0x03 || opcode == 0x09 ||
            opcode == 0x0b || opcode == 0x21 || opcode == 0x23 || opcode == 0x29 ||
            opcode == 0x2b || opcode == 0x31 || opcode == 0x33 || opcode == 0x39 ||
            opcode == 0x3b || opcode == 0x85) {
            ModRmOperand modrm;
            if (!parse_modrm(p + prefix + 1, remaining - prefix - 1, rex, byte_width, modrm)) return false;
            const auto reg = generic_register_name(modrm.reg, byte_width);
            const auto rm = text_operand(modrm);
            const auto length = 1 + modrm.size;
            if (opcode == 0x88 || opcode == 0x89) {
                instruction.size = static_cast<std::uint8_t>(prefix + length);
                instruction.kind = InstructionKind::Move;
                instruction.operand_width = static_cast<std::uint8_t>(byte_width);
                instruction.mnemonic = "mov";
                instruction.operands = rm + ", " + reg;
                instruction.pseudo = rm + " = " + reg + ";";
                instruction.read_operands = {reg};
                instruction.write_operands = {rm};
                set_memory_metadata(instruction, modrm, false, true);
                return true;
            }
            if (opcode == 0x8a || opcode == 0x8b) {
                instruction.size = static_cast<std::uint8_t>(prefix + length);
                instruction.kind = InstructionKind::Move;
                instruction.operand_width = static_cast<std::uint8_t>(byte_width);
                instruction.mnemonic = "mov";
                instruction.operands = reg + ", " + rm;
                instruction.pseudo = reg + " = " + rm + ";";
                instruction.read_operands = {rm};
                instruction.write_operands = {reg};
                set_memory_metadata(instruction, modrm, true, false);
                return true;
            }
            if (opcode == 0x8d) {
                instruction.size = static_cast<std::uint8_t>(prefix + length);
                instruction.kind = InstructionKind::LoadAddress;
                instruction.operand_width = 64;
                instruction.mnemonic = "lea";
                instruction.operands = reg + ", " + modrm.text;
                instruction.pseudo = reg + " = &(" + rm + ");";
                instruction.read_operands = {modrm.text};
                instruction.write_operands = {reg};
                if (modrm.rbp_offset.has_value()) instruction.pseudo = reg + " = &" + stack_name(*modrm.rbp_offset) + ";";
                return true;
            }
            std::string op;
            InstructionKind kind = InstructionKind::Arithmetic;
            switch (opcode) {
            case 0x01: case 0x03: op = "add"; break;
            case 0x09: case 0x0b: op = "or"; break;
            case 0x21: case 0x23: op = "and"; break;
            case 0x29: case 0x2b: op = "sub"; break;
            case 0x31: case 0x33: op = "xor"; break;
            case 0x39: case 0x3b: op = "cmp"; kind = InstructionKind::Compare; break;
            case 0x85: op = "test"; kind = InstructionKind::Test; break;
            default: return false;
            }
            const bool destination_is_rm = opcode == 0x01 || opcode == 0x09 || opcode == 0x21 ||
                                           opcode == 0x29 || opcode == 0x31 || opcode == 0x39 || opcode == 0x85;
            const auto& lhs_info = destination_is_rm ? modrm : ModRmOperand{};
            emit_binary(op, kind, lhs_info, destination_is_rm ? rm : reg,
                        destination_is_rm ? reg : rm, kind != InstructionKind::Compare && kind != InstructionKind::Test,
                        length);
            if (!destination_is_rm) {
                instruction.write_operands = {reg};
                if (modrm.memory) instruction.reads_memory = true;
            }
            return true;
        }

        if (opcode == 0x80 || opcode == 0x81 || opcode == 0x83) {
            ModRmOperand modrm;
            if (!parse_modrm(p + prefix + 1, remaining - prefix - 1, rex, byte_width, modrm)) return false;
            const auto group = modrm.reg & 7U;
            std::size_t immediate_size = opcode == 0x80 || opcode == 0x83 ? 1 : 4;
            const auto length = 1 + modrm.size + immediate_size;
            if (remaining < prefix + length) return false;
            std::int64_t immediate = opcode == 0x80 || opcode == 0x83
                                         ? static_cast<std::int8_t>(p[prefix + 1 + modrm.size])
                                         : static_cast<std::int32_t>(u32(p + prefix + 1 + modrm.size));
            const std::array<const char*, 8> groups = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
            const auto op = groups[group];
            const auto lhs = text_operand(modrm);
            const auto rhs = hex_value(static_cast<std::uint64_t>(immediate));
            const auto kind = group == 7 ? InstructionKind::Compare : InstructionKind::Arithmetic;
            emit_binary(op, kind, modrm, lhs, rhs, group != 7, length);
            instruction.constant_value = BitVector::from_signed(byte_width, immediate);
            return true;
        }

        if (opcode == 0xc1 || opcode == 0xd1 || opcode == 0xd3) {
            ModRmOperand modrm;
            if (!parse_modrm(p + prefix + 1, remaining - prefix - 1, rex, byte_width, modrm)) return false;
            const auto group = modrm.reg & 7U;
            if (group != 4 && group != 5 && group != 7) return false;
            const auto op = group == 4 ? "shl" : group == 5 ? "shr" : "sar";
            std::size_t extra = opcode == 0xc1 ? 1 : 0;
            if (remaining < prefix + 1 + modrm.size + extra) return false;
            const auto rhs = opcode == 0xd3 ? "cl" : hex_value(opcode == 0xd1 ? 1 : p[prefix + 1 + modrm.size]);
            emit_binary(op, InstructionKind::Arithmetic, modrm, text_operand(modrm), rhs,
                        true, 1 + modrm.size + extra);
            return true;
        }

        if (opcode == 0xc7) {
            ModRmOperand modrm;
            if (!parse_modrm(p + prefix + 1, remaining - prefix - 1, rex, width, modrm) || (modrm.reg & 7U) != 0) return false;
            const auto length = 1 + modrm.size + 4;
            if (remaining < prefix + length) return false;
            const auto value = u32(p + prefix + 1 + modrm.size);
            const auto destination = text_operand(modrm);
            instruction.size = static_cast<std::uint8_t>(prefix + length);
            instruction.kind = InstructionKind::Move;
            instruction.operand_width = static_cast<std::uint8_t>(width);
            instruction.mnemonic = "mov";
            instruction.operands = destination + ", " + hex_value(value);
            instruction.pseudo = destination + " = " + hex_value(value) + ";";
            instruction.read_operands = {hex_value(value)};
            instruction.write_operands = {destination};
            instruction.constant_value = BitVector(width, value);
            set_memory_metadata(instruction, modrm, false, true);
            return true;
        }

        if (opcode == 0x69 || opcode == 0x6b) {
            ModRmOperand modrm;
            if (!parse_modrm(p + prefix + 1, remaining - prefix - 1, rex, width, modrm)) return false;
            const auto immediate_size = opcode == 0x69 ? 4U : 1U;
            const auto length = 1 + modrm.size + immediate_size;
            if (remaining < prefix + length) return false;
            const auto immediate = opcode == 0x69 ? static_cast<std::int64_t>(static_cast<std::int32_t>(u32(p + prefix + 1 + modrm.size)))
                                                  : static_cast<std::int64_t>(static_cast<std::int8_t>(p[prefix + 1 + modrm.size]));
            const auto lhs = generic_register_name(modrm.reg, width);
            const auto rhs = text_operand(modrm);
            instruction.size = static_cast<std::uint8_t>(prefix + length);
            instruction.kind = InstructionKind::Arithmetic;
            instruction.operand_width = static_cast<std::uint8_t>(width);
            instruction.mnemonic = "imul";
            instruction.operands = lhs + ", " + rhs + ", " + hex_value(static_cast<std::uint64_t>(immediate));
            instruction.pseudo = lhs + " = " + rhs + " * " + hex_value(static_cast<std::uint64_t>(immediate)) + ";";
            instruction.read_operands = {rhs};
            instruction.write_operands = {lhs};
            instruction.constant_value = BitVector::from_signed(width, immediate);
            set_memory_metadata(instruction, modrm, true, false);
            return true;
        }

        if (opcode == 0xff) {
            ModRmOperand modrm;
            if (!parse_modrm(p + prefix + 1, remaining - prefix - 1, rex, width, modrm)) return false;
            const auto group = modrm.reg & 7U;
            const auto operand = text_operand(modrm);
            const auto length = 1 + modrm.size;
            if (group == 0 || group == 1) {
                const auto op = group == 0 ? "inc" : "dec";
                emit_binary(op, InstructionKind::Arithmetic, modrm, operand, "1", true, length);
                return true;
            }
            if (group == 2) {
                instruction.size = static_cast<std::uint8_t>(prefix + length);
                instruction.kind = InstructionKind::Call;
                instruction.mnemonic = "call";
                instruction.operands = operand;
                instruction.pseudo = "indirect_call(" + operand + ");";
                instruction.read_operands = {operand};
                set_memory_metadata(instruction, modrm, true, false);
                return true;
            }
            if (group == 4) {
                instruction.size = static_cast<std::uint8_t>(prefix + length);
                instruction.kind = InstructionKind::Jump;
                instruction.mnemonic = "jmp";
                instruction.operands = operand;
                instruction.pseudo = "goto indirect_target(" + operand + ");";
                instruction.read_operands = {operand};
                set_memory_metadata(instruction, modrm, true, false);
                // Common GCC/Clang jump-table form: ff 24 c5 disp32
                // (jmp qword ptr [rax * 8 + table]). Recover in-image
                // absolute entries so CFG construction gets real case edges.
                if (opcode == 0xff && prefix + 7 <= remaining &&
                    p[prefix + 1] == 0x24 && p[prefix + 2] == 0xc5) {
                    const auto table = static_cast<std::uint64_t>(u32(p + prefix + 3));
                    std::vector<std::uint64_t> targets;
                    for (std::size_t entry = 0; entry < 64; ++entry) {
                        const auto address_of_entry = table + entry * 8;
                        if (!image.contains(address_of_entry) ||
                            image.code_end() - address_of_entry < 8) break;
                        const auto target = u64(image.code.data() + image.offset_of(address_of_entry));
                        if (!image.contains(target)) break;
                        targets.push_back(target);
                    }
                    if (targets.size() >= 2) {
                        instruction.indirect_targets = std::move(targets);
                        instruction.is_switch_dispatch = true;
                        instruction.switch_expression = "rax";
                        instruction.pseudo = "switch (rax) goto *" + operand + ";";
                    }
                }
                return true;
            }
        }
        return false;
    };
    if (decode_modrm_family()) return instruction;

    unknown();
    return instruction;
}

} // namespace guapseudo

