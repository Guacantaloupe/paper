#include "paper/core/x86_decoder.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#ifdef PAPER_WITH_ZYDIS
#include <Zydis/Zydis.h>
#endif

namespace paper {
namespace {

bool is_prefix(std::uint8_t byte) {
    return byte == 0xf0 || byte == 0xf2 || byte == 0xf3 || byte == 0x2e || byte == 0x36 ||
           byte == 0x3e || byte == 0x26 || byte == 0x64 || byte == 0x65 || byte == 0x66 ||
           byte == 0x67 || (byte >= 0x40 && byte <= 0x4f);
}

std::string simple_mnemonic(std::uint8_t opcode, bool two_byte) {
    if (two_byte) {
        if (opcode >= 0x80 && opcode <= 0x8f) return "jcc";
        if (opcode >= 0x40 && opcode <= 0x4f) return "cmovcc";
        switch (opcode) {
        case 0x05: return "syscall";
        case 0x0b: return "ud2";
        case 0x1f: return "nop";
        case 0xaf: return "imul";
        case 0xb6: case 0xb7: return "movzx";
        case 0xbe: case 0xbf: return "movsx";
        default: return "op0f";
        }
    }
    if (opcode >= 0x70 && opcode <= 0x7f) return "jcc";
    if (opcode >= 0xb8 && opcode <= 0xbf) return "mov";
    if (opcode >= 0x50 && opcode <= 0x57) return "push";
    if (opcode >= 0x58 && opcode <= 0x5f) return "pop";
    switch (opcode) {
    case 0x90: return "nop";
    case 0x68: case 0x6a: return "push";
    case 0x88: case 0x89: case 0x8a: case 0x8b: return "mov";
    case 0x8d: return "lea";
    case 0x84: case 0x85: return "test";
    case 0xc6: case 0xc7: return "mov";
    case 0xcc: case 0xcd: return "int";
    case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd: case 0xde: case 0xdf: return "x87";
    case 0xf4: return "hlt";
    case 0xf6: case 0xf7: return "group3";
    case 0xfe: case 0xff: return "group5";
    default: return "op";
    }
}

#ifdef PAPER_WITH_ZYDIS
bool decode_with_zydis(Address address, std::span<const std::uint8_t> bytes, Instruction& result) {
    thread_local ZydisDecoder decoder;
    thread_local bool decoder_ready = false;
    thread_local ZydisFormatter formatter;
    thread_local bool formatter_ready = false;
    if (!decoder_ready) {
        if (ZYAN_FAILED(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) return false;
        decoder_ready = true;
    }
    if (!formatter_ready) {
        if (ZYAN_FAILED(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) return false;
        formatter_ready = true;
    }

    ZydisDecodedInstruction decoded{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder, bytes.data(), bytes.size(), &decoded, operands))) return false;
    if (decoded.length == 0 || decoded.length > bytes.size() || decoded.length > result.bytes.size()) return false;

    result.address = address;
    result.length = static_cast<std::uint8_t>(decoded.length);
    result.byte_count = static_cast<std::uint8_t>(decoded.length);
    std::fill(result.bytes.begin(), result.bytes.end(), 0);
    std::copy_n(bytes.begin(), decoded.length, result.bytes.begin());

    char formatted[256]{};
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &decoded, operands,
                                                     decoded.operand_count_visible, formatted,
                                                     sizeof(formatted), address, nullptr))) {
        const std::string text(formatted);
        const auto split = text.find_first_of(" \t");
        if (split == std::string::npos) result.mnemonic = text;
        else {
            result.mnemonic = text.substr(0, split);
            const auto operand_start = text.find_first_not_of(" \t", split);
            if (operand_start != std::string::npos) result.operands = text.substr(operand_start);
        }
    }
    if (result.mnemonic.empty()) result.mnemonic = "op";

    for (std::uint8_t i = 0; i < decoded.operand_count_visible; ++i) {
        const auto& operand = operands[i];
        if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
            result.target = address + decoded.length + static_cast<std::int64_t>(operand.imm.value.s);
        } else if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   (operand.mem.base == ZYDIS_REGISTER_RIP || operand.mem.base == ZYDIS_REGISTER_EIP)) {
            result.rip_relative = true;
            result.target = address + decoded.length + static_cast<std::int64_t>(operand.mem.disp.value);
        }
    }

    switch (decoded.meta.category) {
    case ZYDIS_CATEGORY_CALL:
        result.kind = result.target ? InstructionKind::Call : InstructionKind::IndirectCall;
        result.target_indirect = !result.target.has_value();
        break;
    case ZYDIS_CATEGORY_UNCOND_BR:
        result.kind = result.target ? InstructionKind::Jump : InstructionKind::IndirectJump;
        result.target_indirect = !result.target.has_value();
        break;
    case ZYDIS_CATEGORY_COND_BR:
        result.kind = InstructionKind::ConditionalJump;
        result.target_indirect = !result.target.has_value();
        break;
    case ZYDIS_CATEGORY_RET:
        result.kind = InstructionKind::Return;
        break;
    case ZYDIS_CATEGORY_INTERRUPT:
        result.kind = result.mnemonic == "int3" ? InstructionKind::Trap : InstructionKind::Normal;
        break;
    default:
        result.kind = InstructionKind::Normal;
        break;
    }
    return true;
}
#endif

} // namespace

Instruction X86Decoder::decode(Address address, std::span<const std::uint8_t> bytes) const {
    Instruction result;
    result.address = address;
    result.byte_count = static_cast<std::uint8_t>(std::min<std::size_t>(bytes.size(), result.bytes.size()));
    std::copy_n(bytes.begin(), result.byte_count, result.bytes.begin());
    if (bytes.empty()) {
        result.mnemonic = "db";
        result.kind = InstructionKind::Data;
        return result;
    }

#ifdef PAPER_WITH_ZYDIS
    if (decode_with_zydis(address, bytes, result)) return result;
#endif

    std::size_t cursor = 0;
    bool rex_w = false;
    bool address32 = false;
    while (cursor < bytes.size() && cursor < 15 && is_prefix(bytes[cursor])) {
        const auto prefix = bytes[cursor++];
        rex_w = rex_w || (prefix >= 0x48 && prefix <= 0x4f);
        address32 = address32 || prefix == 0x67;
    }
    if (cursor >= bytes.size()) {
        result.length = 1;
        result.mnemonic = "db";
        result.kind = InstructionKind::Data;
        return result;
    }

    const std::uint8_t first = bytes[cursor++];
    bool two_byte = false;
    std::uint8_t opcode = first;
    if (first == 0x0f && cursor < bytes.size()) {
        two_byte = true;
        opcode = bytes[cursor++];
    }

    std::size_t modrm_offset = cursor;
    ModrmInfo modrm{};
    bool modrm_present = has_modrm(opcode, two_byte);
    if (modrm_present && cursor < bytes.size()) {
        modrm = parse_modrm(bytes, cursor, address32);
        cursor += modrm.length;
    }

    std::size_t immediate = immediate_size(opcode, two_byte, rex_w, modrm.reg);
    if (!two_byte) {
        if (opcode == 0x68) immediate = 4;
        if (opcode == 0x6a) immediate = 1;
        if (opcode >= 0xb8 && opcode <= 0xbf) immediate = rex_w ? 8 : 4;
        if (opcode >= 0x70 && opcode <= 0x7f) immediate = 1;
        if (opcode >= 0xe0 && opcode <= 0xe3) immediate = 1;
        if (opcode == 0xe8 || opcode == 0xe9) immediate = 4;
        if (opcode == 0xeb) immediate = 1;
        if (opcode == 0xc2 || opcode == 0xca) immediate = 2;
        if (opcode >= 0xa0 && opcode <= 0xa3) immediate = address32 ? 4 : 8;
    } else if (opcode >= 0x80 && opcode <= 0x8f) {
        immediate = 4;
    }

    const std::size_t length_before_imm = cursor;
    if (cursor + immediate > bytes.size() || cursor + immediate > 15) {
        result.length = 1;
        result.mnemonic = "db";
        result.kind = InstructionKind::Data;
        result.operands = "truncated";
        return result;
    }
    cursor += immediate;
    result.length = static_cast<std::uint8_t>(std::max<std::size_t>(1, cursor));
    result.mnemonic = simple_mnemonic(opcode, two_byte);

    const bool short_conditional = !two_byte && ((opcode >= 0x70 && opcode <= 0x7f) || (opcode >= 0xe0 && opcode <= 0xe3));
    const bool near_conditional = two_byte && opcode >= 0x80 && opcode <= 0x8f;
    if (!two_byte && opcode == 0xe8) {
        result.kind = InstructionKind::Call;
        result.target = address + result.length + static_cast<std::int64_t>(read_signed(bytes, length_before_imm, 4));
        result.operands = hex_address(*result.target);
        result.mnemonic = "call";
    } else if (!two_byte && (opcode == 0xe9 || opcode == 0xeb)) {
        result.kind = InstructionKind::Jump;
        const auto width = opcode == 0xeb ? 1 : 4;
        result.target = address + result.length + static_cast<std::int64_t>(read_signed(bytes, length_before_imm, width));
        result.operands = hex_address(*result.target);
        result.mnemonic = "jmp";
    } else if (short_conditional || near_conditional) {
        result.kind = InstructionKind::ConditionalJump;
        const auto width = short_conditional ? 1 : 4;
        result.target = address + result.length + static_cast<std::int64_t>(read_signed(bytes, length_before_imm, width));
        result.operands = hex_address(*result.target);
        result.mnemonic = "jcc";
    } else if (!two_byte && (opcode == 0xc3 || opcode == 0xcb || opcode == 0xcf || opcode == 0xc2 || opcode == 0xca)) {
        result.kind = InstructionKind::Return;
        result.mnemonic = "ret";
    } else if (!two_byte && opcode == 0xcc) {
        result.kind = InstructionKind::Trap;
        result.mnemonic = "int3";
    } else if (!two_byte && opcode == 0xff && modrm_present) {
        if (modrm.reg == 2 || modrm.reg == 3) {
            result.kind = InstructionKind::IndirectCall;
            result.target_indirect = true;
            result.mnemonic = "call";
            result.operands = "[indirect]";
        } else if (modrm.reg == 4 || modrm.reg == 5) {
            result.kind = InstructionKind::IndirectJump;
            result.target_indirect = true;
            result.mnemonic = "jmp";
            result.operands = "[indirect]";
        }
    }

    if (modrm_present && modrm.length > 0 && modrm.rip_relative) {
        result.rip_relative = true;
        result.target = address + result.length + static_cast<std::int64_t>(modrm.displacement);
        if (result.operands.empty()) result.operands = "[rip+" + hex_address(*result.target) + "]";
    }
    if (result.operands.empty() && result.mnemonic != "nop" && result.mnemonic != "ret" && result.mnemonic != "int3") {
        result.operands = modrm_present ? "..." : "";
    }
    if (result.length > result.byte_count) {
        // The caller may pass a short tail of a section. Keep the decoded
        // boundary bounded by available bytes so it can never skip memory.
        result.length = result.byte_count == 0 ? 1 : result.byte_count;
    }
    result.byte_count = static_cast<std::uint8_t>(std::min<std::size_t>(result.length, bytes.size()));
    std::fill(result.bytes.begin(), result.bytes.end(), 0);
    std::copy_n(bytes.begin(), result.byte_count, result.bytes.begin());
    (void)modrm_offset;
    return result;
}

bool X86Decoder::has_modrm(std::uint8_t opcode, bool two_byte) {
    if (two_byte) {
        if (opcode >= 0x80 && opcode <= 0x8f) return false;
        return opcode != 0x05 && opcode != 0x0b && opcode != 0x31 && opcode != 0x33 &&
               opcode != 0x34 && opcode != 0x35 && opcode != 0xa2;
    }
    if (opcode <= 0x03 || (opcode >= 0x08 && opcode <= 0x0b) ||
        (opcode >= 0x10 && opcode <= 0x13) || (opcode >= 0x18 && opcode <= 0x1b) ||
        (opcode >= 0x20 && opcode <= 0x23) || (opcode >= 0x28 && opcode <= 0x2b) ||
        (opcode >= 0x30 && opcode <= 0x33) || (opcode >= 0x38 && opcode <= 0x3b)) return true;
    return opcode == 0x62 || opcode == 0x63 || opcode == 0x69 || opcode == 0x6b ||
           (opcode >= 0x80 && opcode <= 0x8f) || opcode == 0xc0 || opcode == 0xc1 ||
           opcode == 0xc4 || opcode == 0xc5 || opcode == 0xc6 || opcode == 0xc7 ||
           (opcode >= 0xd0 && opcode <= 0xd3) || opcode == 0xf6 || opcode == 0xf7 ||
           opcode == 0xfe || opcode == 0xff;
}

std::size_t X86Decoder::immediate_size(std::uint8_t opcode, bool two_byte, bool, std::uint8_t modrm_reg) {
    if (two_byte) return opcode == 0xba || opcode == 0xa4 || opcode == 0xa5 ? 1 : 0;
    switch (opcode) {
    case 0x04: case 0x0c: case 0x14: case 0x1c: case 0x24: case 0x2c: case 0x34: case 0x3c:
    case 0x80: case 0x82: case 0x83: case 0xc0: case 0xc1: case 0xc6: return 1;
    case 0x05: case 0x0d: case 0x15: case 0x1d: case 0x25: case 0x2d: case 0x35: case 0x3d:
    case 0x69: case 0x81: case 0xc7: return 4;
    case 0x6b: return 1;
    case 0xf6: return modrm_reg <= 1 ? 1 : 0;
    case 0xf7: return modrm_reg <= 1 ? 4 : 0;
    default: return 0;
    }
}

X86Decoder::ModrmInfo X86Decoder::parse_modrm(std::span<const std::uint8_t> bytes, std::size_t offset, bool address32) {
    ModrmInfo info;
    if (offset >= bytes.size()) return info;
    const std::uint8_t modrm = bytes[offset];
    info.length = 1;
    info.mod = static_cast<std::uint8_t>(modrm >> 6);
    info.reg = static_cast<std::uint8_t>((modrm >> 3) & 7);
    info.rm = static_cast<std::uint8_t>(modrm & 7);
    if (info.mod != 3 && info.rm == 4) {
        if (offset + info.length >= bytes.size()) return info;
        const std::uint8_t sib = bytes[offset + info.length++];
        const std::uint8_t base = sib & 7;
        if (info.mod == 0 && base == 5) {
            if (offset + info.length + 4 <= bytes.size()) {
                info.displacement = static_cast<std::int32_t>(read_unsigned(bytes, offset + info.length, 4));
            }
            info.length += 4;
        }
    } else if (info.mod == 0 && info.rm == 5 && !address32) {
        info.rip_relative = true;
        if (offset + info.length + 4 <= bytes.size()) {
            info.displacement = static_cast<std::int32_t>(read_unsigned(bytes, offset + info.length, 4));
        }
        info.length += 4;
    }
    if (info.mod == 1) info.length += 1;
    if (info.mod == 2) info.length += 4;
    return info;
}

std::int64_t X86Decoder::read_signed(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t size) {
    const auto value = read_unsigned(bytes, offset, size);
    if (size == 1) return static_cast<std::int8_t>(value);
    if (size == 2) return static_cast<std::int16_t>(value);
    if (size == 4) return static_cast<std::int32_t>(value);
    return static_cast<std::int64_t>(value);
}

std::uint64_t X86Decoder::read_unsigned(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t size) {
    if (size > 8 || offset > bytes.size() || size > bytes.size() - offset) return 0;
    std::uint64_t result = 0;
    for (std::size_t i = 0; i < size; ++i) result |= static_cast<std::uint64_t>(bytes[offset + i]) << (i * 8);
    return result;
}

std::string X86Decoder::hex_address(Address address) {
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(address));
    return buffer;
}

} // namespace paper

