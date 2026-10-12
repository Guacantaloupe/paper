#pragma once

#include "paper/core/types.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace paper {

class X86Decoder {
public:
    // Decode one 16-byte window in 64-bit mode. When PAPER_WITH_ZYDIS is
    // enabled this uses Zydis first; otherwise the compact built-in decoder
    // focuses on boundaries and control-flow/data references needed by the
    // static-analysis index.
    Instruction decode(Address address, std::span<const std::uint8_t> bytes) const;

private:
    struct ModrmInfo {
        std::size_t length = 0;
        std::uint8_t reg = 0;
        std::uint8_t mod = 0;
        std::uint8_t rm = 0;
        bool rip_relative = false;
        std::int32_t displacement = 0;
    };

    static bool has_modrm(std::uint8_t opcode, bool two_byte);
    static std::size_t immediate_size(std::uint8_t opcode, bool two_byte, bool rex_w, std::uint8_t modrm_reg);
    static ModrmInfo parse_modrm(std::span<const std::uint8_t> bytes, std::size_t offset, bool address32);
    static std::int64_t read_signed(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t size);
    static std::uint64_t read_unsigned(std::span<const std::uint8_t> bytes, std::size_t offset, std::size_t size);
    static std::string hex_address(Address address);
};

} // namespace paper

