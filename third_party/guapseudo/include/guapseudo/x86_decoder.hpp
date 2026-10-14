#pragma once

#include "guapseudo/model.hpp"

#include <cstdint>

namespace guapseudo {

class X86_64Decoder {
public:
    Instruction decode(const BinaryImage& image, std::uint64_t address) const;

private:
    static std::int8_t i8(const std::uint8_t* p);
    static std::int32_t i32(const std::uint8_t* p);
    static std::uint32_t u32(const std::uint8_t* p);
    static std::uint64_t u64(const std::uint8_t* p);
    static std::string register_name(unsigned index, bool wide = true);
    static std::string hex_value(std::uint64_t value);
    static bool is_conditional_opcode(std::uint8_t opcode);
};

} // namespace guapseudo

