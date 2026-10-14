#pragma once

#include "guapseudo/model.hpp"

#include <cstdint>
#include <unordered_map>

namespace guapseudo {

class ObjdumpDecoder {
public:
    static bool available_for(const BinaryImage& image);
    static std::unordered_map<std::uint64_t, Instruction> decode(const BinaryImage& image);
};

} // namespace guapseudo

