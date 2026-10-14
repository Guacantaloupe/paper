#pragma once

#include "guapseudo/model.hpp"

namespace guapseudo {

class GhidraHeuristics {
public:
    static void apply(const BinaryImage& image, Function& function);
};

const char* ghidra_type_name(ValueType type);

} // namespace guapseudo

