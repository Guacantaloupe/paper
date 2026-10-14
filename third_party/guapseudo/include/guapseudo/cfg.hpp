#pragma once

#include "guapseudo/model.hpp"

namespace guapseudo {

class ControlFlowAnalyzer {
public:
    static void build(Function& function);
};

} // namespace guapseudo

