#pragma once

#include "guapseudo/model.hpp"

namespace guapseudo {

class ControlFlowStructurer {
public:
    static void run(Function& function);
};

const char* control_flow_region_name(ControlFlowRegionKind kind);

} // namespace guapseudo

