#pragma once

#include "guapseudo/model.hpp"

namespace guapseudo {

class SsaTypeAnalyzer {
public:
    static void run(Function& function);
};

const char* value_type_name(ValueType type);

} // namespace guapseudo

