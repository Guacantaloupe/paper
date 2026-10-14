#pragma once

#include "guapseudo/model.hpp"

#include <iosfwd>

namespace guapseudo {

class PseudoCPrinter {
public:
    void print(const BinaryImage& image, const AnalysisResult& result, std::ostream& out) const;
};

} // namespace guapseudo

