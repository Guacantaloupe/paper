#pragma once

#include "guapseudo/model.hpp"

namespace guapseudo {

class ParallelAnalyzer {
public:
    AnalysisResult analyze(const BinaryImage& image, const AnalysisConfig& config) const;
};

} // namespace guapseudo

