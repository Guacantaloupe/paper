#pragma once

#include "paper/json.hpp"

namespace paper {

// Runs the embedded GuaPseudo-C engine against a PE/ELF/raw image.
Json guapseudo_decompile(const Json& arguments);

} // namespace paper
