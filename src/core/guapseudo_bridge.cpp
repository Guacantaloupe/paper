#include "paper/core/guapseudo_bridge.hpp"

#include "guapseudo/analyzer.hpp"
#include "guapseudo/binary_image.hpp"
#include "guapseudo/pseudoc_printer.hpp"

#include <sstream>
#include <stdexcept>

namespace paper {

Json guapseudo_decompile(const Json& arguments) {
    const auto* path = arguments.find("path");
    if (!path || !path->is_string()) throw std::runtime_error("decompile_pseudoc requires path");

    const auto image = guapseudo::BinaryImageLoader::load_file(path->as_string());
    guapseudo::AnalysisConfig config;
    if (const auto* value = arguments.find("threads"); value && value->is_number())
        config.thread_count = static_cast<unsigned>(value->as_u64());
    if (const auto* value = arguments.find("max_function_bytes"); value && value->is_number())
        config.max_function_bytes = static_cast<std::size_t>(value->as_u64());

    const auto result = guapseudo::ParallelAnalyzer().analyze(image, config);
    std::ostringstream output;
    guapseudo::PseudoCPrinter().print(image, result, output);

    Json response = Json::object();
    response["pseudo_c"] = output.str();
    response["functions"] = static_cast<std::uint64_t>(result.functions.size());
    response["decoded_instructions"] = static_cast<std::uint64_t>(result.decoded_instructions);
    response["workers"] = static_cast<std::uint64_t>(result.worker_count);
    response["engine"] = "GuaPseudo-C";
    return response;
}

} // namespace paper
