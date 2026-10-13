#pragma once

#include "paper/core/analyzer.hpp"

#include <iosfwd>

namespace paper {

class McpServer {
public:
    explicit McpServer(Analyzer& analyzer) : analyzer_(analyzer) {}
    void run(std::istream& input, std::ostream& output);

private:
    Json handle(const Json& request);
    Json tool_list() const;
    Json error_response(const Json& id, int code, std::string_view message) const;

    Analyzer& analyzer_;
    bool initialized_ = false;
};

} // namespace paper

