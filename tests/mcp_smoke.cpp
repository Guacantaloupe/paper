#include "paper/core/rpc.hpp"

#include <cassert>
#include <sstream>
#include <string>

int main() {
    paper::Analyzer analyzer;
    paper::McpServer server(analyzer);

    std::istringstream input(
        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}})"
        "\n"
        R"({"jsonrpc":"2.0","method":"notifications/initialized"})"
        "\n"
        R"({"jsonrpc":"2.0","id":2,"method":"ping"})"
        "\n"
        R"({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})"
        "\n"
        R"({"jsonrpc":"2.0","method":"ping"})"
        "\n"
        R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"module_info","arguments":{}}})"
        "\n"
        R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"search_strings","arguments":{"pattern":"ResourceManager"}}})"
        "\n"
        R"({"jsonrpc":"1.0","id":5,"method":"ping"})"
        "\n");
    std::ostringstream output;
    server.run(input, output);

    std::istringstream responses(output.str());
    std::string line;
    int response_count = 0;
    while (std::getline(responses, line)) {
        if (!line.empty()) ++response_count;
    }
    assert(response_count == 6);
    assert(output.str().find("unknown argument: pattern") != std::string::npos);
    assert(output.str().find("list_switches") != std::string::npos);
    assert(output.str().find("list_rtti") != std::string::npos);

    const auto unicode = paper::Json::parse(R"({"text":"\u4e2d\u6587 \ud83d\ude80"})");
    assert(unicode.find("text") && unicode.find("text")->as_string() == "中文 🚀");
    return 0;
}
