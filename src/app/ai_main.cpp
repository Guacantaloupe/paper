#include "paper/core/rpc.hpp"

#include <iostream>

int main() {
    paper::Analyzer analyzer;
    paper::McpServer server(analyzer);
    server.run(std::cin, std::cout);
    return 0;
}

