#pragma once

#include "paper/core/pe_image.hpp"
#include "paper/json.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace paper {

struct StringLiteral {
    Address address = 0;
    std::string value;
};

class Analyzer {
public:
    Analyzer();

    bool open_file(const std::string& path, std::string& error);
    void clear();

    Json module_info() const;
    Json list_sections() const;
    Json list_segments() const;
    Json list_functions(const Json& arguments) const;
    Json get_function(const Json& arguments) const;
    Json disassemble(const Json& arguments) const;
    Json read_bytes(const Json& arguments) const;
    Json xrefs_to(const Json& arguments) const;
    Json xrefs_from(const Json& arguments) const;
    Json cfg(const Json& arguments) const;
    Json search_strings(const Json& arguments) const;
    Json list_strings(const Json& arguments) const;
    Json search_bytes(const Json& arguments) const;
    Json list_imports(const Json& arguments) const;
    Json list_exports(const Json& arguments) const;
    Json list_names(const Json& arguments) const;
    Json list_bookmarks(const Json& arguments) const;
    Json call_graph(const Json& arguments) const;
    Json analysis_stats() const;

    // IDA-style database annotations. These are deliberately kept separate
    // from the decoded PE bytes so analysis remains repeatable and the
    // sidecar can be shared by the GUI and the local AI/MCP client.
    Json set_name(const Json& arguments);
    Json set_comment(const Json& arguments);
    Json set_bookmark(const Json& arguments);
    Json save_database(const Json& arguments);
    Json load_database(const Json& arguments);

    Json call_tool(std::string_view name, const Json& arguments, bool& ok);

private:
    struct BlockRecord {
        BasicBlock block;
        std::size_t function_index = 0;
    };

    void analyze();
    void build_functions_and_cfg(const std::vector<Address>& starts);
    void build_strings();

    const Instruction* instruction_at(Address address) const;
    const Function* function_at(Address address) const;
    const Section* section_at(Address address) const;
    static Address argument_address(const Json& arguments, std::string_view key);
    static std::size_t argument_size(const Json& arguments, std::string_view key, std::size_t fallback);
    static std::string address_string(Address address);

    mutable std::shared_mutex mutex_;
    PeImage image_;
    std::vector<Instruction> instructions_;
    std::unordered_map<Address, std::size_t> instruction_index_;
    std::vector<Function> functions_;
    std::unordered_map<Address, std::size_t> function_index_;
    std::vector<BlockRecord> blocks_;
    std::unordered_map<Address, std::size_t> block_index_;
    std::unordered_map<Address, std::vector<Xref>> xrefs_to_;
    std::unordered_map<Address, std::vector<Xref>> xrefs_from_;
    std::vector<StringLiteral> strings_;
    std::unordered_map<Address, std::string> names_;
    std::unordered_map<Address, std::string> comments_;
    std::unordered_map<Address, std::string> bookmarks_;
    std::string database_path_;
    AnalysisStats stats_;
};

} // namespace paper

