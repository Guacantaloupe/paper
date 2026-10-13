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
    Json list_vtables(const Json& arguments) const;
    Json vtable_of(const Json& arguments) const;
    Json function_strings(const Json& arguments) const;
    Json list_runtime_functions(const Json& arguments) const;
    Json list_switches(const Json& arguments) const;
    Json stack_variables(const Json& arguments) const;
    Json function_dataflow(const Json& arguments) const;
    Json function_signature(const Json& arguments) const;
    Json object_fields(const Json& arguments) const;
    Json function_xrefs(const Json& arguments) const;
    Json analyze_function(const Json& arguments) const;
    Json list_noreturn_functions(const Json& arguments) const;
    Json list_rtti(const Json& arguments) const;
    Json list_exceptions(const Json& arguments) const;
    Json list_tls_callbacks(const Json& arguments) const;
    Json list_relocations(const Json& arguments) const;
    Json list_resources(const Json& arguments) const;
    Json pdb_info(const Json& arguments) const;
    Json load_symbols(const Json& arguments);
    Json list_symbols(const Json& arguments) const;
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

    struct VtableRecord {
        Address start = 0;
        Address end = 0;
        std::vector<Address> slots;
    };

    struct RttiRecord {
        Address vtable = 0;
        Address complete_object_locator = 0;
        Address type_descriptor = 0;
        std::string type_name;
        std::vector<std::string> bases;
    };

    struct SwitchRecord {
        Address instruction = 0;
        Address table = 0;
        std::size_t entry_size = 0;
        bool relative = false;
        Address table_end = 0;
        std::vector<Address> targets;
    };

    struct IndirectTargetRecord {
        Address instruction = 0;
        Address target = 0;
        InstructionKind kind = InstructionKind::IndirectCall;
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
    std::vector<VtableRecord> discover_vtables() const;
    std::vector<RttiRecord> discover_rtti() const;
    std::vector<SwitchRecord> discover_switches(const Function* function) const;
    std::vector<IndirectTargetRecord> collect_indirect_targets(const Function* function) const;
    void propagate_noreturn();
    bool is_noreturn_target(Address address) const;
    static bool known_noreturn_name(std::string_view name);

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
    std::vector<DebugSymbol> symbols_;
    std::string symbol_source_;
    std::unordered_set<Address> noreturn_targets_;
    std::unordered_set<Address> noreturn_functions_;
    std::unordered_map<Address, std::string> noreturn_reasons_;
    mutable std::vector<VtableRecord> vtable_cache_;
    mutable bool vtable_cache_valid_ = false;
    mutable std::vector<RttiRecord> rtti_cache_;
    mutable bool rtti_cache_valid_ = false;
    std::unordered_map<Address, std::string> names_;
    std::unordered_map<Address, std::string> comments_;
    std::unordered_map<Address, std::string> bookmarks_;
    std::string database_path_;
    AnalysisStats stats_;
};

} // namespace paper

