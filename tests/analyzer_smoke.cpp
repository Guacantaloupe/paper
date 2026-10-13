#include "paper/core/analyzer.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

void put16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

void put64(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
}

std::vector<std::uint8_t> make_fixture() {
    std::vector<std::uint8_t> bytes(0x800, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    put32(bytes, 0x3c, 0x80);
    std::memcpy(bytes.data() + 0x80, "PE\0\0", 4);
    put16(bytes, 0x84, 0x8664);
    put16(bytes, 0x86, 3);
    put16(bytes, 0x94, 0xf0);
    const std::size_t optional = 0x98;
    put16(bytes, optional, 0x20b);
    put32(bytes, optional + 16, 0x1000);
    put64(bytes, optional + 24, 0x140000000ull);
    put32(bytes, optional + 32, 0x1000);
    put32(bytes, optional + 36, 0x200);
    put32(bytes, optional + 56, 0x4000);
    put32(bytes, optional + 60, 0x200);
    put32(bytes, optional + 108, 16);
    // IMAGE_DIRECTORY_ENTRY_IMPORT: RVA 0x3000, one descriptor plus a null terminator.
    put32(bytes, optional + 112 + 8, 0x3000);
    put32(bytes, optional + 112 + 12, 40);

    const std::size_t sections = optional + 0xf0;
    std::memcpy(bytes.data() + sections, ".text", 5);
    put32(bytes, sections + 8, 0x200); put32(bytes, sections + 12, 0x1000);
    put32(bytes, sections + 16, 0x200); put32(bytes, sections + 20, 0x200);
    put32(bytes, sections + 36, 0x60000020);
    std::memcpy(bytes.data() + sections + 40, ".rdata", 6);
    put32(bytes, sections + 48, 0x200); put32(bytes, sections + 52, 0x2000);
    put32(bytes, sections + 56, 0x200); put32(bytes, sections + 60, 0x400);
    put32(bytes, sections + 76, 0x40000040);
    std::memcpy(bytes.data() + sections + 80, ".idata", 6);
    put32(bytes, sections + 88, 0x200); put32(bytes, sections + 92, 0x3000);
    put32(bytes, sections + 96, 0x200); put32(bytes, sections + 100, 0x600);
    put32(bytes, sections + 116, 0xc0000040);

    // call qword ptr [rip + 0x205a] -> image+0x3060 (the ExitProcess IAT slot), ret.
    bytes[0x200] = 0xff; bytes[0x201] = 0x15; bytes[0x202] = 0x5a;
    bytes[0x203] = 0x20; bytes[0x204] = 0x00; bytes[0x205] = 0x00; bytes[0x206] = 0xc3;

    // Import descriptor at RVA 0x3000.
    put32(bytes, 0x600, 0x3040); // OriginalFirstThunk / ILT
    put32(bytes, 0x60c, 0x3080); // DLL name
    put32(bytes, 0x610, 0x3060); // FirstThunk / IAT
    put64(bytes, 0x640, 0x3090); // ILT[0] -> hint/name
    put64(bytes, 0x648, 0);
    put64(bytes, 0x660, 0); // IAT is zero before the loader binds it.
    std::memcpy(bytes.data() + 0x680, "KERNEL32.dll\0", 13);
    bytes[0x690] = 0; bytes[0x691] = 0;
    std::memcpy(bytes.data() + 0x692, "ExitProcess\0", 12);
    return bytes;
}

} // namespace

int main() {
    const auto path = std::filesystem::temp_directory_path() / "paper_analyzer_smoke_fixture.exe";
    std::filesystem::remove(path.string() + ".paper.json");
    const auto bytes = make_fixture();
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        assert(output);
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        assert(output);
    }

    paper::Analyzer analyzer;
    std::string error;
    assert(analyzer.open_file(path.string(), error));
    assert(error.empty());

    paper::Json args = paper::Json::object();
    args["address"] = "0x140003060";
    const auto refs = analyzer.xrefs_to(args);
    assert(refs.is_array() && refs.array_items().size() == 1);
    const auto& ref = refs.array_items().front();
    assert(ref.find("kind") && ref.find("kind")->as_string() == "call");
    assert(ref.find("symbol") && ref.find("symbol")->as_string() == "KERNEL32.dll!ExitProcess");
    paper::Json noreturn_args = paper::Json::object();
    noreturn_args["address"] = "0x140001000";
    const auto function_summary = analyzer.get_function(noreturn_args);
    assert(function_summary.find("noreturn") && function_summary.find("noreturn")->as_bool());
    const auto noreturns = analyzer.list_noreturn_functions(paper::Json::object());
    assert(noreturns.is_array() && !noreturns.array_items().empty());
    const auto dataflow = analyzer.function_dataflow(noreturn_args);
    assert(dataflow.find("indirect_targets") && dataflow.find("indirect_targets")->is_array());
    const auto signature = analyzer.function_signature(noreturn_args);
    assert(signature.find("calling_convention") && signature.find("calling_convention")->as_string() == "microsoft_x64");
    const auto fields = analyzer.object_fields(noreturn_args);
    assert(fields.is_array());
    const auto bundle = analyzer.analyze_function(noreturn_args);
    assert(bundle.find("analysis_scope") && bundle.find("analysis_scope")->as_string() == "single_function");
    const auto function_xrefs = analyzer.function_xrefs(noreturn_args);
    assert(function_xrefs.find("outgoing") && function_xrefs.find("strings"));
    paper::Json bad_arguments = paper::Json::object();
    bad_arguments["pattern"] = "ResourceManager";
    bool tool_ok = true;
    const auto bad_result = analyzer.call_tool("search_strings", bad_arguments, tool_ok);
    assert(!tool_ok && bad_result.find("error"));
    paper::Json search_args = paper::Json::object();
    search_args["pattern"] = "ff ?? 5a";
    assert(analyzer.search_bytes(search_args).array_items().size() == 1);

    paper::Json function_args = paper::Json::object();
    function_args["function_address"] = "0x140001000";
    function_args["direction"] = "callees";
    const auto graph = analyzer.call_graph(function_args);
    assert(graph.find("nodes") && graph.find("nodes")->array_items().size() == 1);

    paper::Json annotation = paper::Json::object();
    annotation["address"] = "0x140001000";
    annotation["name"] = "entry_fixture";
    assert(analyzer.set_name(annotation).find("ok")->as_bool());
    annotation["comment"] = "fixture entry";
    assert(analyzer.set_comment(annotation).find("ok")->as_bool());
    annotation["enabled"] = true;
    assert(analyzer.set_bookmark(annotation).find("ok")->as_bool());
    const auto saved = analyzer.save_database(paper::Json::object());
    assert(saved.find("ok") && saved.find("ok")->as_bool());

    paper::Analyzer reloaded;
    assert(reloaded.open_file(path.string(), error));
    paper::Json named_args = paper::Json::object();
    named_args["query"] = "entry_fixture";
    assert(reloaded.list_names(named_args).array_items().size() == 1);
    named_args["address"] = "0x140001000";
    assert(reloaded.get_function(named_args).find("name")->as_string() == "entry_fixture");
    assert(reloaded.list_bookmarks(paper::Json::object()).array_items().size() == 1);
    std::filesystem::remove(path.string() + ".paper.json");
    return 0;
}
