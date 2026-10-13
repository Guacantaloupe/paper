#include "paper/core/rpc.hpp"

#include <iostream>

namespace paper {
namespace {

Json schema_string() {
    Json schema = Json::object();
    schema["type"] = "string";
    return schema;
}

Json schema_number() {
    Json schema = Json::object();
    schema["type"] = "integer";
    schema["minimum"] = 0;
    return schema;
}

Json schema_string_array() {
    Json schema = Json::object();
    schema["type"] = "array";
    Json items = Json::object();
    items["type"] = "string";
    schema["items"] = std::move(items);
    return schema;
}

Json tool(std::string_view name, std::string_view description, Json properties, Json required = Json::array()) {
    Json item = Json::object();
    item["name"] = name;
    item["description"] = description;
    Json input = Json::object();
    input["type"] = "object";
    input["properties"] = std::move(properties);
    input["required"] = std::move(required);
    input["additionalProperties"] = false;
    item["inputSchema"] = std::move(input);
    return item;
}

Json required_list(std::initializer_list<std::string_view> names) {
    Json result = Json::array();
    for (const auto name : names) result.push_back(std::string(name));
    return result;
}

bool valid_request_id(const Json& value) {
    return value.is_null() || value.is_string() || value.is_number();
}

Json rpc_result(const Json& id, Json result) {
    Json response = Json::object();
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["result"] = std::move(result);
    return response;
}

} // namespace

void McpServer::run(std::istream& input, std::ostream& output) {
    std::ios::sync_with_stdio(false);
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) continue;
        try {
            const Json request = Json::parse(line);
            const Json response = handle(request);
            if (response.is_null()) continue;
            output << response.dump() << '\n' << std::flush;
        } catch (const std::exception& exception) {
            output << error_response(Json(nullptr), -32700, exception.what()).dump() << '\n' << std::flush;
        }
    }
}

Json McpServer::handle(const Json& request) {
    if (!request.is_object()) return error_response(Json(nullptr), -32600, "JSON-RPC request must be an object");

    const Json* id = request.find("id");
    const Json request_id = id ? *id : Json(nullptr);
    const bool notification = id == nullptr;
    if (id && !valid_request_id(*id)) return error_response(Json(nullptr), -32600, "invalid JSON-RPC id");

    const auto* version = request.find("jsonrpc");
    if (!version || !version->is_string() || version->as_string() != "2.0") {
        if (notification) return Json(nullptr);
        return error_response(request_id, -32600, "jsonrpc must be \"2.0\"");
    }

    const auto* method_value = request.find("method");
    if (!method_value || !method_value->is_string()) {
        if (notification) return Json(nullptr);
        return error_response(request_id, -32600, "missing JSON-RPC method");
    }
    const auto method = method_value->as_string();

    if (method == "initialize") {
        initialized_ = true;
        Json result = Json::object();
        result["protocolVersion"] = "2024-11-05";
        Json capabilities = Json::object();
        Json tools_capability = Json::object();
        tools_capability["listChanged"] = false;
        capabilities["tools"] = std::move(tools_capability);
        result["capabilities"] = std::move(capabilities);
        Json server_info = Json::object();
        server_info["name"] = "paper-ai";
        server_info["version"] = "0.2.0";
        result["serverInfo"] = std::move(server_info);
        result["instructions"] = "Use tools/call with open_binary before querying the Paper analysis indexes.";
        return notification ? Json(nullptr) : rpc_result(request_id, std::move(result));
    }
    if (method == "notifications/initialized") {
        initialized_ = true;
        return Json(nullptr);
    }
    if (method == "ping") {
        return notification ? Json(nullptr) : rpc_result(request_id, Json::object());
    }
    if (method == "tools/list") {
        if (!initialized_) return notification ? Json(nullptr) : error_response(request_id, -32002, "server is not initialized");
        return notification ? Json(nullptr) : rpc_result(request_id, tool_list());
    }
    if (method != "tools/call") {
        if (notification) return Json(nullptr);
        return error_response(request_id, -32601, "method not found");
    }
    if (!initialized_) return notification ? Json(nullptr) : error_response(request_id, -32002, "server is not initialized");

    const auto* params = request.find("params");
    if (!params || !params->is_object()) {
        if (notification) return Json(nullptr);
        return error_response(request_id, -32602, "tools/call requires an object params value");
    }
    const auto* name_value = params->find("name");
    const auto* arguments = params->find("arguments");
    if (!name_value || !name_value->is_string()) {
        if (notification) return Json(nullptr);
        return error_response(request_id, -32602, "tools/call requires a tool name");
    }
    if (arguments && !arguments->is_object()) {
        if (notification) return Json(nullptr);
        return error_response(request_id, -32602, "tools/call arguments must be an object");
    }
    const Json empty_arguments = Json::object();
    const Json& args = arguments ? *arguments : empty_arguments;
    Json result = Json::object();
    bool ok = true;
    if (name_value->as_string() == "open_binary") {
        for (const auto& [key, value] : args.object_items()) {
            if (key != "path") {
                ok = false;
                result["error"] = "unknown argument: " + key;
                break;
            }
        }
        const auto* path = args.find("path");
        std::string error;
        if (ok) ok = path && path->is_string() && analyzer_.open_file(path->as_string(), error);
        if (ok) {
            result["ok"] = true;
            result["module"] = analyzer_.module_info();
            result["stats"] = analyzer_.analysis_stats();
        } else if (!result.find("error")) {
            result["ok"] = false;
            result["error"] = error.empty() ? "path is required" : error;
        } else {
            result["ok"] = false;
        }
    } else {
        result = analyzer_.call_tool(name_value->as_string(), args, ok);
    }

    Json content_item = Json::object();
    content_item["type"] = "text";
    content_item["text"] = result.dump();
    Json content = Json::array();
    content.push_back(std::move(content_item));
    Json tool_result = Json::object();
    tool_result["content"] = std::move(content);
    // MCP structuredContent is an object. Keep the complete analyzer value
    // under a stable key while content[0].text remains convenient for clients
    // that only implement the textual part of the protocol.
    Json structured = Json::object();
    structured["result"] = result;
    tool_result["structuredContent"] = std::move(structured);
    if (!ok) tool_result["isError"] = true;

    return notification ? Json(nullptr) : rpc_result(request_id, std::move(tool_result));
}

Json McpServer::tool_list() const {
    Json result = Json::object();
    Json tools = Json::array();
    {
        Json properties = Json::object();
        properties["path"] = schema_string();
        tools.push_back(tool("open_binary", "Open and index a PE executable or DLL. This must be called before querying the module.", std::move(properties), required_list({"path"})));
    }
    tools.push_back(tool("module_info", "Return PE identity, architecture, image base, and entry point.", Json::object()));
    tools.push_back(tool("list_sections", "List PE sections and their permissions and address ranges.", Json::object()));
    tools.push_back(tool("list_segments", "List PE segments using IDA terminology; equivalent to list_sections.", Json::object()));
    {
        Json properties = Json::object();
        properties["offset"] = schema_number();
        properties["limit"] = schema_number();
        properties["query"] = schema_string();
        tools.push_back(tool("list_functions", "List indexed function starts, ranges, names, thunks, and block counts.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["name"] = schema_string();
        tools.push_back(tool("get_function", "Resolve a function by address or exact name.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["count"] = schema_number();
        tools.push_back(tool("disassemble", "Return decoded instructions beginning at an address.", std::move(properties), required_list({"address"})));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["count"] = schema_number();
        tools.push_back(tool("read_bytes", "Read raw bytes from a mapped PE section.", std::move(properties), required_list({"address"})));
    }
    for (const auto name : {"xrefs_to", "xrefs_from"}) {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["addresses"] = schema_string_array();
        properties["limit"] = schema_number();
        tools.push_back(tool(name, name == std::string_view("xrefs_to") ? "Return references into address or addresses." : "Return references originating at address or addresses.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["function_address"] = schema_string();
        tools.push_back(tool("cfg", "Return basic blocks, successors, and predecessors for a function.", std::move(properties), required_list({"function_address"})));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["min_length"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool("search_strings", "Search the indexed ASCII and UTF-16 literals.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["min_length"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_strings", "List the indexed string literals for an IDA-style Strings view.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["pattern"] = schema_string();
        properties["limit"] = schema_number();
        tools.push_back(tool("search_bytes", "Search raw image bytes using a hexadecimal pattern.", std::move(properties), required_list({"pattern"})));
    }
    for (const auto name : {"list_imports", "list_exports"}) {
        Json properties = Json::object();
        properties["query"] = schema_string();
        tools.push_back(tool(name, name == std::string_view("list_imports") ? "List imported DLL symbols and IAT addresses." : "List exported names, ordinals, and addresses.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["offset"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_names", "List function, import, export, and user-defined names.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["offset"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_bookmarks", "List persistent address bookmarks and their comments.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_vtables", "List read-only PE data runs containing four or more executable function pointers.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        tools.push_back(tool("vtable_of", "Find the vtable and slot for a function address.", std::move(properties), required_list({"address"})));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        tools.push_back(tool("function_strings", "List string literals referenced by instructions in one function.", std::move(properties), required_list({"address"})));
    }
    {
        Json properties = Json::object();
        properties["offset"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_runtime_functions", "List authoritative x64 PE .pdata runtime function ranges.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["function_address"] = schema_string();
        properties["address"] = schema_string();
        tools.push_back(tool("list_switches", "Recover proven direct-pointer jump tables and their executable case targets.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["function_address"] = schema_string();
        properties["address"] = schema_string();
        tools.push_back(tool("stack_variables", "Map proven RSP/RBP-relative accesses to entry-frame stack slots.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["function_address"] = schema_string();
        properties["address"] = schema_string();
        tools.push_back(tool("function_dataflow", "Perform bounded straight-line constant and indirect-target propagation.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_noreturn_functions", "List functions proven to terminate by known APIs, wrappers, or traps.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_rtti", "Parse verifiable MSVC RTTI descriptors associated with discovered vtables.", std::move(properties)));
    }
    for (const auto name : {"list_exceptions", "list_relocations"}) {
        Json properties = Json::object();
        properties["offset"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool(name, name == std::string_view("list_exceptions") ? "List x64 unwind and exception-handler metadata." : "List PE base relocation entries.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_resources", "List PE resource tree leaves and data ranges.", std::move(properties)));
    }
    tools.push_back(tool("list_tls_callbacks", "List statically mapped TLS callback addresses.", Json::object()));
    tools.push_back(tool("pdb_info", "Return embedded CodeView/PDB identity without fabricating symbols.", Json::object()));
    {
        Json properties = Json::object();
        properties["path"] = schema_string();
        tools.push_back(tool("load_symbols", "Load available PDB symbols through Windows DbgHelp when supported.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["query"] = schema_string();
        properties["offset"] = schema_number();
        properties["limit"] = schema_number();
        tools.push_back(tool("list_symbols", "List symbols loaded from PDB/DbgHelp.", std::move(properties)));
    }
    {
        Json properties = Json::object();
        properties["function_address"] = schema_string();
        properties["direction"] = schema_string();
        properties["depth"] = schema_number();
        tools.push_back(tool("call_graph", "Traverse indexed call edges toward callees or callers.", std::move(properties), required_list({"function_address"})));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["name"] = schema_string();
        tools.push_back(tool("set_name", "Set or clear an IDA-style user name at an address.", std::move(properties), required_list({"address", "name"})));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["comment"] = schema_string();
        tools.push_back(tool("set_comment", "Set or clear a repeatable comment at an address.", std::move(properties), required_list({"address", "comment"})));
    }
    {
        Json properties = Json::object();
        properties["address"] = schema_string();
        properties["enabled"] = Json::object();
        properties["enabled"]["type"] = "boolean";
        properties["comment"] = schema_string();
        tools.push_back(tool("set_bookmark", "Create, update, or remove an address bookmark.", std::move(properties), required_list({"address"})));
    }
    for (const auto name : {"save_database", "load_database"}) {
        Json properties = Json::object();
        properties["path"] = schema_string();
        tools.push_back(tool(name, name == std::string_view("save_database") ? "Save names, comments, and bookmarks to a Paper sidecar database." : "Load names, comments, and bookmarks from a Paper sidecar database.", std::move(properties)));
    }
    tools.push_back(tool("analysis_stats", "Return analysis time, worker count, and index sizes.", Json::object()));
    result["tools"] = std::move(tools);
    return result;
}

Json McpServer::error_response(const Json& id, int code, std::string_view message) const {
    Json error = Json::object();
    error["code"] = code;
    error["message"] = message;
    Json response = Json::object();
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["error"] = std::move(error);
    return response;
}

} // namespace paper

