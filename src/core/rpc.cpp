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

Json tool(std::string_view name, std::string_view description, Json properties, Json required = Json::array()) {
    Json item = Json::object();
    item["name"] = name;
    item["description"] = description;
    Json input = Json::object();
    input["type"] = "object";
    input["properties"] = std::move(properties);
    input["required"] = std::move(required);
    item["inputSchema"] = std::move(input);
    return item;
}

Json required_list(std::initializer_list<std::string_view> names) {
    Json result = Json::array();
    for (const auto name : names) result.push_back(std::string(name));
    return result;
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
    const Json* id = request.find("id");
    const Json request_id = id ? *id : Json(nullptr);
    const auto* method_value = request.find("method");
    if (!method_value || !method_value->is_string()) return error_response(request_id, -32600, "missing JSON-RPC method");
    const auto method = method_value->as_string();
    if (method.rfind("notifications/", 0) == 0) return Json(nullptr);

    if (method == "initialize") {
        Json result = Json::object();
        result["protocolVersion"] = "2024-11-05";
        Json capabilities = Json::object();
        capabilities["tools"] = Json::object();
        result["capabilities"] = std::move(capabilities);
        Json server_info = Json::object();
        server_info["name"] = "paper-ai";
        server_info["version"] = "0.2.0";
        result["serverInfo"] = std::move(server_info);
        Json response = Json::object();
        response["jsonrpc"] = "2.0";
        response["id"] = request_id;
        response["result"] = std::move(result);
        return response;
    }
    if (method == "tools/list") {
        Json response = Json::object();
        response["jsonrpc"] = "2.0";
        response["id"] = request_id;
        response["result"] = tool_list();
        return response;
    }
    if (method != "tools/call") return error_response(request_id, -32601, "method not found");

    const auto* params = request.find("params");
    if (!params || !params->is_object()) return error_response(request_id, -32602, "tools/call requires params");
    const auto* name_value = params->find("name");
    const auto* arguments = params->find("arguments");
    if (!name_value || !name_value->is_string()) return error_response(request_id, -32602, "tools/call requires a tool name");
    const Json empty_arguments = Json::object();
    const Json& args = arguments ? *arguments : empty_arguments;
    Json result = Json::object();
    bool ok = true;
    if (name_value->as_string() == "open_binary") {
        const auto* path = args.find("path");
        std::string error;
        ok = path && path->is_string() && analyzer_.open_file(path->as_string(), error);
        if (ok) {
            result["ok"] = true;
            result["module"] = analyzer_.module_info();
            result["stats"] = analyzer_.analysis_stats();
        } else {
            result["ok"] = false;
            result["error"] = error.empty() ? "path is required" : error;
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
    tool_result["structuredContent"] = result;
    if (!ok) tool_result["isError"] = true;

    Json response = Json::object();
    response["jsonrpc"] = "2.0";
    response["id"] = request_id;
    response["result"] = std::move(tool_result);
    return response;
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
        properties["limit"] = schema_number();
        tools.push_back(tool(name, name == std::string_view("xrefs_to") ? "Return all indexed references into an address." : "Return all indexed references originating at an address.", std::move(properties), required_list({"address"})));
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

