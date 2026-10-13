#include <windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <shellapi.h>

#include "paper/core/analyzer.hpp"

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

// The Win32 backend intentionally keeps this declaration in a #if 0 block so
// including the backend header does not pull <windows.h> into every consumer.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg,
                                                              WPARAM wParam, LPARAM lParam);

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using paper::Address;
using paper::Analyzer;
using paper::Json;

ID3D11Device* g_device = nullptr;
ID3D11DeviceContext* g_device_context = nullptr;
IDXGISwapChain* g_swap_chain = nullptr;
ID3D11RenderTargetView* g_main_render_target = nullptr;
UINT g_resize_width = 0;
UINT g_resize_height = 0;
ImFont* g_code_font = nullptr;
constexpr float kToolbarHeight = 44.0f;

std::string json_string(const Json& value, std::string_view key) {
    const auto* item = value.find(key);
    return item && item->is_string() ? item->as_string() : std::string();
}

std::string json_kind(const Json& value) { return json_string(value, "kind"); }

bool json_bool(const Json& value, std::string_view key, bool fallback = false) {
    const auto* item = value.find(key);
    return item ? item->as_bool(fallback) : fallback;
}

std::string address_text(Address address) {
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(address));
    return buffer;
}

std::optional<Address> parse_address(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    if (text.empty()) return std::nullopt;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text.remove_prefix(2);
    if (text.empty()) return std::nullopt;
    Address value = 0;
    for (const char character : text) {
        unsigned digit = 0;
        if (character >= '0' && character <= '9') digit = static_cast<unsigned>(character - '0');
        else if (character >= 'a' && character <= 'f') digit = static_cast<unsigned>(character - 'a' + 10);
        else if (character >= 'A' && character <= 'F') digit = static_cast<unsigned>(character - 'A' + 10);
        else return std::nullopt;
        if (value > (UINT64_MAX - digit) / 16) return std::nullopt;
        value = value * 16 + digit;
    }
    return value;
}

std::string wide_to_utf8(const wchar_t* text) {
    if (!text || !*text) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), size, nullptr, nullptr);
    result.resize(static_cast<std::size_t>(size - 1));
    return result;
}

std::string choose_pe_file() {
    wchar_t path[32768]{};
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = L"PE images (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All files (*.*)\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameW(&dialog) ? wide_to_utf8(path) : std::string();
}

struct UiState {
    Analyzer analyzer;
    bool has_image = false;
    bool show_functions = true;
    bool show_side = true;
    bool show_lists = true;
    bool show_output = true;
    int side_selection_request = -1;
    int center_selection_request = -1;
    int list_selection_request = -1;
    int selected_function = -1;
    bool focus_goto = false;
    Address current_address = 0;
    std::size_t history_index = 0;
    std::vector<Address> history;
    std::vector<Json> functions;
    std::vector<Json> instructions;
    std::vector<Json> incoming_xrefs;
    std::vector<Json> outgoing_xrefs;
    std::vector<Json> strings;
    std::vector<Json> names;
    std::vector<Json> imports;
    std::vector<Json> exports;
    std::vector<Json> sections;
    std::vector<Json> bookmarks;
    Json properties = Json::object();
    Json cfg = Json::object();
    std::string hex_text;
    std::string output = "Paper ready — static analysis only, no sample execution.";
    std::string status = "Open an EXE, DLL, or SYS image to begin.";
    std::array<char, 256> function_filter{};
    std::array<char, 256> list_filter{};
    std::array<char, 256> name_edit{};
    std::array<char, 512> comment_edit{};
    std::array<char, 256> bookmark_edit{};
    std::array<char, 96> goto_address{};
};

void append_log(UiState& state, std::string message) {
    if (!state.output.empty()) state.output += '\n';
    state.output += std::move(message);
}

void refresh_functions(UiState& state) {
    Json arguments = Json::object();
    arguments["limit"] = 10'000;
    if (state.function_filter[0] != '\0') arguments["query"] = std::string(state.function_filter.data());
    const auto result = state.analyzer.list_functions(arguments);
    state.functions.assign(result.array_items().begin(), result.array_items().end());
    state.selected_function = -1;
}

void refresh_lists(UiState& state) {
    Json arguments = Json::object();
    arguments["limit"] = 50'000;
    if (state.list_filter[0] != '\0') arguments["query"] = std::string(state.list_filter.data());
    const auto strings = state.analyzer.list_strings(arguments);
    const auto names = state.analyzer.list_names(arguments);
    const auto imports = state.analyzer.list_imports(arguments);
    const auto exports = state.analyzer.list_exports(arguments);
    const auto sections = state.analyzer.list_sections();
    const auto bookmarks = state.analyzer.list_bookmarks(arguments);
    state.strings.assign(strings.array_items().begin(), strings.array_items().end());
    state.names.assign(names.array_items().begin(), names.array_items().end());
    state.imports.assign(imports.array_items().begin(), imports.array_items().end());
    state.exports.assign(exports.array_items().begin(), exports.array_items().end());
    state.sections.assign(sections.array_items().begin(), sections.array_items().end());
    state.bookmarks.assign(bookmarks.array_items().begin(), bookmarks.array_items().end());
}

template <std::size_t N>
void copy_text(std::array<char, N>& target, std::string_view value) {
    const auto count = std::min<std::size_t>(N - 1, value.size());
    std::copy_n(value.begin(), count, target.begin());
    target[count] = '\0';
    if (count + 1 < N) std::fill(target.begin() + static_cast<std::ptrdiff_t>(count + 1), target.end(), '\0');
}

void refresh_xrefs(UiState& state, Address address) {
    Json arguments = Json::object();
    arguments["address"] = address_text(address);
    const auto incoming = state.analyzer.xrefs_to(arguments);
    const auto outgoing = state.analyzer.xrefs_from(arguments);
    state.incoming_xrefs.assign(incoming.array_items().begin(), incoming.array_items().end());
    state.outgoing_xrefs.assign(outgoing.array_items().begin(), outgoing.array_items().end());
}

void refresh_hex(UiState& state, Address address) {
    Json arguments = Json::object();
    arguments["address"] = address_text(address);
    arguments["count"] = 256;
    const auto result = state.analyzer.read_bytes(arguments);
    const auto encoded = json_string(result, "bytes");
    if (encoded.empty()) {
        state.hex_text = "No bytes available at this address.";
        return;
    }
    const auto base = parse_address(json_string(result, "address")).value_or(address);
    state.hex_text.clear();
    for (std::size_t offset = 0; offset < encoded.size(); offset += 32) {
        state.hex_text += address_text(base + static_cast<Address>(offset / 2));
        state.hex_text += "  ";
        std::string ascii;
        for (std::size_t index = 0; index < 16; ++index) {
            const auto position = offset + index * 2;
            if (position + 1 < encoded.size()) {
                const auto byte_text = encoded.substr(position, 2);
                state.hex_text += byte_text + ' ';
                const auto byte = static_cast<unsigned>(std::strtoul(byte_text.c_str(), nullptr, 16));
                ascii += byte >= 0x20 && byte <= 0x7e ? static_cast<char>(byte) : '.';
            } else {
                state.hex_text += "   ";
                ascii += ' ';
            }
            if (index == 7) state.hex_text += ' ';
        }
        state.hex_text += " |" + ascii + "|\n";
    }
}

void navigate(UiState& state, Address address, bool add_history = true) {
    if (!address || !state.has_image) return;
    if (add_history) {
        if (state.history.empty()) {
            state.history.push_back(address);
            state.history_index = 0;
        } else if (state.history[state.history_index] != address) {
            if (state.history_index + 1 < state.history.size())
                state.history.erase(state.history.begin() + static_cast<std::ptrdiff_t>(state.history_index + 1), state.history.end());
            state.history.push_back(address);
            state.history_index = state.history.size() - 1;
        }
    }
    state.current_address = address;
    Json arguments = Json::object();
    arguments["address"] = address_text(address);
    arguments["count"] = 256;
    const auto instructions = state.analyzer.disassemble(arguments);
    state.instructions.assign(instructions.array_items().begin(), instructions.array_items().end());
    refresh_xrefs(state, address);
    refresh_hex(state, address);
    state.properties = state.analyzer.get_function(arguments);
    copy_text(state.name_edit, json_string(state.properties, "name"));
    copy_text(state.comment_edit, json_string(state.properties, "comment"));
    state.status = "Viewing " + address_text(address);
}

void open_binary(UiState& state, const std::string& path) {
    if (path.empty()) return;
    std::string error;
    if (!state.analyzer.open_file(path, error)) {
        state.status = error;
        append_log(state, error);
        return;
    }
    state.has_image = true;
    state.history.clear();
    state.history_index = 0;
    state.current_address = 0;
    refresh_functions(state);
    refresh_lists(state);
    const auto stats = state.analyzer.analysis_stats();
    state.status = "Indexed " + std::to_string(stats.find("function_count") ? stats.find("function_count")->as_u64() : 0) +
                   " functions, " + std::to_string(stats.find("instruction_count") ? stats.find("instruction_count")->as_u64() : 0) + " instructions";
    append_log(state, "Loaded " + path + "\n" + state.status + ", " +
               std::to_string(stats.find("xref_count") ? stats.find("xref_count")->as_u64() : 0) + " xrefs");
    const auto info = state.analyzer.module_info();
    if (const auto entry = parse_address(json_string(info, "entry_point"))) navigate(state, *entry);
}

void set_json_property(UiState& state, const Json& value, std::string label) {
    state.properties = value;
    append_log(state, std::move(label));
    state.side_selection_request = 1;
}

void go_back(UiState& state) {
    if (state.history.empty() || state.history_index == 0) return;
    --state.history_index;
    navigate(state, state.history[state.history_index], false);
}

void go_forward(UiState& state) {
    if (state.history.empty() || state.history_index + 1 >= state.history.size()) return;
    ++state.history_index;
    navigate(state, state.history[state.history_index], false);
}

void action_cfg(UiState& state) {
    if (!state.has_image) return;
    Json arguments = Json::object();
    arguments["function_address"] = address_text(state.current_address);
    state.cfg = state.analyzer.cfg(arguments);
    state.properties = state.cfg;
    state.side_selection_request = 1;
    state.center_selection_request = 3;
    append_log(state, "CFG refreshed for " + address_text(state.current_address));
}

void action_call_graph(UiState& state, std::string direction) {
    if (!state.has_image) return;
    Json arguments = Json::object();
    arguments["function_address"] = address_text(state.current_address);
    arguments["direction"] = direction;
    arguments["depth"] = 2;
    set_json_property(state, state.analyzer.call_graph(arguments), direction + " graph refreshed");
}

void action_imports(UiState& state) {
    if (state.has_image) set_json_property(state, state.analyzer.list_imports(Json::object()), "Imports refreshed");
}

void action_exports(UiState& state) {
    if (state.has_image) set_json_property(state, state.analyzer.list_exports(Json::object()), "Exports refreshed");
}

void action_lists(UiState& state, int tab = 0) {
    if (!state.has_image) return;
    refresh_lists(state);
    state.list_selection_request = tab;
    state.show_lists = true;
}

void action_save_database(UiState& state) {
    if (!state.has_image) return;
    const auto result = state.analyzer.save_database(Json::object());
    append_log(state, result.find("ok") && result.find("ok")->as_bool() ?
               "Database saved: " + json_string(result, "path") : "Database save failed: " + json_string(result, "error"));
}

void action_load_database(UiState& state) {
    if (!state.has_image) return;
    const auto result = state.analyzer.load_database(Json::object());
    if (result.find("ok") && result.find("ok")->as_bool()) {
        refresh_functions(state);
        refresh_lists(state);
        navigate(state, state.current_address, false);
        append_log(state, "Database loaded: " + json_string(result, "path"));
    } else {
        append_log(state, "Database load failed: " + json_string(result, "error"));
    }
}

void action_set_name(UiState& state) {
    if (!state.has_image || !state.current_address) return;
    Json arguments = Json::object();
    arguments["address"] = address_text(state.current_address);
    arguments["name"] = std::string(state.name_edit.data());
    const auto result = state.analyzer.set_name(arguments);
    if (result.find("ok") && result.find("ok")->as_bool()) {
        refresh_functions(state);
        refresh_lists(state);
        navigate(state, state.current_address, false);
        append_log(state, "Name updated at " + address_text(state.current_address));
    } else append_log(state, "Name update failed: " + json_string(result, "error"));
}

void action_set_comment(UiState& state) {
    if (!state.has_image || !state.current_address) return;
    Json arguments = Json::object();
    arguments["address"] = address_text(state.current_address);
    arguments["comment"] = std::string(state.comment_edit.data());
    const auto result = state.analyzer.set_comment(arguments);
    if (result.find("ok") && result.find("ok")->as_bool()) {
        navigate(state, state.current_address, false);
        append_log(state, "Comment updated at " + address_text(state.current_address));
    } else append_log(state, "Comment update failed: " + json_string(result, "error"));
}

void action_toggle_bookmark(UiState& state) {
    if (!state.has_image || !state.current_address) return;
    bool exists = false;
    for (const auto& bookmark : state.bookmarks) {
        if (json_string(bookmark, "address") == address_text(state.current_address)) { exists = true; break; }
    }
    Json arguments = Json::object();
    arguments["address"] = address_text(state.current_address);
    arguments["enabled"] = !exists;
    arguments["comment"] = std::string(state.bookmark_edit.data());
    const auto result = state.analyzer.set_bookmark(arguments);
    if (result.find("ok") && result.find("ok")->as_bool()) {
        refresh_lists(state);
        append_log(state, exists ? "Bookmark removed" : "Bookmark added");
    } else append_log(state, "Bookmark update failed: " + json_string(result, "error"));
}

void action_ai_help(UiState& state) {
    state.properties = Json::object();
    state.properties["AI / MCP"] =
        "Register paper_ai.exe as a local stdio server. Recommended calls: open_binary, module_info, "
        "list_functions, list_names, list_strings, disassemble, xrefs_to, xrefs_from, cfg, call_graph, "
        "set_name, set_comment, set_bookmark, save_database, analysis_stats.";
    state.side_selection_request = 1;
}

void setup_fonts(float dpi_scale) {
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig config;
    config.OversampleH = 2;
    config.OversampleV = 1;

    // These fonts are part of a standard Windows installation. Keep a
    // built-in fallback so Paper still starts on a minimal Windows image.
    ImFont* ui_font = io.Fonts->AddFontFromFileTTF(
        "C:\\Windows\\Fonts\\segoeui.ttf", 16.0f * dpi_scale, &config,
        io.Fonts->GetGlyphRangesDefault());
    g_code_font = io.Fonts->AddFontFromFileTTF(
        "C:\\Windows\\Fonts\\consola.ttf", 15.0f * dpi_scale, &config,
        io.Fonts->GetGlyphRangesDefault());
    if (!ui_font) ui_font = io.Fonts->AddFontDefault();
    if (!g_code_font) g_code_font = ui_font;
    io.FontDefault = ui_font;
}

void setup_style(float dpi_scale) {
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 5.0f;
    style.ChildRounding = 4.0f;
    style.FrameRounding = 3.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 5.0f;
    style.GrabRounding = 3.0f;
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.ItemSpacing = ImVec2(8.0f, 7.0f);
    style.FramePadding = ImVec2(7.0f, 5.0f);
    style.ScrollbarSize = 16.0f;
    style.ScaleAllSizes(dpi_scale);
    auto& colors = style.Colors;
    colors[ImGuiCol_WindowBg] = ImVec4(0.055f, 0.065f, 0.085f, 1.0f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.045f, 0.055f, 0.072f, 1.0f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.075f, 0.085f, 0.110f, 0.98f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.105f, 0.125f, 0.165f, 1.0f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.145f, 0.190f, 0.255f, 1.0f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.175f, 0.235f, 0.315f, 1.0f);
    colors[ImGuiCol_Button] = ImVec4(0.105f, 0.145f, 0.205f, 1.0f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.160f, 0.255f, 0.380f, 1.0f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.200f, 0.340f, 0.500f, 1.0f);
    colors[ImGuiCol_Header] = ImVec4(0.110f, 0.190f, 0.300f, 1.0f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.150f, 0.280f, 0.420f, 1.0f);
    colors[ImGuiCol_HeaderActive] = ImVec4(0.180f, 0.340f, 0.500f, 1.0f);
    colors[ImGuiCol_Tab] = ImVec4(0.075f, 0.110f, 0.165f, 1.0f);
    colors[ImGuiCol_TabHovered] = ImVec4(0.145f, 0.275f, 0.430f, 1.0f);
    colors[ImGuiCol_TabActive] = ImVec4(0.110f, 0.210f, 0.340f, 1.0f);
    colors[ImGuiCol_DockingPreview] = ImVec4(0.180f, 0.480f, 0.820f, 0.55f);
}

ImGuiID paper_dockspace_id() {
    // Do not derive the ID from the current window: draw_ui() and the layout
    // builder run at different points in the frame and may have different ID
    // stacks. A global hash keeps the DockSpace and DockBuilder on the same node.
    return ImHashStr("PaperDockSpace");
}

ImVec2 paper_dockspace_pos(const ImGuiViewport* viewport) {
    return ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + kToolbarHeight);
}

ImVec2 paper_dockspace_size(const ImGuiViewport* viewport) {
    return ImVec2(viewport->WorkSize.x, std::max(1.0f, viewport->WorkSize.y - kToolbarHeight));
}

void build_default_layout() {
    const ImGuiID dockspace = paper_dockspace_id();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const ImVec2 dock_pos = paper_dockspace_pos(viewport);
    const ImVec2 dock_size = paper_dockspace_size(viewport);
    ImGui::DockBuilderRemoveNode(dockspace);
    ImGui::DockBuilderAddNode(dockspace, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodePos(dockspace, dock_pos);
    ImGui::DockBuilderSetNodeSize(dockspace, dock_size);
    ImGuiID left = 0;
    ImGuiID right = 0;
    ImGuiID bottom = 0;
    ImGuiID center = dockspace;
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.20f, &left, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.27f, &right, &center);
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.22f, &bottom, &center);
    ImGui::DockBuilderDockWindow("Functions", left);
    ImGui::DockBuilderDockWindow("Xrefs / Properties", right);
    ImGui::DockBuilderDockWindow("IDA Lists", right);
    ImGui::DockBuilderDockWindow("Output", bottom);
    ImGui::DockBuilderDockWindow("IDA View-A", center);
    ImGui::DockBuilderFinish(dockspace);
}

void draw_menu(UiState& state) {
    if (!ImGui::BeginMainMenuBar()) return;
    if (ImGui::BeginMenu("File")) {
        if (ImGui::MenuItem("Open PE...", "Ctrl+O")) open_binary(state, choose_pe_file());
        if (ImGui::MenuItem("Save analysis database", "Ctrl+S", false, state.has_image)) action_save_database(state);
        if (ImGui::MenuItem("Reload analysis database", nullptr, false, state.has_image)) action_load_database(state);
        if (ImGui::MenuItem("Exit")) PostQuitMessage(0);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Navigate")) {
        if (ImGui::MenuItem("Back", "Alt+Left", false, !state.history.empty() && state.history_index > 0)) go_back(state);
        if (ImGui::MenuItem("Forward", "Alt+Right", false, !state.history.empty() && state.history_index + 1 < state.history.size())) go_forward(state);
        ImGui::Separator();
        if (ImGui::MenuItem("Entry point", "Home") && state.has_image) {
            const auto info = state.analyzer.module_info();
            if (const auto entry = parse_address(json_string(info, "entry_point"))) navigate(state, *entry);
        }
        ImGui::SetNextItemWidth(170.0f);
        ImGui::InputText("##goto_menu", state.goto_address.data(), state.goto_address.size(), ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if (ImGui::Button("Go to address")) {
            if (const auto address = parse_address(state.goto_address.data())) navigate(state, *address);
        }
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Analysis")) {
        if (ImGui::MenuItem("Xrefs", "X")) state.side_selection_request = 0;
        if (ImGui::MenuItem("CFG", "Ctrl+Shift+F")) action_cfg(state);
        if (ImGui::MenuItem("Callers", "Ctrl+Shift+U")) action_call_graph(state, "callers");
        if (ImGui::MenuItem("Callees", "Ctrl+Shift+D")) action_call_graph(state, "callees");
        ImGui::Separator();
        if (ImGui::MenuItem("Imports", "Ctrl+I")) action_imports(state);
        if (ImGui::MenuItem("Exports", "Ctrl+E")) action_exports(state);
        if (ImGui::MenuItem("Strings", "Ctrl+Shift+S")) action_lists(state, 0);
        if (ImGui::MenuItem("Names", "Shift+F4")) action_lists(state, 1);
        if (ImGui::MenuItem("Bookmarks", "Ctrl+B")) action_lists(state, 5);
        if (ImGui::MenuItem("AI / MCP help", "F1")) action_ai_help(state);
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
        ImGui::MenuItem("Functions", nullptr, &state.show_functions);
        ImGui::MenuItem("Xrefs / Properties", nullptr, &state.show_side);
        ImGui::MenuItem("IDA Lists", nullptr, &state.show_lists);
        ImGui::MenuItem("Output", nullptr, &state.show_output);
        ImGui::EndMenu();
    }
    ImGui::SameLine(ImGui::GetWindowWidth() - 300.0f);
    ImGui::TextColored(ImVec4(0.45f, 0.75f, 1.0f, 1.0f), "PAPER");
    ImGui::SameLine();
    ImGui::TextDisabled("static analysis");
    ImGui::EndMainMenuBar();
}

void handle_shortcuts(UiState& state) {
    const ImGuiIO& io = ImGui::GetIO();
    if (io.WantTextInput) return;
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O)) open_binary(state, choose_pe_file());
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) go_back(state);
    if (io.KeyAlt && ImGui::IsKeyPressed(ImGuiKey_RightArrow)) go_forward(state);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G)) state.focus_goto = true;
    if (ImGui::IsKeyPressed(ImGuiKey_Home) && state.has_image) {
        const auto info = state.analyzer.module_info();
        if (const auto entry = parse_address(json_string(info, "entry_point"))) navigate(state, *entry);
    }
    if (ImGui::IsKeyPressed(ImGuiKey_X)) state.side_selection_request = 0;
    if (io.KeyCtrl && io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F)) action_cfg(state);
    if (io.KeyCtrl && io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_U)) action_call_graph(state, "callers");
    if (io.KeyCtrl && io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_D)) action_call_graph(state, "callees");
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_I)) action_imports(state);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_E)) action_exports(state);
    if (io.KeyCtrl && !io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_S)) action_save_database(state);
    if (io.KeyCtrl && io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_S)) action_lists(state, 0);
    if (io.KeyShift && ImGui::IsKeyPressed(ImGuiKey_F4)) action_lists(state, 1);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_B)) action_toggle_bookmark(state);
    if (ImGui::IsKeyPressed(ImGuiKey_F1)) action_ai_help(state);
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_H)) state.center_selection_request = 1;
}

void draw_toolbar(UiState& state) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, kToolbarHeight));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags toolbar_flags = ImGuiWindowFlags_NoTitleBar |
                                                ImGuiWindowFlags_NoCollapse |
                                                ImGuiWindowFlags_NoResize |
                                                ImGuiWindowFlags_NoMove |
                                                ImGuiWindowFlags_NoDocking |
                                                ImGuiWindowFlags_NoSavedSettings |
                                                ImGuiWindowFlags_NoScrollbar |
                                                ImGuiWindowFlags_NoScrollWithMouse;
    if (!ImGui::Begin("Toolbar", nullptr, toolbar_flags)) {
        ImGui::End();
        return;
    }
    if (ImGui::Button("Open")) open_binary(state, choose_pe_file());
    ImGui::SameLine();
    if (ImGui::Button("<")) go_back(state);
    ImGui::SameLine();
    if (ImGui::Button(">")) go_forward(state);
    ImGui::SameLine();
    if (ImGui::Button("Entry")) {
        const auto info = state.analyzer.module_info();
        if (const auto entry = parse_address(json_string(info, "entry_point"))) navigate(state, *entry);
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(155.0f);
    if (state.focus_goto) {
        ImGui::SetKeyboardFocusHere();
        state.focus_goto = false;
    }
    ImGui::InputTextWithHint("##goto_toolbar", "0x address", state.goto_address.data(), state.goto_address.size(), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Jump")) {
        if (const auto address = parse_address(state.goto_address.data())) navigate(state, *address);
    }
    ImGui::SameLine();
    if (ImGui::Button("Xrefs")) state.side_selection_request = 0;
    ImGui::SameLine();
    if (ImGui::Button("CFG")) action_cfg(state);
    ImGui::SameLine();
    if (ImGui::Button("Callers")) action_call_graph(state, "callers");
    ImGui::SameLine();
    if (ImGui::Button("Callees")) action_call_graph(state, "callees");
    ImGui::SameLine();
    if (ImGui::Button("Imports")) action_imports(state);
    ImGui::SameLine();
    if (ImGui::Button("Exports")) action_exports(state);
    ImGui::SameLine();
    if (ImGui::Button("Lists")) action_lists(state);
    ImGui::SameLine();
    if (ImGui::Button("Mark")) action_toggle_bookmark(state);
    ImGui::SameLine();
    if (ImGui::Button("Hex")) state.center_selection_request = 1;
    ImGui::SameLine();
    if (ImGui::Button("AI")) action_ai_help(state);
    ImGui::End();
}

void draw_functions(UiState& state) {
    if (!state.show_functions) return;
    ImGui::Begin("Functions", &state.show_functions);
    ImGui::TextDisabled("%zu indexed functions", state.functions.size());
    if (ImGui::InputTextWithHint("##function_filter", "Filter functions...", state.function_filter.data(), state.function_filter.size()))
        refresh_functions(state);
    ImGui::Separator();
    ImGui::PushFont(g_code_font);
    ImGui::BeginChild("function_list", ImVec2(0, 0), false);
    for (std::size_t index = 0; index < state.functions.size(); ++index) {
        const auto address = json_string(state.functions[index], "address");
        const auto name = json_string(state.functions[index], "name");
        const std::string label = address + "  " + name;
        if (ImGui::Selectable(label.c_str(), static_cast<int>(index) == state.selected_function)) {
            state.selected_function = static_cast<int>(index);
            if (const auto parsed = parse_address(address)) navigate(state, *parsed);
        }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", name.c_str(), address.c_str());
    }
    ImGui::EndChild();
    ImGui::PopFont();
    ImGui::End();
}

ImVec4 instruction_color(std::string_view kind) {
    if (kind == "call" || kind == "indirect_call") return ImVec4(1.0f, 0.65f, 0.35f, 1.0f);
    if (kind == "jump" || kind == "conditional_jump" || kind == "indirect_jump") return ImVec4(0.75f, 0.60f, 1.0f, 1.0f);
    if (kind == "return") return ImVec4(1.0f, 0.45f, 0.45f, 1.0f);
    if (kind == "data") return ImVec4(0.55f, 0.65f, 0.72f, 1.0f);
    return ImVec4(0.55f, 0.85f, 0.95f, 1.0f);
}

void draw_cfg_graph(UiState& state) {
    const auto* blocks = state.cfg.find("blocks");
    if (!blocks || !blocks->is_array() || blocks->array_items().empty()) {
        ImGui::TextDisabled("Run CFG on a function to build the graph.");
        return;
    }
    ImGui::BeginChild("cfg_canvas", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    const float node_width = 250.0f;
    const float node_height = 66.0f;
    const float gap_x = 54.0f;
    const float gap_y = 42.0f;
    const std::size_t columns = available.x > 0.0f ?
        std::max<std::size_t>(1, static_cast<std::size_t>(available.x / (node_width + gap_x))) : 1;
    struct NodePosition { Address address = 0; ImVec2 position{}; };
    std::vector<NodePosition> positions;
    positions.reserve(blocks->array_items().size());
    for (std::size_t index = 0; index < blocks->array_items().size(); ++index) {
        const auto& block = blocks->array_items()[index];
        const auto address = parse_address(json_string(block, "start")).value_or(0);
        const auto column = index % columns;
        const auto row = index / columns;
        positions.push_back({address, ImVec2(origin.x + static_cast<float>(column) * (node_width + gap_x),
                                             origin.y + static_cast<float>(row) * (node_height + gap_y))});
    }
    auto position_for = [&](Address address) -> const NodePosition* {
        for (const auto& position : positions) if (position.address == address) return &position;
        return nullptr;
    };
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    for (std::size_t index = 0; index < blocks->array_items().size(); ++index) {
        const auto& block = blocks->array_items()[index];
        const auto* source = &positions[index];
        const auto* successors = block.find("successors");
        if (!successors || !successors->is_array()) continue;
        for (const auto& successor : successors->array_items()) {
            const auto* target = position_for(parse_address(successor.as_string()).value_or(0));
            if (!target) continue;
            const ImVec2 from(source->position.x + node_width * 0.5f, source->position.y + node_height);
            const ImVec2 to(target->position.x + node_width * 0.5f, target->position.y);
            draw_list->AddLine(from, to, IM_COL32(100, 170, 230, 210), 2.0f);
            draw_list->AddTriangleFilled(ImVec2(to.x - 5.0f, to.y - 7.0f), ImVec2(to.x + 5.0f, to.y - 7.0f), to, IM_COL32(100, 170, 230, 230));
        }
    }
    for (std::size_t index = 0; index < positions.size(); ++index) {
        const auto& position = positions[index];
        const auto& block = blocks->array_items()[index];
        const ImU32 fill = position.address == state.current_address ? IM_COL32(35, 100, 150, 240) : IM_COL32(27, 42, 63, 245);
        draw_list->AddRectFilled(position.position, ImVec2(position.position.x + node_width, position.position.y + node_height), fill, 5.0f);
        draw_list->AddRect(position.position, ImVec2(position.position.x + node_width, position.position.y + node_height), IM_COL32(100, 180, 235, 220), 5.0f, 0, 1.5f);
        const auto label = json_string(block, "start") + " - " + json_string(block, "end");
        draw_list->AddText(g_code_font, 14.0f, ImVec2(position.position.x + 10.0f, position.position.y + 10.0f), IM_COL32(220, 238, 250, 255), label.c_str());
        const auto* successors = block.find("successors");
        const auto successor_count = successors && successors->is_array() ? successors->array_items().size() : 0;
        const auto summary = "successors: " + std::to_string(successor_count);
        draw_list->AddText(g_code_font, 13.0f, ImVec2(position.position.x + 10.0f, position.position.y + 36.0f), IM_COL32(155, 180, 200, 255), summary.c_str());
        ImGui::SetCursorScreenPos(position.position);
        ImGui::PushID(static_cast<int>(index));
        if (ImGui::InvisibleButton("cfg_node", ImVec2(node_width, node_height))) navigate(state, position.address);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Jump to %s", json_string(block, "start").c_str());
        ImGui::PopID();
    }
    const auto rows = (positions.size() + columns - 1) / columns;
    ImGui::Dummy(ImVec2(static_cast<float>(columns) * (node_width + gap_x), static_cast<float>(rows) * (node_height + gap_y)));
    ImGui::EndChild();
}

void draw_disassembly(UiState& state) {
    ImGui::Begin("IDA View-A");
    ImGui::PushFont(g_code_font);
    if (!state.has_image) {
        ImGui::TextColored(ImVec4(0.45f, 0.75f, 1.0f, 1.0f), "Open a PE image to begin analysis");
        ImGui::TextDisabled("Ctrl+O   Open   |   X   Xrefs   |   Ctrl+Shift+F   CFG   |   F1   AI/MCP");
        ImGui::PopFont();
        ImGui::End();
        return;
    }
    if (ImGui::BeginTabBar("center_views")) {
        if (ImGui::BeginTabItem("IDA View-A", nullptr, state.center_selection_request == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            if (ImGui::BeginTable("disassembly", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                             ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit,
                                  ImVec2(0, 0))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 115.0f);
                ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 185.0f);
                ImGui::TableSetupColumn("Mnemonic", ImGuiTableColumnFlags_WidthFixed, 105.0f);
                ImGui::TableSetupColumn("Operands", ImGuiTableColumnFlags_WidthStretch, 220.0f);
                ImGui::TableSetupColumn("Comment", ImGuiTableColumnFlags_WidthStretch, 180.0f);
                ImGui::TableHeadersRow();
                for (const auto& instruction : state.instructions) {
                    const auto address = json_string(instruction, "address");
                    const auto kind = json_kind(instruction);
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    if (ImGui::Selectable(address.c_str(), address == address_text(state.current_address), ImGuiSelectableFlags_SpanAllColumns)) {
                        if (const auto parsed = parse_address(address)) {
                            state.current_address = *parsed;
                            refresh_xrefs(state, *parsed);
                        }
                    }
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%s", json_string(instruction, "bytes").c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextColored(instruction_color(kind), "%s", json_string(instruction, "mnemonic").c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(json_string(instruction, "operands").c_str());
                    ImGui::TableNextColumn();
                    const auto target = json_string(instruction, "target");
                    const auto name = json_string(instruction, "name");
                    const auto comment = json_string(instruction, "comment");
                    if (!name.empty()) ImGui::TextColored(ImVec4(0.45f, 0.90f, 0.55f, 1.0f), "%s", name.c_str());
                    else if (!target.empty()) ImGui::TextColored(ImVec4(0.45f, 0.75f, 0.95f, 1.0f), "-> %s", target.c_str());
                    else if (!comment.empty()) ImGui::TextDisabled("; %s", comment.c_str());
                    else if (kind == "return") ImGui::TextDisabled("function return");
                    if (!comment.empty() && !name.empty()) ImGui::SameLine();
                    if (!comment.empty() && !name.empty()) ImGui::TextDisabled("; %s", comment.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Hex View-1", nullptr, state.center_selection_request == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::BeginChild("hex_view", ImVec2(0, 0), false);
            ImGui::TextUnformatted(state.hex_text.c_str());
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Info", nullptr, state.center_selection_request == 2 ? ImGuiTabItemFlags_SetSelected : 0)) {
            const auto info = state.analyzer.module_info();
            ImGui::TextUnformatted(info.dump().c_str());
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Graph View", nullptr, state.center_selection_request == 3 ? ImGuiTabItemFlags_SetSelected : 0)) {
            draw_cfg_graph(state);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    state.center_selection_request = -1;
    ImGui::PopFont();
    ImGui::End();
}

void draw_side(UiState& state) {
    if (!state.show_side) return;
    ImGui::Begin("Xrefs / Properties", &state.show_side);
    ImGui::PushFont(g_code_font);
    if (ImGui::BeginTabBar("side_views")) {
        if (ImGui::BeginTabItem("Xrefs", nullptr, state.side_selection_request == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            for (const auto& reference : state.incoming_xrefs) {
                const auto from = json_string(reference, "from");
                const auto symbol = json_string(reference, "symbol");
                const auto label = "<- " + from + "  " + json_string(reference, "kind") + (symbol.empty() ? "" : "  " + symbol);
                if (ImGui::Selectable(label.c_str())) {
                    if (const auto address = parse_address(from)) navigate(state, *address);
                }
            }
            for (const auto& reference : state.outgoing_xrefs) {
                const auto to = json_string(reference, "to");
                const auto symbol = json_string(reference, "symbol");
                const auto label = "-> " + to + "  " + json_string(reference, "kind") + (symbol.empty() ? "" : "  " + symbol);
                if (ImGui::Selectable(label.c_str())) {
                    if (const auto address = parse_address(to)) navigate(state, *address);
                }
            }
            if (state.incoming_xrefs.empty() && state.outgoing_xrefs.empty()) ImGui::TextDisabled("No indexed xrefs at this address.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Properties", nullptr, state.side_selection_request == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::BeginChild("properties_view", ImVec2(0, 0), false);
            if (state.has_image && state.current_address) {
                ImGui::TextColored(ImVec4(0.45f, 0.75f, 1.0f, 1.0f), "%s", address_text(state.current_address).c_str());
                ImGui::SetNextItemWidth(-92.0f);
                ImGui::InputText("##name_edit", state.name_edit.data(), state.name_edit.size());
                ImGui::SameLine();
                if (ImGui::Button("Rename")) action_set_name(state);
                ImGui::SetNextItemWidth(-92.0f);
                ImGui::InputText("##comment_edit", state.comment_edit.data(), state.comment_edit.size());
                ImGui::SameLine();
                if (ImGui::Button("Comment")) action_set_comment(state);
                ImGui::SetNextItemWidth(-92.0f);
                ImGui::InputText("##bookmark_edit", state.bookmark_edit.data(), state.bookmark_edit.size());
                ImGui::SameLine();
                if (ImGui::Button("Bookmark")) action_toggle_bookmark(state);
                ImGui::Separator();
            }
            ImGui::TextUnformatted(state.properties.dump().c_str());
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    state.side_selection_request = -1;
    ImGui::PopFont();
    ImGui::End();
}

void draw_lists(UiState& state) {
    if (!state.show_lists) return;
    ImGui::Begin("IDA Lists", &state.show_lists);
    ImGui::TextDisabled("Strings / Names / Imports / Exports / Segments / Bookmarks");
    if (ImGui::InputTextWithHint("##list_filter", "Filter current list...", state.list_filter.data(), state.list_filter.size())) refresh_lists(state);
    ImGui::Separator();
    ImGui::PushFont(g_code_font);
    if (ImGui::BeginTabBar("ida_lists_tabs")) {
        if (ImGui::BeginTabItem("Strings", nullptr, state.list_selection_request == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextDisabled("%zu literals", state.strings.size());
            ImGui::BeginChild("strings_list", ImVec2(0, 0), false);
            for (std::size_t index = 0; index < state.strings.size(); ++index) {
                const auto address = json_string(state.strings[index], "address");
                const auto value = json_string(state.strings[index], "value");
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable((address + "  " + value).c_str())) {
                    if (const auto parsed = parse_address(address)) navigate(state, *parsed);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Names", nullptr, state.list_selection_request == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextDisabled("%zu names", state.names.size());
            ImGui::BeginChild("names_list", ImVec2(0, 0), false);
            for (std::size_t index = 0; index < state.names.size(); ++index) {
                const auto address = json_string(state.names[index], "address");
                const auto name = json_string(state.names[index], "name");
                const auto kind = json_string(state.names[index], "kind");
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable((address + "  " + name + "  [" + kind + "]").c_str())) {
                    if (const auto parsed = parse_address(address)) navigate(state, *parsed);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports", nullptr, state.list_selection_request == 2 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextDisabled("%zu imports", state.imports.size());
            ImGui::BeginChild("imports_list", ImVec2(0, 0), false);
            for (std::size_t index = 0; index < state.imports.size(); ++index) {
                const auto thunk = json_string(state.imports[index], "thunk");
                const auto library = json_string(state.imports[index], "library");
                const auto name = json_string(state.imports[index], "name");
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable((thunk + "  " + library + "!" + name).c_str())) {
                    if (const auto parsed = parse_address(thunk)) navigate(state, *parsed);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Exports", nullptr, state.list_selection_request == 3 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextDisabled("%zu exports", state.exports.size());
            ImGui::BeginChild("exports_list", ImVec2(0, 0), false);
            for (std::size_t index = 0; index < state.exports.size(); ++index) {
                const auto address = json_string(state.exports[index], "address");
                const auto name = json_string(state.exports[index], "name");
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable((address + "  " + name).c_str())) {
                    if (const auto parsed = parse_address(address)) navigate(state, *parsed);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Segments", nullptr, state.list_selection_request == 4 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextDisabled("%zu segments", state.sections.size());
            ImGui::BeginChild("segments_list", ImVec2(0, 0), false);
            for (std::size_t index = 0; index < state.sections.size(); ++index) {
                const auto start = json_string(state.sections[index], "start");
                const auto end = json_string(state.sections[index], "end");
                const auto name = json_string(state.sections[index], "name");
                const auto perms = std::string(json_bool(state.sections[index], "executable") ? "X" : "-") +
                                   (json_bool(state.sections[index], "readable") ? "R" : "-") +
                                   (json_bool(state.sections[index], "writable") ? "W" : "-");
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable((name + "  " + start + " - " + end + "  [" + perms + "]").c_str())) {
                    if (const auto parsed = parse_address(start)) navigate(state, *parsed);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Bookmarks", nullptr, state.list_selection_request == 5 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextDisabled("%zu bookmarks", state.bookmarks.size());
            ImGui::BeginChild("bookmarks_list", ImVec2(0, 0), false);
            for (std::size_t index = 0; index < state.bookmarks.size(); ++index) {
                const auto address = json_string(state.bookmarks[index], "address");
                const auto comment = json_string(state.bookmarks[index], "comment");
                ImGui::PushID(static_cast<int>(index));
                if (ImGui::Selectable((address + (comment.empty() ? "" : "  " + comment)).c_str())) {
                    if (const auto parsed = parse_address(address)) navigate(state, *parsed);
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    state.list_selection_request = -1;
    ImGui::PopFont();
    ImGui::End();
}

void draw_output(UiState& state) {
    if (!state.show_output) return;
    ImGui::Begin("Output", &state.show_output);
    ImGui::TextColored(ImVec4(0.45f, 0.75f, 1.0f, 1.0f), "%s", state.status.c_str());
    ImGui::Separator();
    ImGui::BeginChild("output_text", ImVec2(0, 0), false);
    ImGui::TextUnformatted(state.output.c_str());
    ImGui::EndChild();
    ImGui::End();
}

void draw_ui(UiState& state) {
    draw_menu(state);
    handle_shortcuts(state);
    draw_toolbar(state);
    const ImGuiID dockspace = paper_dockspace_id();
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(paper_dockspace_pos(viewport));
    ImGui::SetNextWindowSize(paper_dockspace_size(viewport));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags host_flags = ImGuiWindowFlags_NoTitleBar |
                                             ImGuiWindowFlags_NoCollapse |
                                             ImGuiWindowFlags_NoResize |
                                             ImGuiWindowFlags_NoMove |
                                             ImGuiWindowFlags_NoBringToFrontOnFocus |
                                             ImGuiWindowFlags_NoNavFocus |
                                             ImGuiWindowFlags_NoDocking |
                                             ImGuiWindowFlags_NoSavedSettings |
                                             ImGuiWindowFlags_NoBackground;
    ImGui::Begin("##PaperDockHost", nullptr, host_flags);
    ImGui::DockSpace(dockspace, ImVec2(0, 0), ImGuiDockNodeFlags_PassthruCentralNode);
    ImGui::End();
    static bool layout_initialized = false;
    if (!layout_initialized) {
        // Always apply the first-run layout once. This also repairs an older
        // or partially written ImGui .ini without requiring manual deletion.
        build_default_layout();
        layout_initialized = true;
    }
    draw_functions(state);
    draw_disassembly(state);
    draw_side(state);
    draw_lists(state);
    draw_output(state);
}

bool create_device_d3d(HWND window) {
    DXGI_SWAP_CHAIN_DESC swap_chain_desc{};
    swap_chain_desc.BufferCount = 2;
    swap_chain_desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swap_chain_desc.BufferDesc.RefreshRate.Numerator = 60;
    swap_chain_desc.BufferDesc.RefreshRate.Denominator = 1;
    swap_chain_desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    swap_chain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_chain_desc.OutputWindow = window;
    swap_chain_desc.SampleDesc.Count = 1;
    swap_chain_desc.Windowed = TRUE;
    swap_chain_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL feature_level{};
    const HRESULT result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                                          levels, ARRAYSIZE(levels), D3D11_SDK_VERSION,
                                                          &swap_chain_desc, &g_swap_chain, &g_device,
                                                          &feature_level, &g_device_context);
    return SUCCEEDED(result);
}

void cleanup_render_target() {
    if (g_main_render_target) {
        g_main_render_target->Release();
        g_main_render_target = nullptr;
    }
}

void create_render_target() {
    ID3D11Texture2D* back_buffer = nullptr;
    if (g_swap_chain && SUCCEEDED(g_swap_chain->GetBuffer(0, IID_PPV_ARGS(&back_buffer)))) {
        g_device->CreateRenderTargetView(back_buffer, nullptr, &g_main_render_target);
        back_buffer->Release();
    }
}

void cleanup_device_d3d() {
    cleanup_render_target();
    if (g_swap_chain) { g_swap_chain->Release(); g_swap_chain = nullptr; }
    if (g_device_context) { g_device_context->Release(); g_device_context = nullptr; }
    if (g_device) { g_device->Release(); g_device = nullptr; }
}

LRESULT WINAPI wnd_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    if (ImGui_ImplWin32_WndProcHandler(window, message, w_param, l_param)) return true;
    switch (message) {
    case WM_SIZE:
        if (g_device != nullptr && w_param != SIZE_MINIMIZED) {
            g_resize_width = LOWORD(l_param);
            g_resize_height = HIWORD(l_param);
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((w_param & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    ImGui_ImplWin32_EnableDpiAwareness();
    WNDCLASSEXW window_class{sizeof(WNDCLASSEXW), CS_CLASSDC, wnd_proc, 0L, 0L, instance, nullptr, nullptr, nullptr, nullptr, L"PaperImGui", nullptr};
    RegisterClassExW(&window_class);
    HWND window = CreateWindowW(window_class.lpszClassName, L"Paper — IDA-style Static Analysis",
                                WS_OVERLAPPEDWINDOW, 80, 60, 1680, 1000, nullptr, nullptr, instance, nullptr);
    if (!window || !create_device_d3d(window)) {
        cleanup_device_d3d();
        UnregisterClassW(window_class.lpszClassName, instance);
        return 1;
    }
    create_render_target();
    ShowWindow(window, show_command);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    io.IniFilename = "paper_imgui_v3.ini";
    const float dpi_scale = std::clamp(ImGui_ImplWin32_GetDpiScaleForHwnd(window), 1.0f, 2.0f);
    setup_fonts(dpi_scale);
    setup_style(dpi_scale);
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(g_device, g_device_context);

    UiState state;
    int argument_count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    if (arguments && argument_count > 1) open_binary(state, wide_to_utf8(arguments[1]));
    if (arguments) LocalFree(arguments);

    MSG message{};
    while (message.message != WM_QUIT) {
        while (PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if (message.message == WM_QUIT) break;
        }
        if (message.message == WM_QUIT) break;
        if (g_resize_width != 0 && g_resize_height != 0) {
            cleanup_render_target();
            g_swap_chain->ResizeBuffers(0, g_resize_width, g_resize_height, DXGI_FORMAT_UNKNOWN, 0);
            g_resize_width = g_resize_height = 0;
            create_render_target();
        }
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        draw_ui(state);
        ImGui::Render();
        const float clear_color[4] = {0.035f, 0.045f, 0.060f, 1.0f};
        g_device_context->OMSetRenderTargets(1, &g_main_render_target, nullptr);
        g_device_context->ClearRenderTargetView(g_main_render_target, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }
        g_swap_chain->Present(1, 0);
    }

    // Keep IDA's familiar session behavior: annotations are restored on the
    // next open without requiring a separate export step. Ctrl+S remains
    // available when the user wants an explicit checkpoint.
    if (state.has_image) state.analyzer.save_database(Json::object());
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device_d3d();
    DestroyWindow(window);
    UnregisterClassW(window_class.lpszClassName, instance);
    return 0;
}
