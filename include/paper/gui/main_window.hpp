#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "paper/core/analyzer.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace paper {

class MainWindow final {
public:
    MainWindow();
    ~MainWindow();

    bool create(HINSTANCE instance);
    void show(int command);
    int run();
    void open_path(const std::wstring& path);

private:
    static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param);
    LRESULT message_proc(UINT message, WPARAM w_param, LPARAM l_param);

    void create_menu();
    void create_controls();
    void create_accelerators();
    void layout_controls();
    void select_main_tab(int index);
    void select_side_tab(int index);

    void open_file();
    void refresh_functions();
    void show_selected_function();
    void filter_functions();
    void jump_to_address();
    void go_to_entry();
    void go_back();
    void go_forward();
    void show_xrefs();
    void show_cfg();
    void show_callers();
    void show_callees();
    void show_imports();
    void show_exports();
    void show_hex_view();
    void show_ai_help();
    void jump_to_xref();
    void show_selected_disassembly_row(int row);

    void navigate_to(Address address, bool add_history = true);
    void populate_disassembly(Address address);
    void populate_hex(Address address);
    void populate_xrefs(Address address);
    void populate_properties(const Json& value);
    void set_log(const std::wstring& message);
    void set_status(const std::wstring& message);

    static std::wstring utf8_to_wide(std::string_view text);
    static std::string wide_to_utf8(std::wstring_view text);
    static std::wstring json_string(const Json& item, std::string_view key);
    static std::wstring address_text(Address address);
    static std::optional<Address> parse_address(std::wstring_view text);
    static std::wstring instruction_kind(const Json& item);
    static HWND create_control(DWORD ex_style, LPCWSTR class_name, LPCWSTR title, DWORD style,
                               int x, int y, int width, int height, HWND parent, int id,
                               HINSTANCE instance);
    static void set_control_font(HWND control, HFONT font);

    HINSTANCE instance_ = nullptr;
    HWND window_ = nullptr;
    HACCEL accelerators_ = nullptr;

    HWND open_button_ = nullptr;
    HWND back_button_ = nullptr;
    HWND forward_button_ = nullptr;
    HWND xrefs_button_ = nullptr;
    HWND cfg_button_ = nullptr;
    HWND callers_button_ = nullptr;
    HWND callees_button_ = nullptr;
    HWND imports_button_ = nullptr;
    HWND exports_button_ = nullptr;
    HWND hex_button_ = nullptr;
    HWND ai_button_ = nullptr;
    HWND address_label_ = nullptr;
    HWND address_edit_ = nullptr;
    HWND go_button_ = nullptr;

    HWND functions_label_ = nullptr;
    HWND function_filter_ = nullptr;
    HWND functions_ = nullptr;

    HWND main_tabs_ = nullptr;
    HWND disassembly_ = nullptr;
    HWND hex_view_ = nullptr;
    HWND structures_view_ = nullptr;
    HWND enums_view_ = nullptr;
    HWND imports_view_ = nullptr;
    HWND exports_view_ = nullptr;

    HWND side_tabs_ = nullptr;
    HWND xrefs_ = nullptr;
    HWND properties_ = nullptr;
    HWND log_ = nullptr;
    HWND status_ = nullptr;

    Analyzer analyzer_;
    Address current_address_ = 0;
    std::vector<Address> navigation_history_;
    std::size_t navigation_index_ = 0;
    std::vector<Address> xref_targets_;
    std::vector<Address> disassembly_addresses_;
    std::vector<std::wstring> disassembly_kinds_;
    HFONT default_font_ = nullptr;
    HFONT fixed_font_ = nullptr;
};

} // namespace paper
