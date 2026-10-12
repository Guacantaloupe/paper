#define UNICODE
#define _UNICODE
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "paper/gui/main_window.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cwctype>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>

namespace paper {
namespace {

constexpr wchar_t kWindowClass[] = L"PaperNativeMainWindow";

enum : int {
    IDM_OPEN = 1001,
    IDM_EXIT = 1002,
    IDM_BACK = 1003,
    IDM_FORWARD = 1004,
    IDM_GOTO = 1005,
    IDM_ENTRY = 1006,
    IDM_XREFS = 1007,
    IDM_CFG = 1008,
    IDM_CALLERS = 1009,
    IDM_CALLEES = 1010,
    IDM_IMPORTS = 1011,
    IDM_EXPORTS = 1012,
    IDM_HEX = 1013,
    IDM_AI = 1014,

    IDC_FUNCTION_FILTER = 2001,
    IDC_FUNCTIONS = 2002,
    IDC_MAIN_TABS = 2003,
    IDC_DISASSEMBLY = 2004,
    IDC_HEX_VIEW = 2005,
    IDC_STRUCTURES_VIEW = 2006,
    IDC_ENUMS_VIEW = 2007,
    IDC_IMPORTS_VIEW = 2008,
    IDC_EXPORTS_VIEW = 2009,
    IDC_SIDE_TABS = 2010,
    IDC_XREFS = 2011,
    IDC_PROPERTIES = 2012,
    IDC_LOG = 2013,
    IDC_STATUS = 2014,
    IDC_ADDRESS = 2015
};

std::uint64_t number_or(const Json& object, std::string_view key) {
    const auto* value = object.find(key);
    return value ? value->as_u64() : 0;
}

} // namespace

MainWindow::MainWindow() = default;

MainWindow::~MainWindow() {
    if (accelerators_) DestroyAcceleratorTable(accelerators_);
}

bool MainWindow::create(HINSTANCE instance) {
    instance_ = instance;

    INITCOMMONCONTROLSEX controls{};
    controls.dwSize = sizeof(controls);
    controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&controls);

    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.hInstance = instance_;
    window_class.lpfnWndProc = &MainWindow::window_proc;
    window_class.lpszClassName = kWindowClass;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    window_class.hIconSm = window_class.hIcon;
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassExW(&window_class) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;

    window_ = CreateWindowExW(
        WS_EX_APPWINDOW,
        kWindowClass,
        L"Paper - IDA-style Static Analysis",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        CW_USEDEFAULT, CW_USEDEFAULT, 1680, 1000,
        nullptr, nullptr, instance_, this);
    return window_ != nullptr;
}

void MainWindow::show(int command) {
    ShowWindow(window_, command);
    UpdateWindow(window_);
}

int MainWindow::run() {
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!accelerators_ || !TranslateAcceleratorW(window_, accelerators_, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return static_cast<int>(message.wParam);
}

LRESULT CALLBACK MainWindow::window_proc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    MainWindow* self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(l_param);
        self = static_cast<MainWindow*>(create->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->window_ = window;
    }
    return self ? self->message_proc(message, w_param, l_param) : DefWindowProcW(window, message, w_param, l_param);
}

LRESULT MainWindow::message_proc(UINT message, WPARAM w_param, LPARAM l_param) {
    switch (message) {
    case WM_CREATE:
        create_menu();
        create_controls();
        create_accelerators();
        layout_controls();
        return 0;

    case WM_SIZE:
        layout_controls();
        return 0;

    case WM_COMMAND: {
        const int id = LOWORD(w_param);
        const int code = HIWORD(w_param);
        if (id == IDC_FUNCTION_FILTER && code == EN_CHANGE) {
            filter_functions();
            return 0;
        }
        if (id == IDC_FUNCTIONS && code == LBN_SELCHANGE) {
            show_selected_function();
            return 0;
        }
        if (id == IDC_XREFS && code == LBN_DBLCLK) {
            jump_to_xref();
            return 0;
        }
        switch (id) {
        case IDM_OPEN: open_file(); break;
        case IDM_EXIT: DestroyWindow(window_); break;
        case IDM_BACK: go_back(); break;
        case IDM_FORWARD: go_forward(); break;
        case IDM_GOTO: jump_to_address(); break;
        case IDM_ENTRY: go_to_entry(); break;
        case IDM_XREFS: show_xrefs(); break;
        case IDM_CFG: show_cfg(); break;
        case IDM_CALLERS: show_callers(); break;
        case IDM_CALLEES: show_callees(); break;
        case IDM_IMPORTS: show_imports(); break;
        case IDM_EXPORTS: show_exports(); break;
        case IDM_HEX: show_hex_view(); break;
        case IDM_AI: show_ai_help(); break;
        default: break;
        }
        return 0;
    }

    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(l_param);
        if (header->hwndFrom == main_tabs_ && header->code == TCN_SELCHANGE) {
            select_main_tab(TabCtrl_GetCurSel(main_tabs_));
            return 0;
        }
        if (header->hwndFrom == side_tabs_ && header->code == TCN_SELCHANGE) {
            select_side_tab(TabCtrl_GetCurSel(side_tabs_));
            return 0;
        }
        if (header->hwndFrom == disassembly_ && header->code == NM_CLICK) {
            const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(l_param);
            if (activate->iItem >= 0) show_selected_disassembly_row(activate->iItem);
            return 0;
        }
        if (header->hwndFrom == disassembly_ && header->code == NM_CUSTOMDRAW) {
            const auto* draw = reinterpret_cast<const NMLVCUSTOMDRAW*>(l_param);
            if (draw->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (draw->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT)) {
                const auto row = static_cast<std::size_t>(draw->nmcd.dwItemSpec);
                if (row < disassembly_kinds_.size()) {
                    const auto& kind = disassembly_kinds_[row];
                    if (kind == L"call" || kind == L"indirect_call")
                        const_cast<NMLVCUSTOMDRAW*>(draw)->clrText = RGB(138, 59, 18);
                    else if (kind == L"jump" || kind == L"conditional_jump")
                        const_cast<NMLVCUSTOMDRAW*>(draw)->clrText = RGB(107, 63, 149);
                    else if (kind == L"return")
                        const_cast<NMLVCUSTOMDRAW*>(draw)->clrText = RGB(139, 26, 26);
                }
                return CDRF_DODEFAULT;
            }
        }
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }
    return DefWindowProcW(window_, message, w_param, l_param);
}

void MainWindow::create_menu() {
    HMENU root = CreateMenu();
    HMENU file = CreatePopupMenu();
    AppendMenuW(file, MF_STRING, IDM_OPEN, L"Open binary...\tCtrl+O");
    AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(file, MF_STRING, IDM_EXIT, L"Exit");
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"File");

    HMENU navigate = CreatePopupMenu();
    AppendMenuW(navigate, MF_STRING, IDM_BACK, L"Back\tAlt+Left");
    AppendMenuW(navigate, MF_STRING, IDM_FORWARD, L"Forward\tAlt+Right");
    AppendMenuW(navigate, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(navigate, MF_STRING, IDM_GOTO, L"Go to address...\tCtrl+G");
    AppendMenuW(navigate, MF_STRING, IDM_ENTRY, L"Entry point\tHome");
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(navigate), L"Navigate");

    HMENU analysis = CreatePopupMenu();
    AppendMenuW(analysis, MF_STRING, IDM_XREFS, L"Xrefs\tX");
    AppendMenuW(analysis, MF_STRING, IDM_CFG, L"CFG\tCtrl+Shift+F");
    AppendMenuW(analysis, MF_STRING, IDM_CALLERS, L"Callers\tCtrl+Shift+U");
    AppendMenuW(analysis, MF_STRING, IDM_CALLEES, L"Callees\tCtrl+Shift+D");
    AppendMenuW(analysis, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(analysis, MF_STRING, IDM_IMPORTS, L"Imports\tCtrl+I");
    AppendMenuW(analysis, MF_STRING, IDM_EXPORTS, L"Exports\tCtrl+E");
    AppendMenuW(analysis, MF_STRING, IDM_HEX, L"Hex view\tCtrl+H");
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(analysis), L"Analysis");

    HMENU help = CreatePopupMenu();
    AppendMenuW(help, MF_STRING, IDM_AI, L"AI / MCP help\tF1");
    AppendMenuW(root, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"Help");
    SetMenu(window_, root);
}

void MainWindow::create_controls() {
    default_font_ = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    fixed_font_ = static_cast<HFONT>(GetStockObject(ANSI_FIXED_FONT));

    open_button_ = create_control(0, L"BUTTON", L"Open", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_OPEN, instance_);
    back_button_ = create_control(0, L"BUTTON", L"Back", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_BACK, instance_);
    forward_button_ = create_control(0, L"BUTTON", L"Forward", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_FORWARD, instance_);
    xrefs_button_ = create_control(0, L"BUTTON", L"Xrefs", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_XREFS, instance_);
    cfg_button_ = create_control(0, L"BUTTON", L"CFG", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_CFG, instance_);
    callers_button_ = create_control(0, L"BUTTON", L"Callers", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_CALLERS, instance_);
    callees_button_ = create_control(0, L"BUTTON", L"Callees", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_CALLEES, instance_);
    imports_button_ = create_control(0, L"BUTTON", L"Imports", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_IMPORTS, instance_);
    exports_button_ = create_control(0, L"BUTTON", L"Exports", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_EXPORTS, instance_);
    hex_button_ = create_control(0, L"BUTTON", L"Hex", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_HEX, instance_);
    ai_button_ = create_control(0, L"BUTTON", L"AI", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_AI, instance_);
    address_label_ = create_control(0, L"STATIC", L"Address:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0, 0, 0, 0, window_, 0, instance_);
    address_edit_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 0, 0, window_, IDC_ADDRESS, instance_);
    go_button_ = create_control(0, L"BUTTON", L"Go", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, window_, IDM_GOTO, instance_);

    functions_label_ = create_control(0, L"STATIC", L"Functions", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, window_, 0, instance_);
    function_filter_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 0, 0, window_, IDC_FUNCTION_FILTER, instance_);
    SendMessageW(function_filter_, EM_SETCUEBANNER, FALSE, reinterpret_cast<LPARAM>(L"Filter functions...  (Ctrl+F)"));
    functions_ = create_control(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 0, 0, 0, 0, window_, IDC_FUNCTIONS, instance_);

    main_tabs_ = create_control(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 0, 0, window_, IDC_MAIN_TABS, instance_);
    const std::array<LPCWSTR, 6> main_tab_names{L"IDA View-A", L"Hex View-1", L"Structures", L"Enums", L"Imports", L"Exports"};
    for (int index = 0; index < static_cast<int>(main_tab_names.size()); ++index) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<LPWSTR>(main_tab_names[static_cast<std::size_t>(index)]);
        TabCtrl_InsertItem(main_tabs_, index, &item);
    }

    disassembly_ = create_control(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0, 0, 0, window_, IDC_DISASSEMBLY, instance_);
    ListView_SetExtendedListViewStyle(disassembly_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    const std::array<LPCWSTR, 5> columns{L"Address", L"Bytes", L"Mnemonic", L"Operands", L"Comment"};
    const std::array<int, 5> widths{120, 220, 110, 300, 260};
    for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
        LVCOLUMNW column{};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.pszText = const_cast<LPWSTR>(columns[static_cast<std::size_t>(index)]);
        column.cx = widths[static_cast<std::size_t>(index)];
        column.iSubItem = index;
        ListView_InsertColumn(disassembly_, index, &column);
    }

    hex_view_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_HEX_VIEW, instance_);
    structures_view_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"Structures\r\n\r\nType information will be populated by the symbol/type editor.", WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_STRUCTURES_VIEW, instance_);
    enums_view_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"Enums\r\n\r\nEnum definitions will be populated by the symbol/type editor.", WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_ENUMS_VIEW, instance_);
    imports_view_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_IMPORTS_VIEW, instance_);
    exports_view_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_EXPORTS_VIEW, instance_);

    side_tabs_ = create_control(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 0, 0, window_, IDC_SIDE_TABS, instance_);
    const std::array<LPCWSTR, 2> side_tab_names{L"Xrefs", L"Properties"};
    for (int index = 0; index < static_cast<int>(side_tab_names.size()); ++index) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<LPWSTR>(side_tab_names[static_cast<std::size_t>(index)]);
        TabCtrl_InsertItem(side_tabs_, index, &item);
    }
    xrefs_ = create_control(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 0, 0, 0, 0, window_, IDC_XREFS, instance_);
    properties_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_PROPERTIES, instance_);

    log_ = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 0, 0, 0, 0, window_, IDC_LOG, instance_);
    status_ = create_control(0, STATUSCLASSNAMEW, L"Static analysis only - no sample execution", WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, 0, 0, 0, 0, window_, IDC_STATUS, instance_);

    set_control_font(open_button_, default_font_);
    set_control_font(back_button_, default_font_);
    set_control_font(forward_button_, default_font_);
    set_control_font(xrefs_button_, default_font_);
    set_control_font(cfg_button_, default_font_);
    set_control_font(callers_button_, default_font_);
    set_control_font(callees_button_, default_font_);
    set_control_font(imports_button_, default_font_);
    set_control_font(exports_button_, default_font_);
    set_control_font(hex_button_, default_font_);
    set_control_font(ai_button_, default_font_);
    set_control_font(address_label_, default_font_);
    set_control_font(address_edit_, fixed_font_);
    set_control_font(go_button_, default_font_);
    set_control_font(functions_label_, default_font_);
    set_control_font(function_filter_, default_font_);
    set_control_font(functions_, fixed_font_);
    set_control_font(disassembly_, fixed_font_);
    set_control_font(hex_view_, fixed_font_);
    set_control_font(structures_view_, fixed_font_);
    set_control_font(enums_view_, fixed_font_);
    set_control_font(imports_view_, fixed_font_);
    set_control_font(exports_view_, fixed_font_);
    set_control_font(xrefs_, fixed_font_);
    set_control_font(properties_, fixed_font_);
    set_control_font(log_, fixed_font_);

    select_main_tab(0);
    select_side_tab(0);
    EnableWindow(back_button_, FALSE);
    EnableWindow(forward_button_, FALSE);
    set_status(L"Open a PE executable or DLL to begin.");
    set_log(L"Paper native MSVC GUI ready. Static analysis only - no sample execution.");
}

void MainWindow::create_accelerators() {
    const ACCEL table[] = {
        {FVIRTKEY | FCONTROL, L'O', IDM_OPEN},
        {FVIRTKEY | FALT, VK_LEFT, IDM_BACK},
        {FVIRTKEY | FALT, VK_RIGHT, IDM_FORWARD},
        {FVIRTKEY | FCONTROL, L'G', IDM_GOTO},
        {FVIRTKEY, VK_HOME, IDM_ENTRY},
        {FVIRTKEY, L'X', IDM_XREFS},
        {FVIRTKEY | FCONTROL | FSHIFT, L'F', IDM_CFG},
        {FVIRTKEY | FCONTROL | FSHIFT, L'U', IDM_CALLERS},
        {FVIRTKEY | FCONTROL | FSHIFT, L'D', IDM_CALLEES},
        {FVIRTKEY | FCONTROL, L'I', IDM_IMPORTS},
        {FVIRTKEY | FCONTROL, L'E', IDM_EXPORTS},
        {FVIRTKEY | FCONTROL, L'H', IDM_HEX},
        {FVIRTKEY, VK_F1, IDM_AI}
    };
    accelerators_ = CreateAcceleratorTableW(const_cast<ACCEL*>(table), static_cast<int>(std::size(table)));
}

void MainWindow::layout_controls() {
    if (!window_) return;
    RECT client{};
    GetClientRect(window_, &client);
    const int width = client.right - client.left;
    const int height = client.bottom - client.top;
    const int toolbar_height = 36;
    const int status_height = 22;
    const int log_height = std::clamp(height / 5, 110, 180);
    const int content_top = toolbar_height;
    const int content_bottom = height - status_height - log_height;
    const int content_height = std::max(80, content_bottom - content_top);
    const int left_width = std::clamp(width / 5, 270, 340);
    const int right_width = std::clamp(width / 5, 300, 390);
    const int center_x = left_width;
    const int center_width = std::max(220, width - left_width - right_width);
    const int right_x = center_x + center_width;

    const HWND buttons[] = {open_button_, back_button_, forward_button_, xrefs_button_, cfg_button_, callers_button_, callees_button_, imports_button_, exports_button_, hex_button_, ai_button_};
    const int button_widths[] = {62, 62, 72, 58, 48, 68, 68, 70, 70, 52, 48};
    int button_x = 4;
    for (std::size_t index = 0; index < std::size(buttons); ++index) {
        SetWindowPos(buttons[index], nullptr, button_x, 4, button_widths[index], 28, SWP_NOZORDER);
        button_x += button_widths[index] + 3;
    }
    const int address_label_x = std::min(button_x + 6, std::max(button_x + 6, width - 300));
    if (address_label_) SetWindowPos(address_label_, nullptr, address_label_x, 4, 60, 28, SWP_NOZORDER);
    const int address_x = address_label_x + 62;
    const int go_x = width - 48;
    SetWindowPos(address_edit_, nullptr, address_x, 5, std::max(80, go_x - address_x - 4), 26, SWP_NOZORDER);
    SetWindowPos(go_button_, nullptr, go_x, 4, 44, 28, SWP_NOZORDER);

    SetWindowPos(functions_label_, nullptr, 6, content_top + 4, left_width - 12, 20, SWP_NOZORDER);
    SetWindowPos(function_filter_, nullptr, 4, content_top + 26, left_width - 8, 24, SWP_NOZORDER);
    SetWindowPos(functions_, nullptr, 4, content_top + 54, left_width - 8, content_height - 58, SWP_NOZORDER);
    SetWindowPos(main_tabs_, nullptr, center_x + 4, content_top, center_width - 8, content_height, SWP_NOZORDER);
    SetWindowPos(side_tabs_, nullptr, right_x + 4, content_top, right_width - 8, content_height, SWP_NOZORDER);
    SetWindowPos(log_, nullptr, 0, content_bottom, width, log_height, SWP_NOZORDER);
    SetWindowPos(status_, nullptr, 0, height - status_height, width, status_height, SWP_NOZORDER);

    RECT page{};
    GetClientRect(main_tabs_, &page);
    TabCtrl_AdjustRect(main_tabs_, FALSE, &page);
    POINT main_origin{0, 0};
    MapWindowPoints(main_tabs_, window_, &main_origin, 1);
    const HWND main_pages[] = {disassembly_, hex_view_, structures_view_, enums_view_, imports_view_, exports_view_};
    for (HWND page_control : main_pages) {
        SetWindowPos(page_control, nullptr, main_origin.x + page.left, main_origin.y + page.top, page.right - page.left, page.bottom - page.top, SWP_NOZORDER);
    }

    RECT side_page{};
    GetClientRect(side_tabs_, &side_page);
    TabCtrl_AdjustRect(side_tabs_, FALSE, &side_page);
    POINT side_origin{0, 0};
    MapWindowPoints(side_tabs_, window_, &side_origin, 1);
    SetWindowPos(xrefs_, nullptr, side_origin.x + side_page.left, side_origin.y + side_page.top, side_page.right - side_page.left, side_page.bottom - side_page.top, SWP_NOZORDER);
    SetWindowPos(properties_, nullptr, side_origin.x + side_page.left, side_origin.y + side_page.top, side_page.right - side_page.left, side_page.bottom - side_page.top, SWP_NOZORDER);
    SendMessageW(status_, WM_SIZE, 0, 0);
}

void MainWindow::select_main_tab(int index) {
    if (!main_tabs_) return;
    if (index < 0 || index > 5) index = 0;
    TabCtrl_SetCurSel(main_tabs_, index);
    const HWND pages[] = {disassembly_, hex_view_, structures_view_, enums_view_, imports_view_, exports_view_};
    for (int page = 0; page < 6; ++page) ShowWindow(pages[page], page == index ? SW_SHOW : SW_HIDE);
}

void MainWindow::select_side_tab(int index) {
    if (!side_tabs_) return;
    if (index < 0 || index > 1) index = 0;
    TabCtrl_SetCurSel(side_tabs_, index);
    ShowWindow(xrefs_, index == 0 ? SW_SHOW : SW_HIDE);
    ShowWindow(properties_, index == 1 ? SW_SHOW : SW_HIDE);
}

void MainWindow::open_file() {
    std::vector<wchar_t> path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = window_;
    dialog.lpstrFilter = L"Executables (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All files (*.*)\0*.*\0";
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    dialog.lpstrTitle = L"Open PE image";
    if (GetOpenFileNameW(&dialog)) open_path(path.data());
}

void MainWindow::open_path(const std::wstring& path) {
    std::string error;
    if (!analyzer_.open_file(wide_to_utf8(path), error)) {
        const auto message = utf8_to_wide(error);
        set_status(message);
        set_log(message);
        return;
    }

    navigation_history_.clear();
    navigation_index_ = 0;
    current_address_ = 0;
    const auto info = analyzer_.module_info();
    const auto stats = analyzer_.analysis_stats();
    const auto function_count = number_or(stats, "function_count");
    const auto instruction_count = number_or(stats, "instruction_count");
    const auto xref_count = number_or(stats, "xref_count");
    std::wostringstream status;
    status << L"Indexed " << function_count << L" functions, " << instruction_count << L" instructions";
    set_status(status.str());
    populate_properties(info);
    refresh_functions();
    std::wostringstream log;
    log << L"Loaded " << path << L"\r\n" << function_count << L" functions, " << instruction_count << L" instructions, " << xref_count << L" xrefs";
    set_log(log.str());
    const auto count = static_cast<int>(SendMessageW(functions_, LB_GETCOUNT, 0, 0));
    if (count > 0) {
        SendMessageW(functions_, LB_SETCURSEL, 0, 0);
        show_selected_function();
    }
}

void MainWindow::refresh_functions() {
    std::vector<wchar_t> buffer(2048, L'\0');
    const int length = GetWindowTextW(function_filter_, buffer.data(), static_cast<int>(buffer.size()));
    const std::wstring filter(buffer.data(), static_cast<std::size_t>(std::max(0, length)));
    Json arguments = Json::object();
    if (!filter.empty()) arguments["query"] = wide_to_utf8(filter);
    arguments["limit"] = 10000;
    const auto list = analyzer_.list_functions(arguments);
    SendMessageW(functions_, LB_RESETCONTENT, 0, 0);
    int selected = -1;
    int row = 0;
    for (const auto& item : list.array_items()) {
        const auto address = json_string(item, "address");
        const auto name = json_string(item, "name");
        if (address.empty() || name.empty()) continue;
        const auto parsed = parse_address(address).value_or(0);
        const auto text = name + L"  " + address;
        const auto index = static_cast<int>(SendMessageW(functions_, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(text.c_str())));
        SendMessageW(functions_, LB_SETITEMDATA, static_cast<WPARAM>(index), static_cast<LPARAM>(parsed));
        if (parsed == current_address_) selected = row;
        ++row;
    }
    if (selected >= 0) SendMessageW(functions_, LB_SETCURSEL, selected, 0);
}

void MainWindow::filter_functions() { refresh_functions(); }

void MainWindow::show_selected_function() {
    const auto index = static_cast<int>(SendMessageW(functions_, LB_GETCURSEL, 0, 0));
    if (index < 0) return;
    const auto address = static_cast<Address>(SendMessageW(functions_, LB_GETITEMDATA, static_cast<WPARAM>(index), 0));
    if (!address) return;
    navigate_to(address);
    Json arguments = Json::object();
    arguments["address"] = wide_to_utf8(address_text(address));
    populate_properties(analyzer_.get_function(arguments));
}

void MainWindow::navigate_to(Address address, bool add_history) {
    if (!address) return;
    if (add_history) {
        if (navigation_history_.empty()) {
            navigation_history_.push_back(address);
            navigation_index_ = 0;
        } else if (navigation_history_[navigation_index_] != address) {
            if (navigation_index_ + 1 < navigation_history_.size()) navigation_history_.erase(navigation_history_.begin() + static_cast<std::ptrdiff_t>(navigation_index_ + 1), navigation_history_.end());
            navigation_history_.push_back(address);
            navigation_index_ = navigation_history_.size() - 1;
        }
    }
    current_address_ = address;
    SetWindowTextW(address_edit_, address_text(address).c_str());
    populate_disassembly(address);
    populate_xrefs(address);
    EnableWindow(back_button_, !navigation_history_.empty() && navigation_index_ > 0);
    EnableWindow(forward_button_, !navigation_history_.empty() && navigation_index_ + 1 < navigation_history_.size());
}

void MainWindow::populate_disassembly(Address address) {
    Json arguments = Json::object();
    arguments["address"] = wide_to_utf8(address_text(address));
    arguments["count"] = 256;
    const auto instructions = analyzer_.disassemble(arguments);
    ListView_DeleteAllItems(disassembly_);
    disassembly_addresses_.clear();
    disassembly_kinds_.clear();
    int row = 0;
    for (const auto& instruction : instructions.array_items()) {
        const auto address_value = json_string(instruction, "address");
        const auto bytes = json_string(instruction, "bytes");
        const auto mnemonic = json_string(instruction, "mnemonic");
        const auto operands = json_string(instruction, "operands");
        const auto kind = instruction_kind(instruction);
        std::wstring comment;
        const auto* target = instruction.find("target");
        if (target && target->is_string()) comment = L"-> " + utf8_to_wide(target->as_string());
        else if (kind == L"return") comment = L"function return";
        else if (kind == L"indirect_call" || kind == L"indirect_jump") comment = L"indirect control flow";
        std::array<std::wstring, 5> values{address_value, bytes, mnemonic, operands, comment};
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.pszText = values[0].data();
        const auto inserted = ListView_InsertItem(disassembly_, &item);
        for (int column = 1; column < 5; ++column) ListView_SetItemText(disassembly_, inserted, column, values[static_cast<std::size_t>(column)].data());
        disassembly_addresses_.push_back(parse_address(address_value).value_or(0));
        disassembly_kinds_.push_back(kind);
        ++row;
    }
    if (row > 0) {
        ListView_SetItemState(disassembly_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(disassembly_, 0, FALSE);
    }
    select_main_tab(0);
}

void MainWindow::populate_hex(Address address) {
    Json arguments = Json::object();
    arguments["address"] = wide_to_utf8(address_text(address));
    arguments["count"] = 256;
    const auto bytes = analyzer_.read_bytes(arguments);
    const auto* encoded = bytes.find("bytes");
    if (!encoded || !encoded->is_string()) {
        SetWindowTextW(hex_view_, L"");
        select_main_tab(1);
        return;
    }
    const auto base = parse_address(json_string(bytes, "address")).value_or(address);
    const auto& hex = encoded->as_string();
    std::wostringstream output;
    for (std::size_t offset = 0; offset < hex.size(); offset += 32) {
        const auto byte_count = std::min<std::size_t>(16, (hex.size() - offset) / 2);
        output << address_text(base + static_cast<Address>(offset / 2)) << L"  ";
        std::wstring ascii;
        for (std::size_t index = 0; index < 16; ++index) {
            if (index < byte_count) {
                unsigned value = 0;
                try { value = static_cast<unsigned>(std::stoul(hex.substr(offset + index * 2, 2), nullptr, 16)); } catch (...) { value = 0; }
                output << std::hex << std::setw(2) << std::setfill(L'0') << value << L" ";
                ascii.push_back(value >= 0x20 && value <= 0x7e ? static_cast<wchar_t>(value) : L'.');
            } else {
                output << L"   ";
                ascii.push_back(L' ');
            }
            if (index == 7) output << L' ';
        }
        output << L" |" << ascii << L"|\r\n";
    }
    SetWindowTextW(hex_view_, output.str().c_str());
    select_main_tab(1);
}

void MainWindow::populate_xrefs(Address address) {
    SendMessageW(xrefs_, LB_RESETCONTENT, 0, 0);
    xref_targets_.clear();
    Json arguments = Json::object();
    arguments["address"] = wide_to_utf8(address_text(address));
    const auto incoming = analyzer_.xrefs_to(arguments);
    const auto outgoing = analyzer_.xrefs_from(arguments);
    auto add_reference = [&](const Json& reference, bool incoming_reference) {
        const auto from = json_string(reference, "from");
        const auto to = json_string(reference, "to");
        const auto kind = json_string(reference, "kind");
        const auto symbol = json_string(reference, "symbol");
        const auto target_text = incoming_reference ? from : to;
        const auto target = parse_address(target_text).value_or(0);
        std::wstring line = incoming_reference ? L"<- " : L"-> ";
        line += target_text + L"  " + kind;
        if (!symbol.empty()) line += L"  " + symbol;
        const auto row = static_cast<int>(SendMessageW(xrefs_, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str())));
        SendMessageW(xrefs_, LB_SETITEMDATA, static_cast<WPARAM>(row), static_cast<LPARAM>(target));
        xref_targets_.push_back(target);
    };
    for (const auto& reference : incoming.array_items()) add_reference(reference, true);
    for (const auto& reference : outgoing.array_items()) add_reference(reference, false);
    if (SendMessageW(xrefs_, LB_GETCOUNT, 0, 0) == 0) SendMessageW(xrefs_, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"No indexed xrefs at this address"));
}

void MainWindow::populate_properties(const Json& value) {
    SetWindowTextW(properties_, utf8_to_wide(value.dump()).c_str());
    select_side_tab(1);
}

void MainWindow::set_log(const std::wstring& message) {
    const auto length = GetWindowTextLengthW(log_);
    SendMessageW(log_, EM_SETSEL, static_cast<WPARAM>(length), static_cast<LPARAM>(length));
    const std::wstring line = message + L"\r\n";
    SendMessageW(log_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));
}

void MainWindow::set_status(const std::wstring& message) {
    if (status_) SendMessageW(status_, SB_SETTEXTW, 0, reinterpret_cast<LPARAM>(message.c_str()));
}

void MainWindow::jump_to_address() {
    std::vector<wchar_t> buffer(128, L'\0');
    const auto length = GetWindowTextW(address_edit_, buffer.data(), static_cast<int>(buffer.size()));
    const std::wstring text(buffer.data(), static_cast<std::size_t>(std::max(0, length)));
    const auto address = parse_address(text);
    if (!address) {
        set_log(L"Invalid address: " + text);
        return;
    }
    navigate_to(*address);
}

void MainWindow::go_to_entry() {
    const auto info = analyzer_.module_info();
    const auto entry = parse_address(json_string(info, "entry_point"));
    if (entry) navigate_to(*entry);
}

void MainWindow::go_back() {
    if (navigation_history_.empty() || navigation_index_ == 0) return;
    --navigation_index_;
    navigate_to(navigation_history_[navigation_index_], false);
}

void MainWindow::go_forward() {
    if (navigation_history_.empty() || navigation_index_ + 1 >= navigation_history_.size()) return;
    ++navigation_index_;
    navigate_to(navigation_history_[navigation_index_], false);
}

void MainWindow::show_xrefs() {
    populate_xrefs(current_address_);
    select_side_tab(0);
}

void MainWindow::show_cfg() {
    Json arguments = Json::object();
    arguments["function_address"] = wide_to_utf8(address_text(current_address_));
    populate_properties(analyzer_.cfg(arguments));
    set_log(L"CFG refreshed for " + address_text(current_address_));
}

void MainWindow::show_callers() {
    Json arguments = Json::object();
    arguments["function_address"] = wide_to_utf8(address_text(current_address_));
    arguments["direction"] = "callers";
    arguments["depth"] = 2;
    populate_properties(analyzer_.call_graph(arguments));
}

void MainWindow::show_callees() {
    Json arguments = Json::object();
    arguments["function_address"] = wide_to_utf8(address_text(current_address_));
    arguments["direction"] = "callees";
    arguments["depth"] = 2;
    populate_properties(analyzer_.call_graph(arguments));
}

void MainWindow::show_imports() {
    const auto imports = analyzer_.list_imports(Json::object());
    std::wstring text;
    for (const auto& item : imports.array_items()) {
        text += json_string(item, "thunk") + L"  " + json_string(item, "library") + L"!" + json_string(item, "name") + L"\r\n";
    }
    if (text.empty()) text = L"No imports indexed.";
    SetWindowTextW(imports_view_, text.c_str());
    select_main_tab(4);
}

void MainWindow::show_exports() {
    const auto exports = analyzer_.list_exports(Json::object());
    std::wstring text;
    for (const auto& item : exports.array_items()) text += json_string(item, "address") + L"  " + json_string(item, "name") + L"\r\n";
    if (text.empty()) text = L"No exports indexed.";
    SetWindowTextW(exports_view_, text.c_str());
    select_main_tab(5);
}

void MainWindow::show_hex_view() { populate_hex(current_address_); }

void MainWindow::show_ai_help() {
    wchar_t module_path[32768]{};
    GetModuleFileNameW(nullptr, module_path, static_cast<DWORD>(std::size(module_path)));
    std::wstring executable(module_path);
    const auto slash = executable.find_last_of(L"\\/");
    if (slash != std::wstring::npos) executable.resize(slash + 1);
    executable += L"paper_ai.exe";
    std::wstring text = L"AI / MCP quick setup\r\n\r\nBuild the optional paper_ai target with PAPER_BUILD_AI=ON, then register this executable as a local stdio server:\r\n\r\n{\r\n  \"mcpServers\": {\r\n    \"paper\": {\r\n      \"command\": \"" + executable + L"\",\r\n      \"args\": []\r\n    }\r\n  }\r\n}\r\n\r\nRecommended calls:\r\nopen_binary -> module_info -> list_functions -> disassemble -> xrefs_to / xrefs_from -> cfg -> call_graph\r\n\r\nThe AI server is static-only and shares the same indexed evidence as this GUI.";
    SetWindowTextW(properties_, text.c_str());
    select_side_tab(1);
}

void MainWindow::jump_to_xref() {
    const auto index = static_cast<int>(SendMessageW(xrefs_, LB_GETCURSEL, 0, 0));
    if (index < 0) return;
    const auto target = static_cast<Address>(SendMessageW(xrefs_, LB_GETITEMDATA, static_cast<WPARAM>(index), 0));
    if (target) navigate_to(target);
}

void MainWindow::show_selected_disassembly_row(int row) {
    if (row < 0 || static_cast<std::size_t>(row) >= disassembly_addresses_.size()) return;
    current_address_ = disassembly_addresses_[static_cast<std::size_t>(row)];
    populate_xrefs(current_address_);
}

std::wstring MainWindow::utf8_to_wide(std::string_view text) {
    if (text.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length);
    return result;
}

std::string MainWindow::wide_to_utf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string result(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length, nullptr, nullptr);
    return result;
}

std::wstring MainWindow::json_string(const Json& item, std::string_view key) {
    const auto* value = item.find(key);
    return value && value->is_string() ? utf8_to_wide(value->as_string()) : std::wstring{};
}

std::wstring MainWindow::address_text(Address address) {
    std::wostringstream text;
    text << L"0x" << std::hex << std::nouppercase << address;
    return text.str();
}

std::optional<Address> MainWindow::parse_address(std::wstring_view text) {
    std::size_t first = 0;
    while (first < text.size() && std::iswspace(text[first])) ++first;
    std::size_t last = text.size();
    while (last > first && std::iswspace(text[last - 1])) --last;
    if (first == last) return std::nullopt;
    std::wstring value(text.substr(first, last - first));
    if (value.size() >= 2 && value[0] == L'0' && (value[1] == L'x' || value[1] == L'X')) value.erase(0, 2);
    if (value.empty()) return std::nullopt;
    try {
        std::size_t consumed = 0;
        const auto address = std::stoull(value, &consumed, 16);
        return consumed == value.size() ? std::optional<Address>(static_cast<Address>(address)) : std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

std::wstring MainWindow::instruction_kind(const Json& item) {
    return json_string(item, "kind");
}

HWND MainWindow::create_control(DWORD ex_style, LPCWSTR class_name, LPCWSTR title, DWORD style,
                                int x, int y, int width, int height, HWND parent, int id,
                                HINSTANCE instance) {
    return CreateWindowExW(ex_style, class_name, title, style, x, y, width, height, parent,
                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance, nullptr);
}

void MainWindow::set_control_font(HWND control, HFONT font) {
    if (control && font) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
}

} // namespace paper
