#include "paper/gui/main_window.hpp"

#include <QAction>
#include <QAbstractItemView>
#include <QColor>
#include <QCoreApplication>
#include <QDockWidget>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QMenu>
#include <QMenuBar>
#include <QPlainTextEdit>
#include <QStatusBar>
#include <QStyle>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolBar>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <optional>

namespace paper {
namespace {

QString json_string(const Json& item, std::string_view key) {
    const auto* value = item.find(key);
    return value && value->is_string() ? QString::fromStdString(value->as_string()) : QString();
}

QString json_kind(const Json& item) { return json_string(item, "kind"); }

QLabel* legend_label(const QString& text, const QColor& color, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setAutoFillBackground(true);
    label->setStyleSheet(QString("QLabel { background: %1; color: #202020; padding: 2px 8px; border: 1px solid #b0b0b0; }").arg(color.name()));
    return label;
}

QPlainTextEdit* read_only_text(QWidget* parent) {
    auto* editor = new QPlainTextEdit(parent);
    editor->setReadOnly(true);
    editor->setLineWrapMode(QPlainTextEdit::NoWrap);
    editor->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    return editor;
}

QString pretty_address(const QString& text) {
    return text.isEmpty() ? QStringLiteral("-") : text;
}

} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("Paper — IDA-style Static Analysis");
    resize(1680, 1000);
    setDockNestingEnabled(true);

    auto* open_action = new QAction(style()->standardIcon(QStyle::SP_DialogOpenButton), "Open binary…", this);
    open_action->setShortcut(QKeySequence(QKeySequence::Open));
    open_action->setStatusTip("Open an EXE, DLL, or SYS image");
    connect(open_action, &QAction::triggered, this, &MainWindow::open_file);

    back_action_ = new QAction(style()->standardIcon(QStyle::SP_ArrowBack), "Back", this);
    back_action_->setShortcut(QKeySequence(QStringLiteral("Alt+Left")));
    back_action_->setEnabled(false);
    connect(back_action_, &QAction::triggered, this, &MainWindow::go_back);

    forward_action_ = new QAction(style()->standardIcon(QStyle::SP_ArrowForward), "Forward", this);
    forward_action_->setShortcut(QKeySequence(QStringLiteral("Alt+Right")));
    forward_action_->setEnabled(false);
    connect(forward_action_, &QAction::triggered, this, &MainWindow::go_forward);

    auto* goto_action = new QAction("Go to address…", this);
    goto_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+G")));
    connect(goto_action, &QAction::triggered, this, &MainWindow::jump_to_address);

    auto* entry_action = new QAction("Entry point", this);
    entry_action->setShortcut(QKeySequence(Qt::Key_Home));
    connect(entry_action, &QAction::triggered, this, &MainWindow::go_to_entry);

    auto* xrefs_action = new QAction("Xrefs", this);
    xrefs_action->setShortcut(QKeySequence(QStringLiteral("X")));
    xrefs_action->setStatusTip("Show incoming and outgoing cross-references");
    connect(xrefs_action, &QAction::triggered, this, &MainWindow::show_xrefs);

    auto* cfg_action = new QAction("CFG", this);
    cfg_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+F")));
    connect(cfg_action, &QAction::triggered, this, &MainWindow::show_cfg);

    auto* callers_action = new QAction("Callers", this);
    callers_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+U")));
    connect(callers_action, &QAction::triggered, this, &MainWindow::show_callers);

    auto* callees_action = new QAction("Callees", this);
    callees_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+D")));
    connect(callees_action, &QAction::triggered, this, &MainWindow::show_callees);

    auto* imports_action = new QAction("Imports", this);
    imports_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+I")));
    connect(imports_action, &QAction::triggered, this, &MainWindow::show_imports);

    auto* exports_action = new QAction("Exports", this);
    exports_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+E")));
    connect(exports_action, &QAction::triggered, this, &MainWindow::show_exports);

    auto* hex_action = new QAction("Hex view", this);
    hex_action->setShortcut(QKeySequence(QStringLiteral("Ctrl+H")));
    connect(hex_action, &QAction::triggered, this, &MainWindow::show_hex_view);

    auto* ai_action = new QAction("AI / MCP help", this);
    ai_action->setShortcut(QKeySequence(QKeySequence::HelpContents));
    connect(ai_action, &QAction::triggered, this, &MainWindow::show_ai_help);

    // The main IDA View-A surface: legend strip, tabbed views, and a dense
    // monospaced instruction table with address/bytes/mnemonic/operands.
    auto* central = new QWidget(this);
    auto* central_layout = new QVBoxLayout(central);
    central_layout->setContentsMargins(0, 0, 0, 0);
    central_layout->setSpacing(0);

    auto* legend = new QWidget(central);
    auto* legend_layout = new QHBoxLayout(legend);
    legend_layout->setContentsMargins(6, 4, 6, 4);
    legend_layout->setSpacing(4);
    legend_layout->addWidget(legend_label("Library function", QColor("#b9e5ff"), legend));
    legend_layout->addWidget(legend_label("Regular function", QColor("#bce8ff"), legend));
    legend_layout->addWidget(legend_label("Instruction", QColor("#f4cfb8"), legend));
    legend_layout->addWidget(legend_label("Data", QColor("#d8d8d8"), legend));
    legend_layout->addWidget(legend_label("Unexplored", QColor("#dedea0"), legend));
    legend_layout->addWidget(legend_label("External symbol", QColor("#efb5ee"), legend));
    legend_layout->addWidget(legend_label("Lumina function", QColor("#a8eaa8"), legend));
    legend_layout->addStretch(1);
    central_layout->addWidget(legend);

    views_ = new QTabWidget(central);
    views_->setDocumentMode(true);
    views_->setUsesScrollButtons(true);

    auto* ida_view = new QWidget(views_);
    auto* ida_layout = new QVBoxLayout(ida_view);
    ida_layout->setContentsMargins(0, 0, 0, 0);
    disassembly_ = new QTableWidget(ida_view);
    disassembly_->setColumnCount(5);
    disassembly_->setHorizontalHeaderLabels(QStringList{"Address", "Bytes", "Mnemonic", "Operands", "Comment"});
    disassembly_->verticalHeader()->setVisible(false);
    disassembly_->horizontalHeader()->setStretchLastSection(true);
    disassembly_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    disassembly_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    disassembly_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    disassembly_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    disassembly_->setSelectionBehavior(QAbstractItemView::SelectRows);
    disassembly_->setSelectionMode(QAbstractItemView::SingleSelection);
    disassembly_->setShowGrid(false);
    disassembly_->setAlternatingRowColors(true);
    disassembly_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    disassembly_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    disassembly_->setStyleSheet("QTableWidget { background: #ffffff; alternate-background-color: #f4f6f8; } QTableWidget::item:selected { background: #c9d7e8; color: #111111; }");
    ida_layout->addWidget(disassembly_);
    views_->addTab(ida_view, "IDA View-A");

    hex_view_ = read_only_text(views_);
    structures_view_ = read_only_text(views_);
    structures_view_->setPlainText("Structures\n\nType information will be populated by the symbol/type editor.");
    enums_view_ = read_only_text(views_);
    enums_view_->setPlainText("Enums\n\nEnum definitions will be populated by the symbol/type editor.");
    imports_view_ = read_only_text(views_);
    exports_view_ = read_only_text(views_);
    views_->addTab(hex_view_, "Hex View-1");
    views_->addTab(structures_view_, "Structures");
    views_->addTab(enums_view_, "Enums");
    views_->addTab(imports_view_, "Imports");
    views_->addTab(exports_view_, "Exports");
    central_layout->addWidget(views_, 1);
    setCentralWidget(central);

    // Left IDA-style Functions navigator.
    functions_dock_ = new QDockWidget("Functions", this);
    functions_dock_->setObjectName("FunctionsDock");
    functions_dock_->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    auto* functions_panel = new QWidget(functions_dock_);
    auto* functions_layout = new QVBoxLayout(functions_panel);
    functions_layout->setContentsMargins(4, 4, 4, 4);
    function_filter_ = new QLineEdit(functions_panel);
    function_filter_->setPlaceholderText("Filter functions…  (Ctrl+F)");
    functions_layout->addWidget(function_filter_);
    functions_ = new QListWidget(functions_panel);
    functions_->setAlternatingRowColors(true);
    functions_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    functions_layout->addWidget(functions_, 1);
    functions_dock_->setWidget(functions_panel);
    addDockWidget(Qt::LeftDockWidgetArea, functions_dock_);
    functions_dock_->setMinimumWidth(330);

    // Right-side Xrefs and Properties panes.
    side_dock_ = new QDockWidget("Xrefs / Properties", this);
    side_dock_->setObjectName("SideDock");
    side_dock_->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    auto* side_tabs = new QTabWidget(side_dock_);
    xrefs_ = new QListWidget(side_tabs);
    xrefs_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    properties_ = read_only_text(side_tabs);
    side_tabs->addTab(xrefs_, "Xrefs");
    side_tabs->addTab(properties_, "Properties");
    side_dock_->setWidget(side_tabs);
    addDockWidget(Qt::RightDockWidgetArea, side_dock_);
    side_dock_->setMinimumWidth(360);

    // Bottom output pane mirrors IDA's message/output area without stealing
    // space from the disassembly until the user needs it.
    log_dock_ = new QDockWidget("Output", this);
    log_dock_->setObjectName("OutputDock");
    log_dock_->setAllowedAreas(Qt::BottomDockWidgetArea);
    log_ = read_only_text(log_dock_);
    log_->setMaximumBlockCount(1000);
    log_dock_->setWidget(log_);
    addDockWidget(Qt::BottomDockWidgetArea, log_dock_);
    log_dock_->resize(100, 150);

    connect(function_filter_, &QLineEdit::textChanged, this, &MainWindow::filter_functions);
    connect(functions_, &QListWidget::itemSelectionChanged, this, &MainWindow::show_selected_function);
    connect(xrefs_, &QListWidget::itemDoubleClicked, this, &MainWindow::jump_to_xref);
    connect(disassembly_, &QTableWidget::cellClicked, this, &MainWindow::show_selected_disassembly_row);

    // Menus intentionally expose the same actions as the toolbar so every
    // high-value reverse-engineering query is reachable without mouse use.
    auto* file_menu = menuBar()->addMenu("File");
    file_menu->addAction(open_action);
    file_menu->addSeparator();
    auto* exit_action = new QAction("Exit", this);
    exit_action->setShortcut(QKeySequence(QKeySequence::Quit));
    connect(exit_action, &QAction::triggered, this, &QWidget::close);
    file_menu->addAction(exit_action);

    auto* navigate_menu = menuBar()->addMenu("Navigate");
    navigate_menu->addAction(back_action_);
    navigate_menu->addAction(forward_action_);
    navigate_menu->addSeparator();
    navigate_menu->addAction(goto_action);
    navigate_menu->addAction(entry_action);

    auto* analysis_menu = menuBar()->addMenu("Analysis");
    analysis_menu->addAction(xrefs_action);
    analysis_menu->addAction(cfg_action);
    analysis_menu->addAction(callers_action);
    analysis_menu->addAction(callees_action);
    analysis_menu->addSeparator();
    analysis_menu->addAction(imports_action);
    analysis_menu->addAction(exports_action);
    analysis_menu->addAction(hex_action);

    auto* windows_menu = menuBar()->addMenu("Windows");
    windows_menu->addAction(functions_dock_->toggleViewAction());
    windows_menu->addAction(side_dock_->toggleViewAction());
    windows_menu->addAction(log_dock_->toggleViewAction());

    auto* help_menu = menuBar()->addMenu("Help");
    help_menu->addAction(ai_action);

    auto* toolbar = addToolBar("IDA shortcuts");
    toolbar->setObjectName("IDAQuickToolbar");
    toolbar->setMovable(false);
    toolbar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    toolbar->addAction(open_action);
    toolbar->addAction(back_action_);
    toolbar->addAction(forward_action_);
    toolbar->addSeparator();
    toolbar->addAction(goto_action);
    toolbar->addAction(entry_action);
    toolbar->addSeparator();
    toolbar->addAction(xrefs_action);
    toolbar->addAction(cfg_action);
    toolbar->addAction(callers_action);
    toolbar->addAction(callees_action);
    toolbar->addAction(imports_action);
    toolbar->addAction(exports_action);
    toolbar->addAction(hex_action);
    toolbar->addAction(ai_action);

    status_ = new QLabel("Open a PE executable or DLL to begin.", this);
    statusBar()->addWidget(status_, 1);
    statusBar()->showMessage("Static analysis only — no sample execution");

    refresh_functions();
}

void MainWindow::open_file() {
    const auto path = QFileDialog::getOpenFileName(this, "Open PE image", QString(), "Executables (*.exe *.dll *.sys);;All files (*.*)");
    if (path.isEmpty()) return;
    open_path(path);
}

void MainWindow::open_path(const QString& path) {
    std::string error;
    if (!analyzer_.open_file(path.toStdString(), error)) {
        status_->setText(QString::fromStdString(error));
        set_log(QString::fromStdString(error));
        return;
    }
    navigation_history_.clear();
    navigation_index_ = 0;
    current_address_ = 0;
    const auto info = analyzer_.module_info();
    const auto stats = analyzer_.analysis_stats();
    const auto* functions = stats.find("function_count");
    const auto* instructions = stats.find("instruction_count");
    const auto function_count = functions ? functions->as_u64() : 0;
    const auto instruction_count = instructions ? instructions->as_u64() : 0;
    status_->setText(QString("Indexed %1 functions, %2 instructions").arg(static_cast<qulonglong>(function_count)).arg(static_cast<qulonglong>(instruction_count)));
    populate_properties(info);
    refresh_functions();
    set_log(QString("Loaded %1\n%2 functions, %3 instructions, %4 xrefs")
                .arg(path)
                .arg(static_cast<qulonglong>(function_count))
                .arg(static_cast<qulonglong>(instruction_count))
                .arg(static_cast<qulonglong>(stats.find("xref_count") ? stats.find("xref_count")->as_u64() : 0)));
    if (functions_ && functions_->count() > 0) functions_->setCurrentRow(0);
}

void MainWindow::refresh_functions() {
    functions_->setUpdatesEnabled(false);
    functions_->clear();
    Json args = Json::object();
    const auto query = function_filter_ ? function_filter_->text().trimmed() : QString();
    if (!query.isEmpty()) args["query"] = query.toStdString();
    args["limit"] = 10'000;
    const auto list = analyzer_.list_functions(args);
    int row_to_select = -1;
    int row = 0;
    for (const auto& item : list.array_items()) {
        const auto address = json_string(item, "address");
        const auto name = json_string(item, "name");
        if (address.isEmpty() || name.isEmpty()) continue;
        auto* function_item = new QListWidgetItem(name + "  " + address, functions_);
        function_item->setData(Qt::UserRole, address);
        function_item->setToolTip(name + "\n" + address);
        if (item.find("exported") && item.find("exported")->as_bool()) function_item->setForeground(QColor("#185a9d"));
        if (parse_address(address).value_or(0) == current_address_) row_to_select = row;
        ++row;
    }
    functions_->setUpdatesEnabled(true);
    if (row_to_select >= 0) functions_->setCurrentRow(row_to_select);
}

void MainWindow::filter_functions(const QString&) { refresh_functions(); }

void MainWindow::show_selected_function() {
    const auto selected = functions_->selectedItems();
    if (selected.isEmpty()) return;
    const auto address = item_address(selected.front());
    if (!address) return;
    navigate_to(*address);
    Json args = Json::object();
    args["address"] = address_text(*address).toStdString();
    populate_properties(analyzer_.get_function(args));
}

void MainWindow::navigate_to(Address address, bool add_history) {
    if (address == 0) return;
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
    populate_disassembly(address);
    populate_xrefs(address);
    back_action_->setEnabled(!navigation_history_.empty() && navigation_index_ > 0);
    forward_action_->setEnabled(!navigation_history_.empty() && navigation_index_ + 1 < navigation_history_.size());
}

void MainWindow::populate_disassembly(Address address) {
    Json args = Json::object();
    args["address"] = address_text(address).toStdString();
    args["count"] = 256;
    const auto instructions = analyzer_.disassemble(args);
    disassembly_->setUpdatesEnabled(false);
    disassembly_->clearContents();
    disassembly_->setRowCount(static_cast<int>(instructions.array_items().size()));
    int row = 0;
    for (const auto& instruction : instructions.array_items()) {
        const auto address_value = json_string(instruction, "address");
        const auto bytes = json_string(instruction, "bytes");
        const auto mnemonic = json_string(instruction, "mnemonic");
        const auto operands = json_string(instruction, "operands");
        const auto kind = json_kind(instruction);
        QString comment;
        if (const auto target = instruction.find("target"); target && target->is_string()) comment = QStringLiteral("→ ") + QString::fromStdString(target->as_string());
        else if (kind == QStringLiteral("return")) comment = QStringLiteral("function return");
        else if (kind == QStringLiteral("indirect_call") || kind == QStringLiteral("indirect_jump")) comment = QStringLiteral("indirect control flow");

        const QStringList values{address_value, bytes, mnemonic, operands, comment};
        for (int column = 0; column < values.size(); ++column) {
            auto* cell = new QTableWidgetItem(values[column]);
            cell->setData(Qt::UserRole, address_value);
            disassembly_->setItem(row, column, cell);
        }
        QColor color("#274e8b");
        if (kind == QStringLiteral("call") || kind == QStringLiteral("indirect_call")) color = QColor("#8a3b12");
        else if (kind == QStringLiteral("jump") || kind == QStringLiteral("conditional_jump")) color = QColor("#6b3f95");
        else if (kind == QStringLiteral("return")) color = QColor("#8b1a1a");
        for (int column = 2; column <= 3; ++column) disassembly_->item(row, column)->setForeground(color);
        ++row;
    }
    disassembly_->setUpdatesEnabled(true);
    if (disassembly_->rowCount() > 0) {
        disassembly_->setCurrentCell(0, 0);
        disassembly_->scrollToItem(disassembly_->item(0, 0), QAbstractItemView::PositionAtTop);
    }
    views_->setCurrentIndex(0);
}

void MainWindow::populate_hex(Address address) {
    Json args = Json::object();
    args["address"] = address_text(address).toStdString();
    args["count"] = 256;
    const auto bytes = analyzer_.read_bytes(args);
    const auto* encoded = bytes.find("bytes");
    if (!encoded || !encoded->is_string()) {
        hex_view_->clear();
        return;
    }
    const auto base = parse_address(json_string(bytes, "address")).value_or(address);
    const QString hex = QString::fromStdString(encoded->as_string());
    QString output;
    for (qsizetype offset = 0; offset < hex.size(); offset += 32) {
        const int byte_count = std::min(16, static_cast<int>((hex.size() - offset) / 2));
        output += address_text(base + static_cast<Address>(offset / 2)) + "  ";
        QString ascii;
        for (int index = 0; index < 16; ++index) {
            if (index < byte_count) {
                const auto token = hex.mid(offset + index * 2, 2);
                bool ok = false;
                const auto value = token.toUInt(&ok, 16);
                output += ok ? QString("%1 ").arg(value, 2, 16, QLatin1Char('0')) : QStringLiteral("?? ");
                ascii += ok && value >= 0x20 && value <= 0x7e ? QChar(static_cast<ushort>(value)) : QChar('.');
            } else {
                output += QStringLiteral("   ");
                ascii += QChar(' ');
            }
            if (index == 7) output += QChar(' ');
        }
        output += " |" + ascii + "|\n";
    }
    hex_view_->setPlainText(output);
    views_->setCurrentWidget(hex_view_);
}

void MainWindow::populate_xrefs(Address address) {
    xrefs_->clear();
    Json args = Json::object();
    args["address"] = address_text(address).toStdString();
    const auto incoming = analyzer_.xrefs_to(args);
    const auto outgoing = analyzer_.xrefs_from(args);
    for (const auto& reference : incoming.array_items()) {
        const auto from = json_string(reference, "from");
        const auto kind = json_string(reference, "kind");
        const auto symbol = json_string(reference, "symbol");
        auto* item = new QListWidgetItem(QStringLiteral("← ") + pretty_address(from) + "  " + kind + (symbol.isEmpty() ? QString() : "  " + symbol), xrefs_);
        item->setData(Qt::UserRole, from);
        item->setToolTip(item->text());
    }
    for (const auto& reference : outgoing.array_items()) {
        const auto to = json_string(reference, "to");
        const auto kind = json_string(reference, "kind");
        const auto symbol = json_string(reference, "symbol");
        auto* item = new QListWidgetItem(QStringLiteral("→ ") + pretty_address(to) + "  " + kind + (symbol.isEmpty() ? QString() : "  " + symbol), xrefs_);
        item->setData(Qt::UserRole, to);
        item->setToolTip(item->text());
    }
    if (xrefs_->count() == 0) xrefs_->addItem("No indexed xrefs at this address");
}

void MainWindow::populate_properties(const Json& value) { properties_->setPlainText(QString::fromStdString(value.dump())); }

void MainWindow::set_log(const QString& message) {
    log_->appendPlainText(message);
    log_->ensureCursorVisible();
}

void MainWindow::jump_to_address() {
    bool accepted = false;
    const auto initial = current_address_ ? address_text(current_address_) : QStringLiteral("0x");
    const auto text = QInputDialog::getText(this, "Go to address", "Address (hex):", QLineEdit::Normal, initial, &accepted);
    if (!accepted) return;
    const auto address = parse_address(text);
    if (!address) {
        set_log("Invalid address: " + text);
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
    side_dock_->show();
    side_dock_->raise();
}

void MainWindow::show_cfg() {
    Json args = Json::object();
    args["function_address"] = address_text(current_address_).toStdString();
    const auto cfg = analyzer_.cfg(args);
    populate_properties(cfg);
    side_dock_->show();
    side_dock_->raise();
    set_log("CFG refreshed for " + address_text(current_address_));
}

void MainWindow::show_callers() {
    Json args = Json::object();
    args["function_address"] = address_text(current_address_).toStdString();
    args["direction"] = "callers";
    args["depth"] = 2;
    populate_properties(analyzer_.call_graph(args));
    side_dock_->show();
    side_dock_->raise();
}

void MainWindow::show_callees() {
    Json args = Json::object();
    args["function_address"] = address_text(current_address_).toStdString();
    args["direction"] = "callees";
    args["depth"] = 2;
    populate_properties(analyzer_.call_graph(args));
    side_dock_->show();
    side_dock_->raise();
}

void MainWindow::show_imports() {
    const auto imports = analyzer_.list_imports(Json::object());
    QString text;
    for (const auto& item : imports.array_items()) text += json_string(item, "thunk") + "  " + json_string(item, "library") + "!" + json_string(item, "name") + "\n";
    imports_view_->setPlainText(text.isEmpty() ? QStringLiteral("No imports indexed.") : text);
    views_->setCurrentWidget(imports_view_);
}

void MainWindow::show_exports() {
    const auto exports = analyzer_.list_exports(Json::object());
    QString text;
    for (const auto& item : exports.array_items()) text += json_string(item, "address") + "  " + json_string(item, "name") + "\n";
    exports_view_->setPlainText(text.isEmpty() ? QStringLiteral("No exports indexed.") : text);
    views_->setCurrentWidget(exports_view_);
}

void MainWindow::show_hex_view() { populate_hex(current_address_); }

void MainWindow::show_ai_help() {
    const auto executable = QCoreApplication::applicationDirPath() + "/paper_ai.exe";
    properties_->setPlainText(
        "AI / MCP quick setup\n\n"
        "Register this executable as a local stdio server:\n\n"
        "{\n  \"mcpServers\": {\n    \"paper\": {\n      \"command\": \"" + executable +
        "\",\n      \"args\": []\n    }\n  }\n}\n\n"
        "Recommended first calls:\n"
        "open_binary → module_info → list_functions → disassemble → xrefs_to / xrefs_from → cfg → call_graph\n\n"
        "The AI server is static-only and shares the same indexed evidence as this GUI.");
    side_dock_->show();
    side_dock_->raise();
}

void MainWindow::jump_to_xref(QListWidgetItem* item) {
    if (!item) return;
    const auto address = parse_address(item->data(Qt::UserRole).toString());
    if (address) navigate_to(*address);
}

void MainWindow::show_selected_disassembly_row(int row, int) {
    if (row < 0 || row >= disassembly_->rowCount() || !disassembly_->item(row, 0)) return;
    const auto address = parse_address(disassembly_->item(row, 0)->data(Qt::UserRole).toString());
    if (!address) return;
    current_address_ = *address;
    populate_xrefs(*address);
}

std::optional<Address> MainWindow::item_address(const QListWidgetItem* item) const {
    return item ? parse_address(item->data(Qt::UserRole).toString()) : std::nullopt;
}

std::optional<Address> MainWindow::parse_address(const QString& text) {
    const auto value = text.trimmed();
    if (value.isEmpty()) return std::nullopt;
    bool ok = false;
    const int base = value.startsWith("0x", Qt::CaseInsensitive) ? 0 : 16;
    const auto address = value.toULongLong(&ok, base);
    return ok ? std::optional<Address>(static_cast<Address>(address)) : std::nullopt;
}

QString MainWindow::address_text(Address address) { return QStringLiteral("0x") + QString::number(address, 16); }

} // namespace paper

