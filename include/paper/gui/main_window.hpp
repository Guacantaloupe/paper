#pragma once

#include "paper/core/analyzer.hpp"

#include <QMainWindow>
#include <QString>

#include <cstdint>
#include <optional>
#include <vector>

class QListWidget;
class QListWidgetItem;
class QLineEdit;
class QPlainTextEdit;
class QLabel;
class QDockWidget;
class QTabWidget;
class QTableWidget;
class QAction;

namespace paper {

class MainWindow final : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    void open_path(const QString& path);

private slots:
    void open_file();
    void show_selected_function();
    void filter_functions(const QString& query);
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
    void jump_to_xref(QListWidgetItem* item);
    void show_selected_disassembly_row(int row, int column);

private:
    void refresh_functions();
    void navigate_to(Address address, bool add_history = true);
    void populate_disassembly(Address address);
    void populate_hex(Address address);
    void populate_xrefs(Address address);
    void populate_properties(const Json& value);
    void set_log(const QString& message);
    std::optional<Address> item_address(const QListWidgetItem* item) const;
    static std::optional<Address> parse_address(const QString& text);
    static QString address_text(Address address);

    Analyzer analyzer_;
    QListWidget* functions_ = nullptr;
    QLineEdit* function_filter_ = nullptr;
    QTableWidget* disassembly_ = nullptr;
    QPlainTextEdit* hex_view_ = nullptr;
    QPlainTextEdit* structures_view_ = nullptr;
    QPlainTextEdit* enums_view_ = nullptr;
    QPlainTextEdit* imports_view_ = nullptr;
    QPlainTextEdit* exports_view_ = nullptr;
    QListWidget* xrefs_ = nullptr;
    QPlainTextEdit* properties_ = nullptr;
    QPlainTextEdit* log_ = nullptr;
    QTabWidget* views_ = nullptr;
    QDockWidget* functions_dock_ = nullptr;
    QDockWidget* side_dock_ = nullptr;
    QDockWidget* log_dock_ = nullptr;
    QLabel* status_ = nullptr;
    QAction* back_action_ = nullptr;
    QAction* forward_action_ = nullptr;
    Address current_address_ = 0;
    std::vector<Address> navigation_history_;
    std::size_t navigation_index_ = 0;
};

} // namespace paper

