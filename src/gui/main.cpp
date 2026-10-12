#include "paper/gui/main_window.hpp"

#include <QApplication>

int main(int argc, char** argv) {
    QApplication application(argc, argv);
    application.setApplicationName("Paper");
    application.setApplicationVersion("0.2.0");
    application.setOrganizationName("Paper");
    paper::MainWindow window;
    if (argc > 1) window.open_path(QString::fromLocal8Bit(argv[1]));
    window.show();
    return application.exec();
}


