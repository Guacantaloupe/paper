#define UNICODE
#define _UNICODE
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "paper/gui/main_window.hpp"

#include <shellapi.h>

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int command) {
    paper::MainWindow window;
    if (!window.create(instance)) return 1;

    int argument_count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    if (arguments && argument_count > 1) window.open_path(arguments[1]);
    if (arguments) LocalFree(arguments);

    window.show(command);
    return window.run();
}
