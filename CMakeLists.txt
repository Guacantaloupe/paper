cmake_minimum_required(VERSION 3.22)
project(Paper VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(PAPER_BUILD_GUI "Build the optional native Win32 desktop application" ON)
option(PAPER_BUILD_AI "Build the optional JSON-RPC/MCP AI server" OFF)
option(PAPER_BUILD_TESTS "Build the core smoke tests" OFF)
option(PAPER_WITH_ZYDIS "Use the Zydis x86-64 decoder backend when available" OFF)

find_package(Threads REQUIRED)

add_library(paper_core STATIC
    src/core/pe_image.cpp
    src/core/x86_decoder.cpp
    src/core/analyzer.cpp
    src/core/rpc.cpp
)
target_include_directories(paper_core PUBLIC include)
target_link_libraries(paper_core PUBLIC Threads::Threads)

if(PAPER_WITH_ZYDIS)
    find_package(Zydis CONFIG REQUIRED)
    if(TARGET Zydis::Zydis)
        target_link_libraries(paper_core PUBLIC Zydis::Zydis)
    elseif(TARGET Zydis)
        target_link_libraries(paper_core PUBLIC Zydis)
    else()
        message(FATAL_ERROR "PAPER_WITH_ZYDIS is ON, but no Zydis CMake target was exported")
    endif()
    target_compile_definitions(paper_core PUBLIC PAPER_WITH_ZYDIS=1)
endif()

if(MSVC)
    # Keep optimization/debug-runtime flags under CMake's configuration control.
    # In particular, Debug uses /Od /RTC1 while Release uses /O2; adding /O2
    # unconditionally would make those configurations incompatible.
    target_compile_options(paper_core PRIVATE /W4 /permissive-)
    target_compile_definitions(paper_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    target_compile_options(paper_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(PAPER_BUILD_AI)
    add_executable(paper_ai src/app/ai_main.cpp)
    target_link_libraries(paper_ai PRIVATE paper_core)
endif()

if(PAPER_BUILD_GUI)
    if(WIN32)
        add_executable(paper WIN32
            src/gui/main.cpp
            src/gui/main_window.cpp
            include/paper/gui/main_window.hpp
        )
        target_link_libraries(paper PRIVATE paper_core comctl32 comdlg32 shell32 user32 gdi32)
        target_include_directories(paper PRIVATE include)
        target_compile_definitions(paper PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
        if(MSVC)
            target_compile_options(paper PRIVATE /W4 /permissive-)
        else()
            target_compile_options(paper PRIVATE -Wall -Wextra -Wpedantic)
        endif()
    else()
        message(STATUS "The native Paper desktop target is currently available on Windows only.")
    endif()
endif()

if(PAPER_BUILD_TESTS)
    enable_testing()
    add_executable(paper_core_smoke tests/core_smoke.cpp)
    target_link_libraries(paper_core_smoke PRIVATE paper_core)
    add_test(NAME paper_core_smoke COMMAND paper_core_smoke)
    add_executable(paper_pe_smoke tests/pe_smoke.cpp)
    target_link_libraries(paper_pe_smoke PRIVATE paper_core)
    add_test(NAME paper_pe_smoke COMMAND paper_pe_smoke)
    add_executable(paper_analyzer_smoke tests/analyzer_smoke.cpp)
    target_link_libraries(paper_analyzer_smoke PRIVATE paper_core)
    add_test(NAME paper_analyzer_smoke COMMAND paper_analyzer_smoke)
endif()

