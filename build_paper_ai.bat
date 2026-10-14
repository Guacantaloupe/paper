@echo off
rem Build Paper's AI/MCP server (paper_ai) without vcvars.
rem
rem WHY NOT CMAKE HERE
rem     The project's CMake path wants a generator and, for the GUI target, Dear ImGui
rem     plus DirectX 11.  The AI target needs neither: it is five translation units that
rem     link only against the CRT and Threads.  On a machine where `call vcvars64.bat`
rem     prints its banner and then never returns -- verified on this one with a 120 s
rem     timeout -- locating the toolchain directly is both faster and less failure-prone
rem     than fighting a generator, and the same approach already builds the sky-re C++
rem     tools in seconds.
rem
rem Usage: build_paper_ai.bat [<paper-root>]
rem Exit status: 0 on success, 1 on any failure.
setlocal enabledelayedexpansion
set "ROOT=%~1"
if "%ROOT%"=="" set "ROOT=%~dp0"

cd /d "%ROOT%" || ( echo cannot cd to "%ROOT%" & exit /b 1 )
if not exist src\app\ai_main.cpp ( echo not a paper checkout: %ROOT% & exit /b 1 )

if not exist build-here\obj mkdir build-here\obj
if not exist build-here\bin mkdir build-here\bin

rem ---------------------------------------------------------------- toolchain
set "CL_EXE="
where cl.exe >nul 2>&1 && set "CL_EXE=cl.exe"

if not defined CL_EXE (
    set "VSROOT="
    for %%d in (
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
        "C:\Program Files\Microsoft Visual Studio\2022\Community"
        "C:\Program Files\Microsoft Visual Studio\2022\Professional"
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise"
    ) do (
        if not defined VSROOT if exist "%%~d\VC\Tools\MSVC" set "VSROOT=%%~d"
    )
    if not defined VSROOT ( echo no Visual Studio with VC\Tools\MSVC found & exit /b 1 )

    set "MSVCVER="
    for /f "delims=" %%v in ('dir /b /ad /o-n "!VSROOT!\VC\Tools\MSVC" 2^>nul') do (
        if not defined MSVCVER set "MSVCVER=%%v"
    )
    if not defined MSVCVER ( echo no MSVC toolset under !VSROOT! & exit /b 1 )
    set "MSVCDIR=!VSROOT!\VC\Tools\MSVC\!MSVCVER!"
    set "CL_EXE=!MSVCDIR!\bin\Hostx64\x64\cl.exe"
    if not exist "!CL_EXE!" ( echo no x64 cl.exe under !MSVCDIR! & exit /b 1 )

    set "WINSDK="
    for %%d in (
        "C:\Program Files (x86)\Windows Kits\10"
        "C:\Program Files\Windows Kits\10"
    ) do (
        if not defined WINSDK if exist "%%~d\Include" set "WINSDK=%%~d"
    )
    if not defined WINSDK ( echo no Windows SDK found & exit /b 1 )

    set "SDKVER="
    for /f "delims=" %%v in ('dir /b /ad /o-n "!WINSDK!\Include" 2^>nul') do (
        if not defined SDKVER set "SDKVER=%%v"
    )
    set "SDKDIR=!WINSDK!\Include\!SDKVER!"
    if not exist "!SDKDIR!\ucrt" ( echo no ucrt headers under !SDKDIR! & exit /b 1 )

    set "INCLUDE=!MSVCDIR!\include;!SDKDIR!\ucrt;!SDKDIR!\um;!SDKDIR!\shared"
    set "LIB=!MSVCDIR!\lib\x64;!WINSDK!\Lib\!SDKVER!\ucrt\x64;!WINSDK!\Lib\!SDKVER!\um\x64"
    set "PATH=!MSVCDIR!\bin\Hostx64\x64;!PATH!"
    echo MSVC !MSVCVER!  SDK !SDKVER!
)

rem ---------------------------------------------------------------- compile
rem /std:c++20 because the project declares C++20.  /EHsc and /MT are the defaults the
rem other builds in this session use; NOMINMAX avoids the min/max macro collisions that
rem <windows.h> introduces.
rem
rem dbghelp is linked because load_symbols resolves symbols through the DbgHelp API, and the
rem project's CMakeLists links it for the same reason. Without it the build fails on
rem SymInitializeA and SymLoadModuleExA being undeclared.
set "SRC=src\app\ai_main.cpp src\core\pe_image.cpp src\core\x86_decoder.cpp src\core\analyzer.cpp src\core\rpc.cpp"

"%CL_EXE%" /nologo /std:c++20 /EHsc /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
    /Iinclude /Fobuild-here\obj\ /Fdbuild-here\obj\paper_ai.pdb ^
    %SRC% ^
    /link /OUT:build-here\bin\paper_ai.exe /SUBSYSTEM:CONSOLE dbghelp.lib

if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
if not exist build-here\bin\paper_ai.exe ( echo no output binary & exit /b 1 )

for %%f in (build-here\bin\paper_ai.exe) do echo built %%f  (%%~zf bytes)
exit /b 0
