# Paper

Paper is a Windows PE static-analysis application built with C++20, Dear ImGui, and DirectX 11. The desktop target is `paper.exe`; an optional `paper_ai.exe` exposes the same analysis engine through a local MCP-compatible JSON-RPC interface.

## Features

- PE, DLL, and SYS loading
- x86/x64 instruction decoding and multi-threaded analysis
- Function discovery, basic blocks, CFGs, and call graphs
- Imports, exports, sections/segments, strings, and indexed xrefs
- Address navigation, byte search, hexadecimal view, and properties
- User names, comments, bookmarks, and sidecar analysis databases
- Dear ImGui docking layout with an IDA-inspired workflow
- Optional Zydis decoder backend

The project is a static analyzer. It does not execute the input image.

## Build

The supported desktop environment is Windows with Visual Studio 2022, the Windows SDK, and CMake. The GUI uses the DirectX 11 backend; Qt is not required.

CMake builds the desktop target by default:

- `PAPER_BUILD_GUI=ON`
- `PAPER_BUILD_AI=OFF`
- `PAPER_BUILD_TESTS=OFF`

The generated desktop executable is `paper.exe`. Enable `PAPER_BUILD_AI` only when an AI client needs the local MCP server. Enable `PAPER_BUILD_TESTS` for the core smoke tests. Dear ImGui is fetched automatically unless a copy is provided in `third_party/imgui`.

For improved x86/x64 decoding, install Zydis and enable `PAPER_WITH_ZYDIS=ON`. The built-in decoder remains available as the fallback.

## Interface

The desktop interface contains:

- Functions
- IDA View-A
- Hex View and module information
- Xrefs and Properties
- Strings, Names, Imports, Exports, Segments, and Bookmarks
- CFG Graph View
- Byte Search
- Output and analysis statistics

Names, comments, and bookmarks are stored in a sidecar file named `<image>.paper.json`. The database is loaded when the image is opened and saved explicitly with `Ctrl+S` or automatically when the application closes.

See [GUI shortcuts](docs/GUI_SHORTCUTS_ZH.md) for the current keyboard map.

## AI interface

`paper_ai.exe` communicates over newline-delimited JSON-RPC using the MCP methods `initialize`, `tools/list`, and `tools/call`.

Available operations include:

`open_binary`, `module_info`, `list_sections`, `list_segments`, `list_functions`, `get_function`, `disassemble`, `read_bytes`, `xrefs_to`, `xrefs_from`, `cfg`, `search_strings`, `list_strings`, `search_bytes`, `list_imports`, `list_exports`, `list_names`, `list_bookmarks`, `call_graph`, `set_name`, `set_comment`, `set_bookmark`, `save_database`, `load_database`, and `analysis_stats`.

Example request:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":"C:\\samples\\demo.exe"}}}
```

The recommended AI workflow is: open the image, inspect module information and segments, enumerate functions and symbols, then use disassembly, xrefs, CFGs, strings, and byte searches to collect evidence.

See [AI usage](docs/AI_USAGE_ZH.md) for the complete tool list and examples.

## Scope

The current release focuses on static PE analysis and an efficient navigation workflow. Type recovery, a decompiler, binary patching, plugin scripting, and dynamic debugging are separate future modules.
