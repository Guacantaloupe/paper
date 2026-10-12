# Paper

Paper is a fast, local, IDA-style static analysis workbench. The v0.2 core is deliberately split into two parts:

- `paper_core`: PE loading, executable-section disassembly, function discovery, CFG recovery, imports/exports, strings, and indexed cross-references. x64 unwind ranges from `.pdata` are used when present, and PE import calls are retained as call xrefs even when they use RIP-relative IAT indirection.
- `paper_ai`: a line-oriented MCP-compatible stdio server. AI clients can call the same analysis engine through structured tools without scraping a GUI.

The analysis engine does not run a program, perform symbolic execution, call SMT/Z3, or ask a model to guess program facts. AI is an optional caller of the evidence API.

## Build

The project uses C++20. On Windows, open the folder with Visual Studio 2022 or configure it with CMake. The `paper` desktop target is a native Win32 application and builds directly with MSVC; it does not require Qt. The optional `paper_ai` target has no GUI dependency, but is disabled by default when the goal is to build only the desktop application.

The desktop target is intended to start by double-clicking `paper.exe`. The AI target is intended to be registered as a local stdio tool by the AI client.

The desktop window follows the classic IDA workflow: Functions navigator on the left, IDA View-A disassembly in the center, Xrefs/Properties on the right, and Output at the bottom. The shortcut map is in [`docs/GUI_SHORTCUTS_ZH.md`](docs/GUI_SHORTCUTS_ZH.md).

For broader x86-64 decoding, configure with an installed Zydis CMake package and set `PAPER_WITH_ZYDIS=ON`. The built-in decoder remains available as a dependency-free fallback, so the project still builds when Zydis is not installed.

The default desktop-only configuration is `PAPER_BUILD_GUI=ON`, `PAPER_BUILD_AI=OFF`, and `PAPER_BUILD_TESTS=OFF`. In Visual Studio's CMake settings, set `PAPER_BUILD_AI=ON` or `PAPER_BUILD_TESTS=ON` when those extra targets are needed. The GUI uses the native Windows common controls (ListView, TabControl, dock-style panes), so a Qt installation is not required.

```text
PAPER_WITH_ZYDIS=ON
```

When enabled, Zydis is used only behind `X86Decoder`; the function, CFG, xref, and AI query APIs stay unchanged.

## AI connection

`paper_ai` speaks newline-delimited JSON-RPC with the MCP method names `initialize`, `tools/list`, and `tools/call`. The available tools include:

`open_binary`, `module_info`, `list_sections`, `list_functions`, `get_function`, `disassemble`, `read_bytes`, `xrefs_to`, `xrefs_from`, `cfg`, `search_strings`, `search_bytes`, `list_imports`, `list_exports`, `call_graph`, and `analysis_stats`.

An MCP client only needs to register the executable as a local stdio server. The exact executable path depends on the client; no project-specific shell wrapper is required.

Example request after initialization:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_binary","arguments":{"path":"C:\\samples\\demo.exe"}}}
```

Then an AI can request the classic reverse-engineering workflow:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"xrefs_to","arguments":{"address":"0x140001230"}}}
```

All query tools read immutable in-memory indexes after analysis, so xrefs, function lookup, CFG, imports, and disassembly do not rescan the binary. `analysis_stats` reports worker count and elapsed analysis time, while `module_info.runtime_function_count` shows how much unwind metadata was available for function recovery.

