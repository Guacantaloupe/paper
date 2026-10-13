# Paper

Paper is a fast, local, IDA-style static analysis workbench. The v0.2 core is deliberately split into two parts:

- `paper_core`: PE loading, executable-section disassembly, function discovery, CFG recovery, imports/exports, strings, names, comments, bookmarks, persistent sidecar databases, indexed cross-references, direct-pointer switch tables, bounded stack/data-flow facts, noreturn propagation, MSVC RTTI, x64 unwind metadata, TLS callbacks, relocations, resources, and CodeView/PDB metadata.
- `paper_ai`: a line-oriented MCP-compatible stdio server. AI clients can call the same analysis engine through structured tools without scraping a GUI.

The analysis engine does not run a program, perform symbolic execution, call SMT/Z3, or ask a model to guess program facts. AI is an optional caller of the evidence API.

## Build

The project uses C++20. On Windows, open the folder with Visual Studio 2022 or configure it with CMake. The `paper` desktop target uses Dear ImGui's docking branch with the DirectX 11 backend and builds with MSVC; Qt is not required. CMake fetches a pinned ImGui docking commit automatically when no copy exists in `third_party/imgui`. The optional `paper_ai` target has no GUI dependency, but is disabled by default when the goal is to build only the desktop application.

The desktop target is intended to start by double-clicking `paper.exe`. The AI target is intended to be registered as a local stdio tool by the AI client.

The desktop window follows the classic IDA workflow: Functions navigator on the left, IDA View-A disassembly in the center, Xrefs/Properties and IDA Lists on the right, and Output at the bottom. IDA Lists includes Strings, Names, Imports, Exports, Segments, and Bookmarks. Names, repeatable comments, and bookmarks can be edited in Properties and saved next to the input as `<image>.paper.json`. The Dear ImGui docking layout is styled as a dark reverse-engineering workbench. The shortcut map is in [`docs/GUI_SHORTCUTS_ZH.md`](docs/GUI_SHORTCUTS_ZH.md).

For broader x86-64 decoding, configure with an installed Zydis CMake package and set `PAPER_WITH_ZYDIS=ON`. The built-in decoder remains available as a dependency-free fallback, so the project still builds when Zydis is not installed.

The default desktop-only configuration is `PAPER_BUILD_GUI=ON`, `PAPER_BUILD_AI=OFF`, and `PAPER_BUILD_TESTS=OFF`. The only desktop dependency is the Windows SDK's DirectX 11 libraries. If the machine has network access, CMake automatically fetches Dear ImGui; a local copy may be placed in `third_party/imgui` and automatic fetching can be disabled with `PAPER_FETCH_IMGUI=OFF`. Set `PAPER_BUILD_AI=ON` or `PAPER_BUILD_TESTS=ON` only when those extra targets are needed.

```text
PAPER_WITH_ZYDIS=ON
```

When enabled, Zydis is used only behind `X86Decoder`; the function, CFG, xref, and AI query APIs stay unchanged.

## AI connection

`paper_ai` speaks newline-delimited JSON-RPC with the MCP method names `initialize`, `tools/list`, and `tools/call`. The available tools include:

`open_binary`, `module_info`, `list_sections`, `list_segments`, `list_functions`, `get_function`, `disassemble`, `read_bytes`, `xrefs_to`, `xrefs_from`, `cfg`, `search_strings`, `list_strings`, `search_bytes`, `list_imports`, `list_exports`, `list_names`, `list_bookmarks`, `list_vtables`, `vtable_of`, `function_strings`, `list_runtime_functions`, `list_switches`, `stack_variables`, `function_dataflow`, `list_noreturn_functions`, `list_rtti`, `list_exceptions`, `list_tls_callbacks`, `list_relocations`, `list_resources`, `pdb_info`, `load_symbols`, `list_symbols`, `call_graph`, `set_name`, `set_comment`, `set_bookmark`, `save_database`, `load_database`, and `analysis_stats`.

`list_vtables` reports read-only data runs containing executable function pointers together with data references that install the table. `vtable_of` maps a known function address to its table slots. `xrefs_to` and `xrefs_from` accept either one `address` or an `addresses` array; passing a function start to `xrefs_from` aggregates the function's outgoing references. Unknown argument names are rejected instead of silently falling back to a default query.

The recovery queries are evidence-first: direct-pointer jump tables, tracked RSP/RBP slots, constants, indirect targets, noreturn edges, RTTI descriptors, and PE directories are returned only when the bytes or metadata prove them. Relative jump tables, variable types, inheritance, or missing PDB symbols are not filled with confidence guesses.

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

