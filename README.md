# Paper

Paper is a fast, local, IDA-style static analysis workbench. The v0.2 core is deliberately split into two parts:

- `paper_core`: PE loading, executable-section disassembly, function discovery, CFG recovery, imports/exports, strings, names, comments, bookmarks, persistent sidecar databases, indexed cross-references, direct and relative jump-table facts, bounded block-local data-flow and indirect-target resolution, stack-frame slots, ABI-only function signatures, register-relative object-field accesses, noreturn propagation, MSVC RTTI/vtable mapping, x64 unwind and language-specific exception data, TLS callbacks, relocations, resources, and CodeView/PDB metadata.
- `paper_ai`: a line-oriented MCP-compatible stdio server. AI clients can call the same analysis engine through structured tools without scraping a GUI.

The analysis engine does not run a program, perform symbolic execution, call SMT/Z3, or ask a model to guess program facts. AI is an optional caller of the evidence API.

## Build

The project uses C++20. On Windows, open the folder with Visual Studio 2022 or configure it with CMake. The `paper` desktop target uses Dear ImGui's docking branch with the DirectX 11 backend and builds with MSVC; Qt is not required. CMake fetches a pinned ImGui docking commit automatically when no copy exists in `third_party/imgui`. The optional `paper_ai` target has no GUI dependency, but is disabled by default when the goal is to build only the desktop application.

The desktop target is intended to start by double-clicking `paper.exe`. The AI target is intended to be registered as a local stdio tool by the AI client.

The desktop window follows the classic IDA workflow: Functions navigator on the left, IDA View-A disassembly in the center, Xrefs/Properties and IDA Lists on the right, and Output at the bottom. IDA Lists includes Strings, Names, Imports, Exports, Segments, and Bookmarks. Names, repeatable comments, and bookmarks can be edited in Properties and saved next to the input as `<image>.paper.json`. The Dear ImGui docking layout is styled as a dark reverse-engineering workbench. The shortcut map is in [`docs/GUI_SHORTCUTS_ZH.md`](docs/GUI_SHORTCUTS_ZH.md).

For broader x86-64 decoding, configure with an installed Zydis CMake package and set `PAPER_WITH_ZYDIS=ON`. The built-in decoder remains available as a dependency-free fallback, so the project still builds when Zydis is not installed.

The default desktop-only configuration is `PAPER_BUILD_GUI=ON`, `PAPER_BUILD_AI=OFF`, and `PAPER_BUILD_TESTS=OFF`. The only desktop dependency is the Windows SDK's DirectX 11 libraries. If the machine has network access, CMake automatically fetches Dear ImGui; a local copy may be placed in `third_party/imgui` and automatic fetching can be disabled with `PAPER_FETCH_IMGUI=OFF`. Set `PAPER_BUILD_AI=ON` or `PAPER_BUILD_TESTS=ON` only when those extra targets are needed.

For MSVC, keep the standard configuration split: **Debug** uses `/Od` and `/RTC1`, while **Release** uses `/O2` and must not use `/RTC1`. Do not add `/O2` to the Debug property sheet; MSVC rejects `/RTC1` together with `/O2` and will rewrite `/Od` when both are present. A clean CMake configure is recommended after changing configuration properties.

```text
PAPER_WITH_ZYDIS=ON
```

When enabled, Zydis is used only behind `X86Decoder`; the function, CFG, xref, and AI query APIs stay unchanged.

## AI connection

`paper_ai` speaks newline-delimited JSON-RPC with the MCP method names `initialize`, `tools/list`, and `tools/call`. The available tools include:

`open_binary`, `module_info`, `list_sections`, `list_segments`, `list_functions`, `get_function`, `disassemble`, `read_bytes`, `read_struct`, `describe_address`, `xrefs_to`, `xrefs_from`, `cfg`, `search_strings`, `list_strings`, `find_instructions`, `source_locations`, `search_bytes`, `list_imports`, `list_exports`, `list_names`, `list_bookmarks`, `list_vtables`, `vtable_of`, `function_strings`, `list_runtime_functions`, `list_switches`, `stack_variables`, `function_dataflow`, `function_signature`, `object_fields`, `function_xrefs`, `analyze_function`, `list_noreturn_functions`, `list_rtti`, `list_exceptions`, `list_tls_callbacks`, `list_relocations`, `list_resources`, `pdb_info`, `load_symbols`, `list_symbols`, `call_graph`, `set_name`, `set_comment`, `set_bookmark`, `save_database`, `load_database`, `diff_binary`, `export_annotations`, `import_annotations`, `export_snapshot`, `decode_asset`, and `analysis_stats`.

### EXE 更新与快照身份

Paper 不把地址当作跨版本身份。`module_info` 会返回：

- `sha256`：整个 PE 文件的精确 SHA-256；
- `text_sha256`：按 PE 节顺序拼接可执行节原始字节后的 SHA-256；
- `pdata_sha256`：异常目录（`.pdata`）原始字节的 SHA-256；
- `identity`：包含路径、架构、镜像基址、镜像大小和上述指纹的稳定对象。

`list_functions`、`get_function` 和快照中的每个函数都会返回 `content_hash`。它由解码后的指令边界和字节计算，并归一化相对分支、RIP 相对位移以及 PE 基址重定位，因此函数移动或整体重定位时仍可匹配；真实指令/常量变化仍会改变哈希。

更新 EXE 时建议按以下顺序操作：

```json
{"tool":"diff_binary","path_a":"out/Sky-old.exe","path_b":"out/Sky-new.exe"}
```

`diff_binary` 按“显式名称 → 函数内容哈希 → 调用邻域 → 函数引用字符串”匹配，返回 `unchanged`、`moved`、`changed`、`added`、`removed` 以及 `address_map`。有歧义的匹配不会猜测。

注解可单独迁移：

```json
{"tool":"export_annotations","path":"out/paper.annotations.json"}
{"tool":"import_annotations","path":"out/paper.annotations.json"}
```

注解文件的每条名称、注释和书签都带有所在函数的 `function_hash` 与函数内偏移。二进制指纹不一致时，Paper 只按唯一函数哈希或显式 `address_map` 迁移；没有可验证证据的条目会跳过并说明原因，不会静默把旧地址写到新 EXE。`save_database` 生成的 `.paper.json` 也使用同一套身份和迁移规则。

需要一次性给下游 AI 或离线工具使用时：

```json
{"tool":"export_snapshot","path":"out/Sky.paper.snapshot.json","include_xrefs":true}
```

快照包含身份、节、函数哈希、导入/导出、`.pdata`、虚表/RTTI、字符串、注解和（可选）完整 xrefs/指令，并在文件顶层保留 `format`/`version`，可直接判断它描述的是哪个 EXE。

`list_vtables` reports read-only data runs containing executable function pointers together with data references that install the table. It also exposes the exact installer count and whether the boundary has two-or-more-installer or RTTI evidence; runs without that evidence are explicitly marked rather than silently presented as a proven table. `vtable_of` maps a known function address to its table slots. `xrefs_to` and `xrefs_from` accept either one `address` or an `addresses` array and now include the decoded instruction and containing function for every site; passing a function start to `xrefs_from` aggregates the function's outgoing references. `find_instructions` searches decoded instruction forms or contiguous sequences, while `source_locations` extracts only byte-proven check/log file, line, and expression tuples. Unknown argument names are rejected instead of silently falling back to a default query.

`search_strings`/`list_strings` support `offset`, `referenced_only`, and a `referenced_by` count. `list_imports` returns a truthful summary object by default (`import_count`, descriptor count, `note`, and `imports`); pass `summary:false` only for the legacy array view. The summary reports the exact `OriginalFirstThunk == 0`/`FirstThunk` source fact. `get_function`, `disassemble`, `function_strings`, and `function_signature` accept `addresses` batches; `list_rtti` omits large method arrays unless `include_methods:true` is requested. Switch discovery is cached per function and probes candidate entry modes before doing a full table scan, so repeated RTTI/switch queries do not rescan a large image.

`read_struct` reads a caller-supplied little-endian layout (`u8/u16/u32/u64`, signed variants, `ptr`, `bytes[N]`, `ascii[N]`, `utf16[N]`, and `[]` arrays) directly from mapped bytes. `describe_address` combines section, function, `.pdata`, string, import thunk, vtable slot, instruction, and two-way xref facts in one response. `vtable_of` accepts an `addresses` batch. `find_instructions` also accepts exact displacement, immediate range, memory-base/index, and capture-field predicates. `source_locations({"all":true})` scans the whole indexed image and reports both total and returned proven locations.

Every tool schema exposes the optional transport argument `output`. For example, `{"tool":"find_instructions","pattern":"lea {reg},[rip+{disp}]","output":"out/scan.json"}` writes the exact JSON result to that path and returns a small status envelope; no Python result-writer is needed. `decode_asset` is the stable query surface for a host-registered C++ decoder for a proprietary format. Paper does not guess an unknown asset grammar: the decoder must be registered by the embedding application and must return its own byte-backed facts.

The recovery queries are evidence-first: direct/relative jump-table entries, block-local constants and indirect targets, tracked RSP/RBP slots, ABI facts, register-relative memory offsets, noreturn edges, RTTI descriptors, vtable installers, and PE directories are returned only when the bytes or metadata prove them. The single-function `analyze_function` call bundles these fast queries for one address. It does not fabricate C/C++ types, symbolic values, inheritance, or missing PDB signatures; an absent fact is omitted rather than represented as a confidence guess.

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

