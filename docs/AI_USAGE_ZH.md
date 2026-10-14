# 让 AI 使用 Paper

Paper 的 AI 接口是一个本地 MCP stdio 服务器。AI 客户端启动 `paper_ai.exe` 后，通过标准输入输出交换一行一条 JSON-RPC 消息。Paper 自己完成 PE 解析和静态索引，AI 只负责提出查询、组织证据和解释结果。

服务器遵循 MCP 初始化顺序：客户端发送 `initialize`，收到响应后发送 `notifications/initialized`，再调用 `tools/list` 和 `tools/call`。`ping` 可用于健康检查。通知消息不会产生输出；协议错误会返回标准 JSON-RPC `error` 对象。中文函数名、注释和路径支持 UTF-8 及 JSON `\\uXXXX` 转义。

## 注册方式

在支持 MCP 的客户端配置一个本地服务器，直接指向编译出来的 `paper_ai.exe`：

```json
{
  "mcpServers": {
    "paper": {
      "command": "C:\\Paper\\paper_ai.exe",
      "args": []
    }
  }
}
```

不需要为 Paper 写 PowerShell、CMD 或 Linux 启动脚本。桌面程序 `paper.exe` 用于人工浏览，`paper_ai.exe` 作为 AI 客户端的本地工具进程。

## 推荐调查顺序

AI 接到一个逆向任务后，可以按下面的顺序调用：

1. `open_binary({"path":"..."})`：打开 EXE、DLL 或 SYS，并建立一次索引。
2. `module_info()`、`list_sections()`/`list_segments()`：确认架构、镜像基址、入口点和可执行区间。
3. `list_exports()`、`list_imports()`：先利用已有符号确定模块边界和 API 角色。
4. `list_functions()`：获取函数地址、名称、范围和基本块数量。
5. `disassemble({"address":"0x...","count":80})`：读取局部指令；多个函数可一次传 `addresses:[...]`。
6. `read_struct({"address":"0x...","layout":[["u32","tag"],["u32","count"],["u64[]","entries"]],"entries_count":8})`：按显式布局读取结构，不再为每个资产/目录写 `read_bytes + struct.unpack` 脚本。
7. `describe_address({"address":"0x..."})`：一次返回节区、函数、`.pdata`、字符串、导入桩、虚表槽和双向 xref 事实。
8. `xrefs_to({"address":"0x..."})`：查找调用者、跳转来源和 RIP 相对数据引用；每项同时给出解码指令、寄存器、位移和所属函数。
9. `xrefs_from({"address":"0x..."})`：查找当前指令产生的调用、跳转或数据引用。
10. `cfg({"function_address":"0x..."})`：获取基本块和前后继关系。
11. `call_graph({"function_address":"0x...","direction":"callees","depth":2})`：扩展到调用图。
12. `search_strings()`、`list_strings()`、`search_bytes()`：用文本或字节模式定位辅助证据；字符串项带 `referenced_by`，可用 `referenced_only:true` 和 `offset` 分页。
13. `list_names()`、`list_bookmarks()`：查看当前数据库中的函数/导入/导出/用户命名和标记。
14. `list_vtables()`、`vtable_of()`：枚举只读数据中的函数指针表，并把虚函数地址映射到表槽位；`list_vtables` 对 `installer_count==0` 明确标记 `suspicious`。
15. `find_instructions({"pattern":"lea {reg},[rip+{disp}]","target_in":["0x..."],"displacement":0,"memory_base":"rsp","capture":["register","target"]})`：按解码后的指令形式、操作数谓词或 `sequence:[...]` 查询，不必手写机器码扫描器。
16. `source_locations({"all":true})`：扫描完整镜像，返回 `function_count`、总 `location_count` 与可选 `limit` 截断后的 locations；默认地址查询仍保持单函数快速路径。
17. `function_strings()`：列出单个函数直接引用的字符串，也接受 `addresses` 批量查询。
18. `list_runtime_functions()`：导出 x64 PE `.pdata` 的运行时函数范围。
19. `list_switches({"function_address":"0x..."})`：恢复有直接指针证据的 `jmp [index*8+table]` 跳转表和 case 目标；结果按函数缓存。
20. `stack_variables({"function_address":"0x..."})`：按已追踪的 RSP/RBP 相对访问列出栈槽，不猜变量类型。
21. `function_dataflow({"function_address":"0x..."})`：执行有限的直线常量传播和间接调用目标解析。
22. `function_signature({"function_address":"0x..."})`：只返回架构/ABI 寄存器和已证明的栈槽，不猜 C/C++ 类型，也接受 `addresses` 批量查询。
23. `object_fields({"function_address":"0x..."})`：列出以 ABI 参数寄存器为基址的精确内存偏移和读写证据。
24. `function_xrefs({"function_address":"0x..."})`：一次取得函数出入向 xrefs 和字符串引用。
25. `analyze_function({"function_address":"0x..."})`：单函数快速总入口，组合 CFG、数据流、栈槽、签名、字段、xrefs、字符串和跳表。
26. `list_noreturn_functions()`：列出由已知终止 API、可传播包装函数或明确陷阱证明为 noreturn 的函数。
27. `list_rtti()`：从已确认的虚表前置 Complete Object Locator 读取 MSVC RTTI 类名和基类数组；只有显式 `include_methods:true` 才展开大型方法槽数组。
28. `list_exceptions()`、`list_tls_callbacks()`、`list_relocations()`、`list_resources()`：读取 PE 异常/展开信息（含已验证的 MSVC FuncInfo）、TLS 回调、基址重定位和资源叶节点。
29. `pdb_info()`、`load_symbols()`、`list_symbols()`：读取嵌入 CodeView 身份；Windows 下可通过 DbgHelp 加载可用 PDB 符号。
30. `set_name()`、`set_comment()`、`set_bookmark()`：把已确认的逆向结论写回 Paper 数据库。
31. `save_database({"path":"..."})`、`load_database()`：保存或恢复数据库；保存路径可以指向用户可写目录，不必写回 Program Files。
32. `decode_asset({"format":"mesh","path":"..."})`：调用宿主注册的 C++ 资产解码器。Paper 不猜自定义格式；注册的解码器必须自己返回可验证字段。
33. `module_info()`：读取 `sha256`、`text_sha256`、`pdata_sha256` 和组合后的 `identity`，每次更新 EXE 后都应重新确认。
34. `list_functions()` / `get_function()`：每个函数带 `content_hash`，用于跨版本匹配，而不是把旧绝对地址当作身份。
35. `diff_binary({"path_a":"old.exe","path_b":"new.exe"})`：按名称、归一化函数哈希、调用邻域和引用字符串匹配函数，返回 `unchanged`、`moved`、`changed`、`added`、`removed` 和 `address_map`。
36. `export_annotations()` / `import_annotations()`：导出带二进制身份、函数哈希和函数内偏移的名称/注释/书签；身份不一致时只接受唯一哈希或显式地址映射。
37. `export_snapshot({"path":"out/paper.snapshot.json"})`：一次写出带身份盖章的函数、xrefs、字符串、虚表、RTTI、PE 元数据和注解快照。

## 经典 xrefs 查询

如果 AI 已经从函数列表或反汇编中得到一个地址，例如 `0x140001230`，直接调用：

```json
{
  "jsonrpc": "2.0",
  "id": 20,
  "method": "tools/call",
  "params": {
    "name": "xrefs_to",
    "arguments": {
      "address": "0x140001230",
      "limit": 500
    }
  }
}
```

返回值中的每一项都包含 `from`、`to`、`kind`、`instruction` 和 `function`。`instruction` 给出助记符、长度、目标寄存器、RIP 相对事实和原始位移；`function` 给出站点所在函数。`kind` 可以是 `call`、`jump`、`conditional_jump` 或 `data`。如果地址是导入表槽位，还会附带 `library!symbol`；即使指令是 `call [rip+IAT]`，也会保留为 `call`，不会被误报成普通数据引用。

## 类型化读取与结果落盘

`read_struct` 的布局是严格顺序的 little-endian 字段。`u32` 字段名为 `tag` 且四个字节可打印时会显示 FourCC；需要明确地址语义时使用 `ptr`/`address`，`u64[]` 数组会以十六进制地址字符串返回。读取越过节区或使用未知类型会直接返回错误，不会静默猜测。

```json
{
  "address": "0x141d5b4e0",
  "layout": [["u32", "tag"], ["u32", "count"], ["u64[]", "entries"]],
  "entries_count": 8
}
```

所有工具都有可选的 `output` 路径。例如：

```json
{"pattern":"lea {reg},[rip+{disp}]","target_in":["0x141f75506"],"output":"out/scan.json"}
```

服务器会把工具返回值原样写成 JSON；响应另外返回 `{ "ok": true, "output": "...", "binary_identity": {...}, "result": ... }` 状态包。目录必须预先存在，Paper 不执行 shell 或 Python。所有 Paper 直接生成的数据库、注解和快照文件都包含 `identity`；这使得文件脱离当前会话后仍能判断它对应哪一个 EXE。

## 工具清单

| 工具 | 用途 |
|---|---|
| `open_binary` | 打开并索引一个 PE 文件 |
| `module_info` | 架构、基址、入口点、镜像大小 |
| `list_sections` | 节区范围和读写执行权限 |
| `list_segments` | IDA 术语下的段列表（等同于 `list_sections`） |
| `list_functions` | 函数列表和分页 |
| `get_function` | 按地址或名称取得函数摘要 |
| `disassemble` | 从地址读取反汇编指令 |
| `read_bytes` | 从节区读取原始字节 |
| `read_struct` | 按显式 little-endian layout 读取类型化结构和数组 |
| `describe_address` | 一次汇总地址的节区、函数、`.pdata`、字符串、导入、虚表和 xrefs |
| `xrefs_to` | 查入向交叉引用 |
| `xrefs_from` | 查出向交叉引用 |
| `cfg` | 基本块、后继和前驱 |
| `search_strings` | ASCII/UTF-16 字符串搜索、引用计数和分页 |
| `list_strings` | IDA 风格字符串列表、`referenced_only` |
| `find_instructions` | 解码后的指令/连续指令模式查询 |
| `source_locations` | check/log 文件、行号和表达式证据 |
| `search_bytes` | 十六进制字节模式搜索，支持 `?` 半字节/通配字节 |
| `list_imports` | 导入 DLL、符号、IAT 和 thunk 来源；默认 summary 对象，`summary:false` 返回旧数组 |
| `list_exports` | 导出名称、序号和地址 |
| `list_names` | 函数、导入、导出和用户名称 |
| `list_bookmarks` | 持久化地址标记 |
| `list_vtables` | 枚举函数指针表和安装引用 |
| `vtable_of` | 查找函数所属虚表和槽位 |
| `function_strings` | 查询单函数引用的字符串 |
| `decode_asset` | 调用宿主注册的确定性自定义资产解码器 |
| `list_runtime_functions` | 导出 `.pdata` 函数范围 |
| `list_switches` | 恢复有唯一证据的绝对/相对跳转表和 case 目标 |
| `stack_variables` | RSP/RBP 相对栈槽映射 |
| `function_dataflow` | 基本块内有界常量、定义/使用和间接目标 |
| `function_signature` | x64 ABI 与精确栈槽，不猜类型 |
| `object_fields` | 寄存器相对字段偏移和读写引用 |
| `function_xrefs` | 单函数入向/出向 xrefs 和字符串引用 |
| `analyze_function` | 单函数快速综合分析 |
| `list_noreturn_functions` | 终止函数传播结果 |
| `list_rtti` | MSVC RTTI 类名和继承数组 |
| `list_exceptions` | x64 `.pdata` 展开、语言数据和已验证的 MSVC FuncInfo |
| `list_tls_callbacks` | TLS 回调地址 |
| `list_relocations` | PE 基址重定位项 |
| `list_resources` | PE 资源树叶节点 |
| `pdb_info` / `load_symbols` / `list_symbols` | CodeView 身份和可用 PDB 符号 |
| `call_graph` | 调用者/被调用者遍历 |
| `set_name` / `set_comment` | 写入或清除地址标注 |
| `set_bookmark` | 写入或清除地址书签 |
| `save_database` / `load_database` | 保存或加载 Paper 分析数据库 |
| `diff_binary` | 比较两个 EXE，输出函数状态和旧到新地址映射 |
| `export_annotations` / `import_annotations` | 带指纹和函数哈希迁移名称、注释、书签 |
| `export_snapshot` | 一次导出带二进制身份的完整分析快照 |
| `analysis_stats` | 分析时间、线程数和索引规模 |

所有查询都读取已经建立的内存索引。`xrefs_to`、`xrefs_from`、函数查找和 CFG 查询不重新扫描文件；分页参数用于避免大程序把整个结果一次性送给 AI。`module_info.runtime_function_count` 可以用来判断 PE 是否提供了 x64 `.pdata` 函数边界证据；`analysis_stats` 可用来记录多核分析耗时和工作线程数。

`xrefs_to` 和 `xrefs_from` 同时接受单个 `address` 或 `addresses` 数组；当 `xrefs_from` 的地址正好是函数起始地址时，会合并该函数所有指令的出向引用。未知参数会返回错误，不会静默退回默认查询。

如果本地构建启用了 Zydis（CMake 选项 `PAPER_WITH_ZYDIS=ON`），AI 不需要改变任何调用方式：同一组 MCP 工具会自动获得更完整的 x86-64 指令文本和控制流目标。

跳转表、栈槽、数据流、签名和对象字段接口只返回能够从指令、映像数据或 PE 元数据直接验证的关系。无法证明的变量类型、继承关系、C++ 原型或符号不会被填成猜测值；这也是为什么某些压缩、混淆或缺少 PDB 的样本会返回空数组。

## 中文界面

Paper 默认使用简体中文界面。通过顶部菜单“视图 → 语言”可以切换到 English；切换不会改变窗口的内部布局 ID，已有 Docking 布局可以继续使用。中文字体会优先尝试 Windows 的 Microsoft YaHei 或 SimSun，并合并到界面和等宽代码字体中。

