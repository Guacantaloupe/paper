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
5. `disassemble({"address":"0x...","count":80})`：读取局部指令。
6. `xrefs_to({"address":"0x..."})`：查找调用者、跳转来源和 RIP 相对数据引用。
7. `xrefs_from({"address":"0x..."})`：查找当前指令产生的调用、跳转或数据引用。
8. `cfg({"function_address":"0x..."})`：获取基本块和前后继关系。
9. `call_graph({"function_address":"0x...","direction":"callees","depth":2})`：扩展到调用图。
10. `search_strings()`、`list_strings()`、`search_bytes()`：用文本或字节模式定位辅助证据。
11. `list_names()`、`list_bookmarks()`：查看当前数据库中的函数/导入/导出/用户命名和标记。
12. `set_name()`、`set_comment()`、`set_bookmark()`：把已确认的逆向结论写回 Paper 数据库。
13. `save_database()`、`load_database()`：保存或恢复 `<image>.paper.json` 侧车数据库。

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

返回值中的每一项都包含 `from`、`to` 和 `kind`。`kind` 可以是 `call`、`jump`、`conditional_jump` 或 `data`。如果地址是导入表槽位，还会附带 `library!symbol`；即使指令是 `call [rip+IAT]`，也会保留为 `call`，不会被误报成普通数据引用。

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
| `xrefs_to` | 查入向交叉引用 |
| `xrefs_from` | 查出向交叉引用 |
| `cfg` | 基本块、后继和前驱 |
| `search_strings` | ASCII/UTF-16 字符串搜索 |
| `list_strings` | IDA 风格字符串列表 |
| `search_bytes` | 十六进制字节模式搜索，支持 `?` 半字节/通配字节 |
| `list_imports` | 导入 DLL、符号和 IAT 地址 |
| `list_exports` | 导出名称、序号和地址 |
| `list_names` | 函数、导入、导出和用户名称 |
| `list_bookmarks` | 持久化地址标记 |
| `call_graph` | 调用者/被调用者遍历 |
| `set_name` / `set_comment` | 写入或清除地址标注 |
| `set_bookmark` | 写入或清除地址书签 |
| `save_database` / `load_database` | 保存或加载 Paper 分析数据库 |
| `analysis_stats` | 分析时间、线程数和索引规模 |

所有查询都读取已经建立的内存索引。`xrefs_to`、`xrefs_from`、函数查找和 CFG 查询不重新扫描文件；分页参数用于避免大程序把整个结果一次性送给 AI。`module_info.runtime_function_count` 可以用来判断 PE 是否提供了 x64 `.pdata` 函数边界证据；`analysis_stats` 可用来记录多核分析耗时和工作线程数。

如果本地构建启用了 Zydis（CMake 选项 `PAPER_WITH_ZYDIS=ON`），AI 不需要改变任何调用方式：同一组 MCP 工具会自动获得更完整的 x86-64 指令文本和控制流目标。

## 中文界面

Paper 默认使用简体中文界面。通过顶部菜单“视图 → 语言”可以切换到 English；切换不会改变窗口的内部布局 ID，已有 Docking 布局可以继续使用。中文字体会优先尝试 Windows 的 Microsoft YaHei 或 SimSun，并合并到界面和等宽代码字体中。

