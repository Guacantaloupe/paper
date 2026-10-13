# Paper v0.2 架构

```text
Dear ImGui + DirectX 11 shell ─┐
                           ├── paper_core ── PE image ── parallel decode ── indexes
MCP stdio server ──────────┘                         ├── functions / CFG
                                                     ├── xrefs
                                                     ├── strings / imports / exports
                                                     └── query APIs
```

GUI 的布局模拟经典 IDA 工作区：Functions 导航 dock、IDA View-A/Hex View/Info 标签、Xrefs/Properties dock 和 Output dock。Dear ImGui 的工具栏与菜单共用同一组分析动作，因此 `X`、`Ctrl+G`、CFG、Callers/Callees、Imports/Exports、Hex 和 AI/MCP 都能用按钮或快捷键触发。

`paper_core` 不执行样本，也不依赖符号执行、SMT/Z3 或模型推断。PE 文件被读入后，分析线程按可执行节区并行解码；每个线程只写自己的局部结果，主线程按地址合并并建立哈希索引。这样做能避免在查询阶段重新反汇编，也避免多个线程同时修改全局容器。

当前版本的索引包括：

- 指令地址到指令记录的哈希表；
- 地址到入向/出向 xrefs 的哈希表；
- 函数起点到函数摘要的排序数组和哈希表；
- 函数基本块的前驱/后继关系；
- ASCII、UTF-16、导入和导出表；字符串引用计数和助记符倒排索引。

`paper_ai` 复用这些查询接口，因此 AI 调用和 GUI 点击得到的是同一份证据。`X86Decoder` 可以选择性地接入 Zydis：启用 `PAPER_WITH_ZYDIS=ON` 后，Zydis 负责完整的 x86-64 指令边界、控制流和 RIP 相对操作数格式化；没有安装 Zydis 时仍使用内置回退解码器。两种后端共享同一个 `Instruction` 结构，因此函数、CFG、xref 和 MCP 层不需要分叉。

函数入口优先合并四类证据：入口点/导出、直接 call 和尾跳转、常见 prologue/CET `ENDBR64`，以及 x64 PE `.pdata` 的 runtime-function 范围。`.pdata` 的范围存在时用于收紧函数终点，减少对齐填充被误收进 CFG 的情况。

RIP 相对间接 call/jump 会先按控制流分类，再按数据引用分类。这样 `call [rip+IAT]` 在 `xrefs_to` 中返回 `kind: "call"`，并附带 `library!symbol`，同时参与 `call_graph` 的间接调用遍历。

每条 xref 查询结果都可以回到解码指令和所属函数；`find_instructions` 直接在助记符/操作数事实上做模式或连续序列匹配，`source_locations` 使用有界寄存器状态从 check/log 调用前的字符串与立即数恢复源码位置。跳表结果按函数缓存，RTTI 默认只返回类/继承事实，方法槽只有显式请求时才展开；虚表边界同时暴露 installer 数量和 RTTI 证据，避免把相邻表静默合并成一个确定事实。

