# Paper GUI：IDA 风格布局与快捷操作

Paper v0.2 的桌面窗口使用 Dear ImGui Docking，按经典 IDA 工作方式组织：左侧是 Functions 导航，中间是 IDA View-A 反汇编，顶部是深色快捷工具栏，右侧是 Xrefs/Properties 和 IDA Lists，底部是 Output。`Hex View-1`、`Info`、`Graph View` 是中间的可切换标签。IDA Lists 包含 Strings、Names、Imports、Exports、Segments、Bookmarks。

## 顶部快捷按钮

| 按钮 | 作用 |
|---|---|
| Open | 打开 EXE、DLL 或 SYS |
| Back / Forward | 在已访问的地址之间导航 |
| Go to address | 跳转到十六进制地址 |
| Entry point | 回到 PE 入口点 |
| Xrefs | 查看当前地址的入向/出向交叉引用 |
| CFG | 查看当前函数的基本块和前后继 |
| Callers / Callees | 查看两层调用者或被调用者 |
| Imports / Exports | 切换导入表或导出表 |
| Lists | 打开 Strings、Names、Imports、Exports、Segments、Bookmarks |
| Search | 搜索十六进制字节模式 |
| Hex view | 查看当前地址附近的十六进制和 ASCII |
| AI / MCP | 显示 `paper_ai.exe` 的本地 MCP 配置和推荐调用顺序 |

## 键盘快捷键

| 快捷键 | 操作 |
|---|---|
| `Ctrl+O` | 打开文件 |
| `Alt+Left` / `Alt+Right` | 后退/前进 |
| `Ctrl+G` | 跳转地址 |
| `Home` | 入口点 |
| `X` | Xrefs |
| `Ctrl+Shift+F` | CFG |
| `Ctrl+Shift+U` / `Ctrl+Shift+D` | Callers / Callees |
| `Ctrl+I` / `Ctrl+E` | Imports / Exports |
| `Ctrl+Shift+S` | Strings list |
| `Ctrl+F` | 打开十六进制字节搜索 |
| `Shift+F4` | Names list |
| `Ctrl+B` | 当前地址添加/移除书签 |
| `Ctrl+S` | 保存 `<image>.paper.json` |
| `Ctrl+H` | Hex view |
| `F1` | AI / MCP 使用方法 |

点击右侧 Xrefs 项会直接跳到引用指令或目标地址；点击中央反汇编行会同步刷新右侧 Xrefs。左侧 Functions 搜索框可以按名称过滤函数。Properties 中的 Rename、Comment、Bookmark 会写入与 `paper_ai.exe` 共用的内存数据库，按 `Ctrl+S` 持久化。窗口支持 Dear ImGui Docking，可拖动面板调整为自己的 IDA 工作区。

GUI 只调用 `paper_core` 的静态索引，不执行样本；AI 通过 `paper_ai.exe` 复用同一份证据。
