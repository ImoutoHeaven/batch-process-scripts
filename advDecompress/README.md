# advDecompress

一个跨平台（Windows 10 / Debian 12 等）高级批量解压脚本，支持递归扫描目录、自动识别并处理多种归档格式（7z / RAR / ZIP / 自解压 EXE 等），同时提供多线程、传统 ZIP 编码修复、LLM 语言校验、RAR CLI 优先、灵活的解压策略、全局锁等丰富功能，方便在大规模文件清理、备份整理、资源归档等场景下使用。

> **许可：** 本项目采用 MIT 许可证。

---

## 功能特色

* **格式丰富**：内建 7-Zip（须自行安装）作为主解压引擎，可选调用 RAR CLI 处理 RAR/SFX。
* **递归扫描**：可按深度范围过滤子目录，自动判断单卷 / 多卷、SFX、传统编码 ZIP 等复杂情况。
* **灵活策略**：内置 10+ 种解压策略，可根据文件数量、目录深度等自动选择输出结构。
* **传统 ZIP 支持**：自动/手动转码（Shift-JIS、GBK…），可用 LLM 二次校验，彻底解决乱码问题。
* **多线程 & 全局锁**：支持并发解压，配合锁文件避免多实例冲突。
* **成功/失败后处理**：成功或失败的归档可选择删除 / 保留 / 移动到指定目录。
* **跳过规则**：按格式/多卷类型精细跳过无需处理的文件。
* **安全包装**：所有文件系统与子进程操作均带异常捕获与调试开关，日志清晰。

---

## 环境要求

1. Python ≥ 3.8  
2. [7-Zip](https://www.7-zip.org/) 命令行版本（`7z` 或 `7za`）需在 `PATH` 中。  
3. 可选：WinRAR / rar CLI（启用 `--enable-rar` 时使用）。  
4. Python 依赖  
   ```bash
   # 基础依赖（二选一）
   pip install chardet
   # 或
   pip install charset-normalizer

   # 若启用 LLM 语言校验，请再安装
   pip install torch transformers
   ```
   启用 LLM 时脚本将在首次运行时自动下载所需模型，无需额外配置。

---

## 快速开始

```bash
python advDecompress.py <扫描路径> -o <输出目录> -t 4 -v
```

---

## 命令行参数一览

| 位置/选项 | 描述 | 默认值 |
|-----------|------|--------|
| `path` | 扫描的文件或目录（必填） | - |
| `-o`, `--output` | 解压输出目录 | 与 `path` 同级 |
| `-p`, `--password` | 统一密码（单个值） | - |
| `-pf`, `--password-file` | 密码文件（每行一个） | - |
| `-tzp`, `--traditional-zip-policy` | 传统编码 ZIP 处理策略：`move` / `asis` / `decode-auto` / `decode-<编码页>` | `decode-auto` |
| `-tzt`, `--traditional-zip-to` | 当策略为 `move` 时，传统 ZIP 移动目录 | - |
| `-tzdc`, `--traditional-zip-decode-confidence` | `decode-auto` 最低置信度(%) | 90 |
| `-tzdm`, `--traditional-zip-decode-model` | 编码检测模型：`chardet` / `charset_normalizer` | `chardet` |
| `-el`, `--enable-llm` | 启用 LLM 语言校验 | 关闭 |
| `-lc`, `--llm-confidence` | LLM 校验最低置信度(%) | 95 |
| `-er`, `--enable-rar` | 优先使用 RAR CLI 解压 RAR/SFX | 关闭 |
| `-t`, `--threads` | 并行解压线程数 | 1 |
| `-dp`, `--decompress-policy` | 解压策略（下节详述） | `2-collect` |
| `-sp`, `--success-policy` | 解压成功后：`delete` / `asis` / `move` | `asis` |
| `--success-to`, `-st` | `-sp move` 时的目标目录 | - |
| `-fp`, `--fail-policy` | 解压失败后：`asis` / `move` | `asis` |
| `--fail-to`, `-ft` | `-fp move` 时的目标目录 | - |
| `-n`, `--dry-run` | 预览模式，不真正解压 | 关闭 |
| `-v`, `--verbose` | 详细日志 | 关闭 |
| `--skip-7z` / `--skip-rar` / `--skip-zip` / `--skip-exe` | 跳过对应单卷格式 | - |
| `--skip-7z-multi` / `--skip-rar-multi` / `--skip-zip-multi` / `--skip-exe-multi` | 跳过对应多卷格式 | - |
| `--no-lock` | 禁用全局锁（多实例慎用） | 关闭 |
| `--lock-timeout` | 获取锁最大重试次数 | 30 |
| `-dr`, `--depth-range` | 扫描深度范围，如 `0-2` / `1` | 全深度 |
| `--fix-ext`, `-fe` | 启用扩展名修复（按文件头识别） | 关闭 |

---

## 解压策略详解（`-dp/--decompress-policy`）

| 策略名 | 行为说明 |
|---------|----------|
| `separate` | 总在 `<归档名>/` 新建独立文件夹，避免与现有文件冲突。 |
| `direct` | 尝试直接写入目标目录；若文件/文件夹冲突自动回退 `separate`。 |
| `only-file-content` | 仅提取最深层 **file_content**（通常是单一有效文件夹）至 `<归档名>/`。 |
| `only-file-content-direct` | 同上，但若不存在冲突则直接落在目标目录。 |
| `file-content-with-folder` | 提取 **file_content**，并保留其父文件夹名。 |
| `file-content-with-folder-separate` | 在 `separate` 目录内保留父文件夹名。 |
| `N-collect`（如 `2-collect`） | 若提取项目数 ≥ N 则放到 `<归档名>/`，否则按 `direct`。 |
| `file-content-N-collect` | 先定位 **file_content** 后按阈值判断。 |
| `file-content-auto-folder-N-collect-len` | 自动选取最长文件夹名作为目标，再按照阈值判断。 |
| `file-content-auto-folder-N-collect-meaningful` | 自动选取“最有意义”文件夹名（ASCII 过滤）后按阈值判断。 |

> N 为正整数，例如 `5-collect`、`file-content-10-collect`、`file-content-auto-folder-3-collect-len` 等。

---

## 传统 ZIP 策略示例

```bash
# 自动识别编码并解压，置信度低于 88% 则跳过
a python advDecompress.py A.zip -tzp decode-auto -tzdc 88

# 强制按 Shift-JIS 解码传统 ZIP
a python advDecompress.py B.zip -tzp decode-932

# 对所有传统 ZIP 仅移动文件，不做解压
a python advDecompress.py D:\Downloads -tzp move -tzt D:\ZipLegacy
```

---

## 常见使用示例

```bash
# 递归扫描 Downloads，使用 8 线程，解压后大于等于 3 个项目则进入子目录
a python advDecompress.py D:\Downloads -o D:\Unpacked -t 8 -dp 3-collect

# 仅处理第一层目录下的 RAR，并在成功后删除原归档
a python advDecompress.py /data/backups -er -dr 0 -sp delete --skip-zip --skip-7z

# 处理多卷 ZIP，若遭遇传统编码则自动解码
python advDecompress.py archive.zip -tzp decode-auto -enable-rar
```

---

## 退出码

| 代码 | 含义 |
|------|------|
| 0 | 成功结束 |
| 1 | 参数 / 路径错误、未获锁或其他致命错误 |

---

## 调试与日志

* 使用 `-v / --verbose` 可查看详细调试信息。 
* `-n / --dry-run` 可在完全不写盘的前提下预览待处理的归档列表与策略决策。

---

## 已知问题

1. **多线程中断难以终止** → 在启用多线程（`-t` > 1）解压时，若想中途停止任务，使用 `Ctrl+C` 或向进程发送 `SIGTERM` 等信号可能无法立即终止所有线程；建议直接结束 Python 进程，或在启动脚本时避免使用过大的线程数。

---

© 2024 advDecompress. MIT 许可证。