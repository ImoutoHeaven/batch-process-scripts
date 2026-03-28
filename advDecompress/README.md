# advDecompress

一个跨平台（Windows 10 / Debian 12 等）高级批量解压脚本，支持递归扫描目录、自动识别并处理多种归档格式（7z / RAR / ZIP / TAR / 自解压 EXE 等），同时提供多线程、传统 ZIP 编码修复、RAR CLI 优先、灵活的解压策略、全局锁等丰富功能，方便在大规模文件清理、备份整理、资源归档等场景下使用。

> **许可：** 本项目采用 MIT 许可证。

---

## 功能特色

* **格式丰富**：内建 7-Zip（须自行安装）作为主解压引擎，可选调用 RAR CLI 处理 RAR/SFX。
* **TAR 系列**：支持 `.tar` / `.tar.gz` / `.tgz` / `.tar.bz2` / `.tbz2` / `.tar.xz` / `.txz`；tarball 会在一次运行中解到最终内容（不会在输出目录留下中间 `.tar`）。
* **递归扫描**：可按深度范围过滤子目录，自动判断单卷 / 多卷、SFX、传统编码 ZIP 等复杂情况。
* **灵活策略**：内置 10+ 种解压策略，可根据文件数量、目录深度等自动选择输出结构。
* **传统 ZIP 支持**：自动/手动转码（Shift-JIS、GBK…），尽量解决乱码问题。
* **多线程 & 全局锁**：支持并发解压，配合锁文件避免多实例冲突。
* **成功/失败后处理**：成功或失败的归档可选择删除 / 保留 / 移动到指定目录。
* **扩展名修复**：智能检测文件头并修复错误扩展名，支持大小阈值过滤以提升处理效率。
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

   ```

---

## 快速开始

```bash
# 基本批量解压
python advDecompress.py <扫描路径> -o <输出目录> -t 4 -v

# 包含扩展名修复的完整用法
python advDecompress.py <扫描路径> -o <输出目录> --fix-ext -fet 500kb -t 4 -v
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
| `--force-clean-tmp` | 强制删除非空临时/中转目录（不安全，不建议） | 关闭 |
| `-er`, `--enable-rar` | 优先使用 RAR CLI 解压 RAR/SFX | 关闭 |
| `-des`, `--detect-elf-sfx` | 启用 ELF SFX 检测（Linux），默认关闭以减少扫描开销 | 关闭 |
| `-t`, `--threads` | 并行解压线程数 | 1 |
| `-dp`, `--decompress-policy` | 解压策略（下节详述） | `2-collect` |
| `-sp`, `--success-policy` | 解压成功后：`delete` / `asis` / `move`（事务模式下 `delete` 会在 durability barrier 成功后才删除源归档；Windows 事务模式需配合 `--unsafe-windows-delete`，并在删除前仅提供 best-effort payload directory durability） | `asis` |
| `--success-to`, `-st` | `-sp move` 时的目标目录 | - |
| `-fp`, `--fail-policy` | 解压失败后：`asis` / `move` | `asis` |
| `--fail-to`, `-ft` | `-fp move` 时的目标目录 | - |
| `-n`, `--dry-run` | 预览模式，不真正解压 | 关闭 |
| `-v`, `--verbose` | 详细日志 | 关闭 |
| `--skip-7z` / `--skip-rar` / `--skip-zip` / `--skip-exe` / `--skip-tar` | 跳过对应单卷格式 | - |
| `--skip-7z-multi` / `--skip-rar-multi` / `--skip-zip-multi` / `--skip-exe-multi` | 跳过对应多卷格式 | - |
| `--no-lock` | 禁用全局锁（多实例慎用） | 关闭 |
| `--lock-timeout` | 获取锁最大重试次数 | 30 |
| `--legacy` | 切回旧版非事务化流程（默认是事务化流程，启用 journal / 恢复；legacy `-sp delete` 不要求 `--unsafe-windows-delete`） | 关闭 |
| `--unsafe-windows-delete` | 仅允许 Windows 事务模式下的 `-sp delete` 继续执行；legacy 模式不依赖此开关 | 关闭 |
| `--degrade-cross-volume` | 允许跨卷降级 copy+delete（降低原子性） | 关闭 |
| `--conflict-mode` | 事务化落位冲突策略：`fail` / `suffix` | `fail` |
| `--no-durability` | 关闭事务模式的 durability barrier；与 `-sp delete` 不兼容 | 关闭 |
| `--fsync-files` | durability 策略：`auto` / `none`；`-sp delete` 下必须为 `auto` | `auto` |
| `--keep-journal-days` | 终态事务 journal 的 GC 保留天数（仍可恢复 / 可重试的记录不会因 TTL 删除） | 7 |
| `-scj`, `--success-clean-journal` | 数据集进入终态且最终全部成功时删除 `.advdecompress_work`（可用 `-scj false` 关闭） | 开启 |
| `-fcj`, `--fail-clean-journal` | 数据集进入终态且存在最终失败时删除 `.advdecompress_work`（可用 `-fcj false` 关闭） | 开启 |
| `-dr`, `--depth-range` | 扫描深度范围，如 `0-2` / `1` | 全深度 |
| `--fix-ext`, `-fe` | 启用扩展名修复（按文件头识别） | 关闭 |
| `--safe-fix-ext`, `-sfe` | 启用安全扩展名修复（追加正确扩展名） | 关闭 |
| `--fix-extension-threshold`, `-fet` | 扩展名修复文件大小阈值，小于此值跳过处理 | `10mb` |

---

> 事务模式下的工作目录统一放在输出根目录的 `.advdecompress_work/` 下，其中 `dataset_manifest.json` 用于记录本轮数据集并驱动严格恢复。
> 默认不会在仍有可恢复 / 可重试状态时清掉该目录；是否删除整个 `.advdecompress_work/` 取决于数据集终态后的 `-scj` / `-fcj`，旧 journal 则按 `--keep-journal-days` 在不影响恢复时回收。
> 若 `.advdecompress_work/` 已存在但缺少 `dataset_manifest.json`，该状态也视为不兼容且不可恢复，需先删除整个 `.advdecompress_work/` 后再重新开始。

## 事务模式说明（默认）

* 默认使用事务化流程；`--legacy` 才会切回旧版非事务化流程。
* 首次运行会把本轮待处理归档列表、顺序与关键参数写入 `.advdecompress_work/dataset_manifest.json`。
* 之后恢复遵循**严格数据集恢复**：只继续 manifest 中已有的归档，不会在恢复时重新发现并纳入后来新增的归档；如需把后来新增的归档也纳入处理，请删除 `.advdecompress_work/` 后重新开始新一轮运行。
* 能直接续跑完成的归档会继续完成，不会重新解压；必须重试的归档只重跑对应单个归档。
* 若命令指纹不一致，或 manifest 记录的归档缺失、大小变化、时间戳变化等，脚本会拒绝恢复，并明确提示先删除 `.advdecompress_work/` 后再重新开始。
* 单个事务一旦成功落位并通过 durability barrier，就会立刻执行该事务自己的成功后处理（例如 `-sp delete` / `-sp move`）；不是 extract 成功后立刻处理源归档，也不再等待整批归档都提取完成。
* `-sp delete` 只有在事务 journal 与已落位输出都通过 durability barrier 后才会删除源归档；因此不能与 `--no-durability` 或 `--fsync-files none` 同用。
* Windows 下的事务模式若要使用 `-sp delete`，必须显式加上 `--unsafe-windows-delete`；此时删除前仍会尝试 payload directory durability，但该部分只提供 best-effort 保证，源归档仍会在事务化落位后删除。
* 同一 `output_dir` 的事务仍通过 `output_dir.lock` 串行落位；多线程下先完成提取的事务可能先落位，因此同目录内的命名/冲突处理顺序可能不同于扫描顺序。
* 多线程只保留受 orchestration window / `--threads` 约束的在途提取任务，不会先把整批归档都提取完再统一落位。
* 因此磁盘峰值主要受并发度与同目录串行点影响，不再随着整批归档数量线性累积。
* `--keep-journal-days` 只会回收已收敛到终态的旧 journal；仍可恢复 / 可重试的记录会保留，避免把恢复现场提前清掉。

## 解压策略详解（`-dp/--decompress-policy`）

| 策略名 | 行为说明 |
|---------|----------|
| `separate` | 总在 `<归档名>/` 新建独立文件夹，避免与现有文件冲突。 |
| `direct` | 尝试直接写入目标目录；事务化模式默认冲突即失败（可用 `--conflict-mode suffix` 自动改名），`--legacy` 才会回退 `separate`。 |
| `collect` | （事务化模式）锁内基于冲突自动选择 `direct` 或 `separate`。 |
| `only-file-content` | 仅提取最深层 **file_content**（通常是单一有效文件夹）至 `<归档名>/`。 |
| `only-file-content-direct` | 同上，但若不存在冲突则直接落在目标目录。 |
| `file-content-with-folder` | 提取 **file_content**，并保留其父文件夹名。 |
| `file-content-with-folder-separate` | 在 `separate` 目录内保留父文件夹名。 |
| `N-collect`（如 `2-collect`） | 若提取项目数 ≥ N 则放到 `<归档名>/`，否则按 `direct`。 |
| `file-content-N-collect` | 先定位 **file_content** 后按阈值判断。 |
| `file-content-auto-folder-N-collect-len` | 自动选取最长文件夹名作为目标，再按照阈值判断。 |
| `file-content-auto-folder-N-collect-meaningful` | 自动选取“最有意义”文件夹名（ASCII 过滤）后按阈值判断。 |
| `file-content-auto-folder-N-collect-meaningful-ent` | 自动选取“最有意义”文件夹名（熵加权评分）后按阈值判断。 |

> N 为正整数，例如 `5-collect`、`file-content-10-collect`、`file-content-auto-folder-3-collect-len`、`file-content-auto-folder-3-collect-meaningful-ent` 等。
>
> 事务化模式（默认）已支持全部解压策略；`--legacy` 仅用于回退旧版流程。
>
---

## 扩展名修复功能详解

脚本支持智能检测归档文件的真实类型并修复错误的扩展名，避免因扩展名错误导致的解压失败。

### 使用方式

| 参数 | 功能 |
|------|------|
| `--fix-ext`, `-fe` | 普通修复模式：替换错误扩展名或为无扩展名文件添加正确扩展名 |
| `--safe-fix-ext`, `-sfe` | 安全修复模式：总是追加正确扩展名，不替换现有扩展名 |
| `--fix-extension-threshold`, `-fet` | 文件大小阈值，小于此值的文件将被跳过 |

### 文件大小阈值格式

* **格式**：`<数字><单位>`，单位支持 `k`/`kb`、`m`/`mb`、`g`/`gb`（大小写不敏感）
* **示例**：`500kb`、`10mb`、`2g`、`1GB`
* **特殊值**：`0` 表示禁用大小过滤，处理所有文件
* **默认值**：`10mb`（小于 10MB 的文件将被跳过）

### 使用示例

```bash
# 启用普通修复模式，使用默认 10MB 阈值，只处理较大的文件
python advDecompress.py /path/to/archives --fix-ext

# 使用安全修复模式，设置 500KB 阈值
python advDecompress.py /path/to/archives --safe-fix-ext -fet 500kb

# 禁用大小过滤，处理所有文件（包括小文件）
python advDecompress.py /path/to/archives --fix-ext -fet 0

# 设置 2GB 阈值，只处理超大文件
python advDecompress.py /path/to/archives --fix-ext -fet 2g
```

### 注意事项

* 扩展名修复需要读取文件头进行类型检测，对于大量小文件可能较耗时
* 设置合适的大小阈值可显著提升处理效率
* 安全修复模式不会覆盖现有扩展名，适合不确定原扩展名正确性的场景
* 修复操作需要用户交互确认，不支持静默批量操作

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

# Windows 事务模式下显式允许 delete
python advDecompress.py D:\Downloads -o D:\Unpacked -sp delete --unsafe-windows-delete

# 处理多卷 ZIP，若遭遇传统编码则自动解码
python advDecompress.py archive.zip -tzp decode-auto -enable-rar

# 启用扩展名修复，只处理大于 500KB 的文件
python advDecompress.py /data/archives --fix-ext -fet 500kb -v

# 启用扩展名修复，处理所有文件（不限大小）
python advDecompress.py /data/archives --fix-ext -fet 0 -v
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
