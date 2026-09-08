# advDecompress_lite

`advDecompress_lite` 是一个面向 Windows 和 Linux 的批量解压命令行工具。它按文件名、格式和分卷关系发现归档，把每个归档组放入独立的临时工作区，完成校验后再按布局策略写入输出目录。

## 依赖

- Python 3.8 或更高版本。
- PATH 中可执行的 7-Zip：`7z` 或 `7zz`。这是运行所需的主解压器。
- 可选的 `rar` 命令。使用 `--enable-rar` 时优先调用它处理 RAR 和 RAR SFX；命令缺失时使用 7-Zip。
- 可选的 `chardet` 或 `charset_normalizer`。传统 ZIP 使用自动编码检测时，选择的检测器需要可导入；检测器不可用、编码不支持或置信度不足时，该 ZIP 会被说明原因并跳过。

程序入口是 `advDecompress_lite/advDecompress_lite.py`，命令从仓库根目录运行即可。

## 快速开始

Windows：

```powershell
py -3 advDecompress_lite\advDecompress_lite.py "D:\incoming" -o "D:\decoded"
```

Linux：

```bash
python3 advDecompress_lite/advDecompress_lite.py ./incoming -o ./decoded
```

`path` 可以是单个归档或目录。目录会递归扫描；`-o/--output` 省略时，目录输入使用输入目录，文件输入使用文件所在目录。递归输入会保留归档相对于输入根目录的父目录结构。

常用操作示例：

```bash
# 预览发现和处理动作；dry-run 不创建解压工作区
python3 advDecompress_lite/advDecompress_lite.py ./incoming -n -v

# 保留密码中的首尾空格；密码文件每行保留内容，只移除行尾符
python3 advDecompress_lite/advDecompress_lite.py ./incoming -p '  pass word  '
python3 advDecompress_lite/advDecompress_lite.py ./incoming -pf ./passwords.txt

# 传统 ZIP 使用明确代码页，或移动到指定目录
python3 advDecompress_lite/advDecompress_lite.py ./incoming -tzp decode-936
python3 advDecompress_lite/advDecompress_lite.py ./incoming -tzp move -tzt ./traditional-zips

# 成功后移动源归档；失败后移动仍存在的源组
python3 advDecompress_lite/advDecompress_lite.py ./incoming \
  -sp move -st ./succeeded -fp move -ft ./failed

# 预览扩展名修复；0 取消大小筛选
python3 advDecompress_lite/advDecompress_lite.py ./incoming -fe -fet 0 -n
```

## 处理与边界

归档发现支持单卷 7z、RAR、ZIP、TAR 和压缩 TAR，7z 数字分卷、RAR `partN` 与旧式 `rNN` 分卷、ZIP `zip+zNN` 分卷、EXE SFX 分卷、RAR SFX 分卷，以及启用 `--detect-elf-sfx` 后的 ELF SFX。缺少主卷的组会作为失败组处理；指定一个分卷作为输入时会解析到它所属的归档组。`--skip-*` 过滤器在分组后跳过相应单卷或多卷组。

运行期的分组、密码候选和命中次数驻留内存；解压内容使用每个任务独立的临时目录。解压及整树校验成功后开始按策略放置；放置过程中失败可能留下已放置内容，并报告位置、执行 FP。SP 移动失败独立报告，不触发 FP。普通完成会清理临时目录。运行模型覆盖单次执行，崩溃后的恢复、续传、回滚和持久执行记录属于当前边界之外。

默认启用全局 HDD 锁，覆盖扫描到源处理完成；`--no-lock` 显式绕过它，跨进程共享输出时由调用方负责协调。`-t/--threads` 控制并发归档任务数，默认值为 1；布局和源处理仍受进程内锁保护。

## CLI 选项

| 选项 | 默认值与作用 |
| --- | --- |
| `-h`, `--help` | 显示帮助。 |
| `path` | 必填；输入文件或目录。 |
| `-o`, `--output` | 输出目录；省略时使用输入目录或输入文件的父目录。 |
| `-p`, `--password` | 一个显式密码，优先于密码文件候选。 |
| `-pf`, `--password-file` | UTF-8 密码文件，每行一个候选；保留空格，去重并按成功命中次数调整后续顺序。 |
| `-tzp`, `--traditional-zip-policy` | `decode-auto`；可选 `asis`、`move`、`decode-CODEPAGE`。 |
| `-tzt`, `--traditional-zip-to` | 传统 ZIP 使用 `move` 时的目标目录。 |
| `-tzdc`, `--traditional-zip-decode-confidence` | `90`；自动 ZIP 编码检测的最低置信度，范围 `0..100`。 |
| `-tzdm`, `--traditional-zip-decode-model` | `chardet`；可选 `chardet` 或 `charset_normalizer`。 |
| `-er`, `--enable-rar` | 默认关闭；RAR CLI 可用时优先使用它。 |
| `-des`, `--detect-elf-sfx` | 默认关闭；启用 ELF SFX 发现。 |
| `-t`, `--threads` | `1`；正整数并发任务数。 |
| `-dp`, `--decompress-policy` | `2-collect`；见下方布局策略表。 |
| `-sp`, `--success-policy` | `asis`；成功布局后保留、删除或移动源组，可选 `asis`、`delete`、`move`。 |
| `-st`, `--success-to` | 成功源组的移动目标；`-sp move` 时必填。 |
| `-fp`, `--fail-policy` | `asis`；失败源组保留或移动，可选 `asis`、`move`。 |
| `-ft`, `--fail-to` | 失败源组的移动目标；`-fp move` 时必填。 |
| `--conflict-mode` | `fail`；输出冲突处理，可选 `fail`、`suffix`。 |
| `-n`, `--dry-run` | 默认关闭；执行发现和动作预览，保留源、输出和临时目录状态。 |
| `-v`, `--verbose` | 默认关闭；输出归档格式、组类型、分卷数等诊断信息。 |
| `--skip-7z`, `--skip-rar`, `--skip-zip`, `--skip-exe`, `--skip-tar` | 跳过对应单卷格式。 |
| `--skip-7z-multi`, `--skip-rar-multi`, `--skip-zip-multi`, `--skip-exe-multi` | 跳过对应多卷格式。 |
| `--no-lock` | 默认启用全局锁；此选项绕过锁。 |
| `--lock-timeout` | `30`；全局锁的最大获取尝试次数，必须为正数。 |
| `-dr`, `--depth-range` | 默认所有深度；可写单个非负深度（如 `2`）或闭区间（如 `1-3`）。 |
| `-fe`, `--fix-ext` | 普通扩展名修复：替换可疑扩展名；与 `-sfe` 互斥。 |
| `-sfe`, `--safe-fix-ext` | 安全扩展名修复：在原文件名后追加归档扩展名；与 `-fe` 互斥。 |
| `-fet`, `--fix-extension-threshold` | `10mb`；修复候选的大小筛选，支持 `k/kb`、`m/mb`、`g/gb`，`0` 取消筛选。 |

扩展名修复先打印预览并等待确认；`--dry-run` 只显示预览。修复完成后，发现、分组和源策略都使用新文件名。

## 输出布局策略

`N` 是十进制整数；普通 `N-collect` 接受 `N >= 0`，文件内容系列要求 `N >= 1`。递归计数同时计算文件和目录，并可在达到阈值时提前停止。

内容根从解压根向下进入“恰好一个子目录且没有文件”的层级，直到当前目录含文件、出现分支，或到达最内层空目录。内容根的项目是 `file-content-*` 策略的布局输入；最深文件夹名指内容根的目录名；内容根等于解压根时，以归档名作为该名称。所有 `file-content-*collect` 策略共享“达到 `N` 时包裹、低于 `N` 时尝试兼容直接合并”的阈值决策，`auto-folder` 系列只改变包裹名的选择。

| `-dp` 值 | 输出行为 |
| --- | --- |
| `separate` | 将完整解压树放入唯一的归档名目录。 |
| `direct` | 顶层项目直接放到输出目录；冲突按 `--conflict-mode` 处理。 |
| `collect` | 顶层项目可直接放置时直接放置；有冲突时整体放入归档名目录。 |
| `N-collect` | 项目总数达到 `N` 时整体放入归档名目录；否则直接放置，`fail` 模式冲突时回退到归档名目录。 |
| `only-file-content` | 找到内容根后，将内容根项目放入唯一的归档名目录。 |
| `only-file-content-direct` | 兼容时直接合并内容根；冲突时回退到归档名目录。 |
| `file-content-with-folder` | 将内容根项目放入唯一的最深文件夹名目录。 |
| `file-content-with-folder-separate` | 使用归档名目录和最深文件夹名两层；两者相同时合并为一层。 |
| `file-content-N-collect` | 使用上述阈值和合并决策；包裹名固定为归档名。 |
| `file-content-auto-folder-N-collect-len` | 使用上述阈值和合并决策；在归档名与最深文件夹名之间按原始名称长度选择，长度相同优先最深文件夹名。 |
| `file-content-auto-folder-N-collect-meaningful` | 使用上述阈值和合并决策；在归档名与最深文件夹名之间按现有 ASCII 非意义字符过滤后的名称长度选择，长度相同优先最深文件夹名。 |
| `file-content-auto-folder-N-collect-meaningful-ent` | 使用上述阈值和合并决策；在归档名与最深文件夹名之间按现有意义字符与熵加权分数选择，分数相同优先最深文件夹名。 |

`direct` 在同名文件或目录冲突时，`fail` 报错，`suffix` 为整项生成唯一后缀；低于阈值的普通 `N-collect` 在 `fail` 冲突时改用归档名容器，在 `suffix` 时按 `direct` 处理。`collect` 和内容直接合并类策略发生冲突时使用唯一包裹容器，即使选择 `suffix`。目录合并会保留已有空目录，输出树在移动前完成一次整体安全校验。

## 密码、ZIP 与源策略

密码探测使用 7-Zip 的列表或测试命令，批量运行时按显式密码和密码文件自动尝试候选。显式密码先尝试；密码文件候选保留每行的空格，只移除 `CR/LF`，空行省略。成功候选的命中数只在本次运行内调整排序。

传统 ZIP 的 `decode-auto` 仅接受支持的编码和达到 `-tzdc` 最低置信度的检测结果。检测器缺失、编码不可用或置信度不足时，任务状态为跳过，源文件保留且 SP/FP 不执行。`-tzp asis` 保留整个传统 ZIP 组并跳过解压；`-tzp move` 将整个组移动到 `-tzt`，SP/FP 不执行；`-tzp decode-CODEPAGE` 使用指定代码页解码。

成功策略（SP）在完整解压、校验和布局成功后执行：

- `asis` 保留全部源卷。
- `delete` 尝试删除全部源卷；删除失败打印警告，解压结果仍保持成功。
- `move` 将完整源组移动到 `-st`，保持卷文件名和输入父目录结构；目标冲突时为整组选择唯一容器。

失败策略（FP）处理密码耗尽、主卷缺失、解压或校验失败、布局失败等失败组：

- `asis` 保留现有源组。
- `move` 将仍存在的组成员移动到 `-ft`；移动失败会保留错误位置并返回非零退出码。

跳过状态和传统 ZIP 移动各自完成对应动作，SP/FP 不执行；扩展名修复预览只显示计划。批处理中的其他归档组继续处理，最终退出码反映失败组和源处理错误。

## 结果与检查

运行结束时输出发现数量、成功数、失败数、跳过数、移动数（如有）、扩展名修复数（如有）、发现/解压/布局/源处理耗时和错误位置。可先使用 `--dry-run --verbose` 检查分组、策略和路径，再执行实际处理。
