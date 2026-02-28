# ed2k_calculator

给文件或目录生成 115 兼容 ED2K 链接。

输出是日志文件（`.ed2k.log`），每一行一条 ED2K 链接。

## Quickstart

### 1. 环境准备
- Python 3.11 或更高版本

### 2. 最快跑起来
在仓库根目录执行：

```bash
python3 ed2k_calculator/ed2k115_calc.py <输入文件或目录> --out <输出日志或目录>
```

例如：

```bash
python3 ed2k_calculator/ed2k115_calc.py ./input --out ./flat.ed2k.log
```

执行后会生成 `flat.ed2k.log`。

### 3. 常用参数
- `--keep-dirs`：按原目录结构输出多个 `files.ed2k.log`
- `--url-encode`：对文件名做 URL 编码
- `--dry-run`：只预览将处理哪些文件，不写日志和数据库

### 4. 常见用法

```bash
# 目录 -> 单个日志文件
python3 ed2k_calculator/ed2k115_calc.py ./input --out ./flat.ed2k.log

# 目录 -> 按目录结构输出日志
python3 ed2k_calculator/ed2k115_calc.py ./input --out ./out --keep-dirs

# 单文件输入
python3 ed2k_calculator/ed2k115_calc.py ./movie.mkv --out ./movie.ed2k.log

# 先看计划，不实际写入
python3 ed2k_calculator/ed2k115_calc.py ./input --out ./flat.ed2k.log --dry-run
```

## Deploy

下面给两种部署方式，先用 A，够用再上 B。

### A. 纯 Python 部署（推荐）

适合大多数机器，步骤最少。

1. 准备脚本：`ed2k_calculator/ed2k115_calc.py`
2. 在目标机确保有 `python3`
3. 用绝对路径运行

```bash
python3 /opt/ed2k_calculator/ed2k115_calc.py /data/input --out /data/out/flat.ed2k.log
```

你可以把这条命令放到 crontab、systemd timer 或任务平台里周期执行。

### B. 原生加速部署（可选）

当文件很多、希望进一步提速时可以启用。

1. 安装 Rust 与 `maturin`
2. 在项目根目录执行：

```bash
maturin develop --manifest-path ed2k_calculator/native/Cargo.toml
```

完成后脚本会自动尝试使用原生加速；如果原生模块不可用，会自动回退到纯 Python 路径，不影响可用性。

### 部署后自检

```bash
python3 ed2k_calculator/ed2k115_calc.py --help
python3 -m unittest discover -s ed2k_calculator/tests -p "test_*.py" -v
```
