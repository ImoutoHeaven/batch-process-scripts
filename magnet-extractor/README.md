# magnet-extractor

递归扫描目录里的 `.torrent` 文件并输出 magnet 链接。
优先尝试原生解析；原生模块不可用或解析失败时自动回退到纯 Python。

## Quickstart

在仓库根目录执行：

```bash
# 扁平输出：所有结果写到同一个 files.magnet.txt
python3 magnet-extractor/magnet_extractor.py /tmp/torf-test -o /tmp/torf-test-flat/files.magnet.txt

# 保留目录结构：每个目录各写一个 files.magnet.txt
python3 magnet-extractor/magnet_extractor.py /tmp/torf-test --keep-dirs -o /tmp/torf-test-keep
```

- 默认模式会把全部 magnet 写到一个固定的 `files.magnet.txt`；不传 `-o` 时写到 `<输入目录>/files.magnet.txt`
- `--keep-dirs` 会按相对目录输出多个固定的 `files.magnet.txt`；不传 `-o` 时直接写回输入目录树
- `-o` 在默认模式下是输出文件路径，在 `--keep-dirs` 下是输出根目录

## Tests

```bash
python3 -m unittest discover -s "magnet-extractor/tests" -p "test_*.py" -v
```

## Native build

如需启用原生解析，在你准备运行脚本的同一个 Python 环境里执行：

```bash
maturin develop --manifest-path magnet-extractor/native/Cargo.toml
```

构建后该环境下的 CLI 会优先尝试原生解析；原生模块不可用或解析失败时仍会回退到纯 Python。
