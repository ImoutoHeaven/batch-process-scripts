#!/usr/bin/env bash
set -euo pipefail

for tool in 7z rar parpar; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'Missing required binary: %s\n' "$tool" >&2
        exit 1
    }
done

python3 advArchiver/advArchiver.py --help
python3 advArchiver/scripts/build_single_file.py
python3 -m unittest advArchiver.tests.test_build_single_file advArchiver.tests.test_real_cli_guardrails -v
python3 advArchiver/dist/advArchiver.py --help
