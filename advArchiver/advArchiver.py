import importlib
import sys


package = importlib.import_module("advArchiver")
sys.modules.setdefault("advArchiver.advArchiver", package)


from advArchiver.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
