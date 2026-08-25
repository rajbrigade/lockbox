#!/usr/bin/env python3
"""Run the whole suite with no test framework installed.

    python3 run_tests.py            # everything
    python3 run_tests.py offline    # only tests whose module matches "offline"
    python3 run_tests.py -v         # verbose
"""

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbosity = 2 if "-v" in sys.argv else 1
    pattern = f"test*{args[0]}*.py" if args else "test*.py"
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=pattern)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
