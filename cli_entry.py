#!/usr/bin/env python3
"""Entry point for the frozen console executable.

`src/lockbox/__main__.py` uses a package-relative import, which is correct for
`python -m lockbox` but wrong for a frozen script, where the entry file is
executed as top-level `__main__` with no parent package. Hence this shim, which
imports absolutely.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from lockbox.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
