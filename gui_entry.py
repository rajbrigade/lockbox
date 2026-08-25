#!/usr/bin/env python3
"""Entry point for the windowed (GUI) executable.

A separate file from `__main__.py` so PyInstaller can build a console binary
and a windowed binary from the same source tree without either dragging in the
other's dependencies.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from lockbox.ui.app import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
