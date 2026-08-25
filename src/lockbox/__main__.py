"""Entry point: `python -m lockbox`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
