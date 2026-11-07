"""xray.py - run exe-xray from a checkout without installing anything.

    python xray.py C:\\Windows\\System32\\notepad.exe
    python xray.py app.exe --json
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from exe_xray.cli import main  # noqa: E402  (path setup must come first)

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
