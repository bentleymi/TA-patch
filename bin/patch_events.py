#!/usr/bin/env python3
"""Emit one JSON event per cycle describing package-manager patch state."""
import sys

from patch_common import discover, emit


def main():
    try:
        emit(discover())
    except Exception:
        emit({"status": "absent", "pm": None})
    return 0


if __name__ == "__main__":
    sys.exit(main())
