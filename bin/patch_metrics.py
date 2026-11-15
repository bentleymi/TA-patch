#!/usr/bin/env python3
"""Emit flat numeric patch metrics (one JSON event per cycle)."""
import sys

from patch_common import discover, emit, metrics_payload


def main():
    try:
        data = discover()
    except Exception:
        data = {"status": "absent", "pm": None}
    emit(metrics_payload(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
