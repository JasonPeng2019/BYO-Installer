"""Retain actual prior-handler stderr and observe scoped hook restoration."""

import json
import runpy
import sys
import threading
from pathlib import Path


def main():
    helper, directory = sys.argv[1], Path(sys.argv[2])
    sys.argv = [helper, *sys.argv[3:]]
    original = threading.excepthook

    def previous(args):
        record = {
            "error_type": args.exc_type.__name__,
            "message": str(args.exc_value),
            "thread_name": args.thread.name if args.thread else None,
            "thread_ident": args.thread.ident if args.thread else None,
            "native_id": args.thread.native_id if args.thread else None,
        }
        (directory / "prior-handler.json").write_text(json.dumps(record, indent=2) + "\n")
        original(args)

    threading.excepthook = previous
    try:
        runpy.run_path(helper, run_name="__main__")
    finally:
        (directory / "hook-lifetime.json").write_text(
            json.dumps({"previous_handler_restored": threading.excepthook is previous}) + "\n"
        )
        threading.excepthook = original


if __name__ == "__main__":
    main()
