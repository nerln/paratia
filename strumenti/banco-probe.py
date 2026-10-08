#!/usr/bin/env python3
"""A real child probe: open/fstat only, no file bytes read or printed."""
import argparse
import json
import os
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--file", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--nonce", required=True)
    a = p.parse_args()
    r = {"nonce": a.nonce, "pid": os.getpid(), "ppid": os.getppid(), "uid": os.getuid(),
         "processo": sys.executable, "riuscito": False, "errno": None, "byte": None}
    try:
        fd = os.open(a.file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            r["byte"] = os.fstat(fd).st_size
            r["riuscito"] = True
        finally:
            os.close(fd)
    except OSError as error:
        r["errno"] = error.errno
    fd = os.open(a.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(r, f, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
