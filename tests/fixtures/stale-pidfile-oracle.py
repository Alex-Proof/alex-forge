#!/usr/bin/env python3
"""Independent state oracle for the clear-stale-pidfile fixture.

Deliberately implemented separately from the generated repair script in
src/modes/repair/actions.ts: a different language (Python instead of POSIX sh), a different
liveness check (os.kill(pid, 0), the standard POSIX idiom for "does this PID exist" without
sending a real signal) rather than shelling out to the same /proc-reading approach the generated
script itself uses, and no shared code with the artifact builder.

The fault this action targets is narrowly "a stale PID file is blocking startup" -- NOT "a second
instance is running". Those are different states and must never be conflated:
  - PID file absent: no fault, nothing to clean.
  - PID file present and its PID IS alive: a real second instance may be running. This is not a
    fault Forge's free-tcp-port-style cleanup should touch, so it also reports "no fault".
  - PID file present and its PID is NOT alive: a stale lock file. This is the one state this
    action may clean up.

Exit 0 = target state holds (no stale pidfile blocking startup: file absent OR its process is
genuinely alive). Exit 1 = fault present (a confirmed-stale pidfile). Exit 2 = the oracle itself
could not determine the state reliably.
"""
import os
import sys


def pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists, just owned by someone else -- still alive.
        return True
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: stale-pidfile-oracle.py <pidfile-path>", file=sys.stderr)
        return 2

    pidfile_path = sys.argv[1]

    if not os.path.exists(pidfile_path):
        print('{"oracle":"stale-pidfile","state":"absent"}')
        return 0

    try:
        with open(pidfile_path, "r", encoding="utf-8") as handle:
            raw = handle.read().strip()
        pid = int(raw)
    except (OSError, ValueError) as error:
        print(f'{{"oracle":"stale-pidfile","error":"{error}"}}', file=sys.stderr)
        return 2

    if pid_is_alive(pid):
        print(f'{{"oracle":"stale-pidfile","state":"alive","pid":{pid}}}')
        return 0

    print(f'{{"oracle":"stale-pidfile","state":"stale","pid":{pid}}}')
    return 1


if __name__ == "__main__":
    sys.exit(main())
