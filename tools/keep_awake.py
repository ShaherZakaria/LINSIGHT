#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ask Windows not to idle-sleep this machine while a long run is going.

Nothing is configured and nothing is left behind: SetThreadExecutionState is
the same request a media player makes while it is playing, it lasts only as
long as this process, and Windows drops it the moment the process exits. No
power plan is edited, so there is no setting to remember to put back.

What it cannot do is override a VDI broker. A hosted desktop that disconnects
or powers off on its own idle or session policy is being stopped from outside
the guest, and nothing running inside it has a say in that.

    python tools/keep_awake.py            # hold until killed
    python tools/keep_awake.py --hours 4  # hold for four hours, then release
"""

import argparse
import ctypes
import sys
import time

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hours", type=float, default=0,
                    help="release after this many hours (default: until killed)")
    ap.add_argument("--no-display", action="store_true",
                    help="keep the system awake but let the screen blank")
    opts = ap.parse_args()

    if not sys.platform.startswith("win"):
        raise SystemExit("[!] this is a Windows API; on Linux use systemd-inhibit")

    flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    if not opts.no_display:
        flags |= ES_DISPLAY_REQUIRED
    if not ctypes.windll.kernel32.SetThreadExecutionState(flags):
        raise SystemExit("[!] SetThreadExecutionState refused the request")
    print("[+] idle sleep held off (pid %d). Kill this process to release it."
          % __import__("os").getpid(), flush=True)

    try:
        deadline = time.time() + opts.hours * 3600 if opts.hours else None
        while deadline is None or time.time() < deadline:
            time.sleep(30)
    except KeyboardInterrupt:
        pass
    finally:
        # explicit, though the state dies with the process anyway
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        print("[+] released", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
