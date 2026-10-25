#!/usr/bin/env python3
"""Explicit conservative alternative when user-systemd is unavailable.

Unlike run-limited.py this is NOT a kernel-enforced aggregate cgroup limit.
By default each process inherits 3 GiB address and 1 GiB data limits. A 5 ms
watchdog kills the private process group at 1.5 GiB summed RSS, below 3 GiB
host MemAvailable, or after 10 minutes. CPU affinity is one logical CPU.
An explicit --budget-mib can adjust the limits, never above 5120 MiB RSS.
An explicit --reserve-mib can choose a 2048..8192 MiB host reserve; the
default remains 3072 MiB and is never lowered automatically.
The RSS threshold is sampled, not a hard ceiling, and cannot disable swap.
Use only trusted offline compilation or tests which keep all children in
this process group; never Nix builds or VM tests.
"""
import os
import argparse
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time


def constrain(budget):
    address = max(3072, budget * 2) * 1024 ** 2
    data = budget * 2 // 3 * 1024 ** 2
    resource.setrlimit(resource.RLIMIT_AS, (address, address))
    resource.setrlimit(resource.RLIMIT_DATA, (data, data))
    resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    os.nice(10)


def available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise RuntimeError('MemAvailable unavailable')


def group_rss(group):
    total = 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # /proc/stat comm may contain spaces and closing parentheses.
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == group:
                total += int(fields[21]) * os.sysconf('SC_PAGE_SIZE')
        except (FileNotFoundError, ProcessLookupError):
            pass
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--budget-mib', type=int, default=1536)
    parser.add_argument('--reserve-mib', type=int, default=3072,
                        help='host MemAvailable reserve, 2048..8192 MiB (default: 3072)')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 128 <= args.budget_mib <= 5120:
        parser.error('budget must be 128..5120 MiB; never raise automatically')
    if not 2048 <= args.reserve_mib <= 8192:
        parser.error('host reserve must be 2048..8192 MiB; never lower automatically')
    reserve = args.reserve_mib * 1024 ** 2
    command = args.command
    if command[:1] == ['--']:
        command = command[1:]
    if not command:
        raise SystemExit('command required')
    if available() < reserve:
        raise SystemExit(f'Not starting: less than {args.reserve_mib} MiB MemAvailable')
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    env = dict(os.environ, CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1')
    child = subprocess.Popen(command, start_new_session=True,
                             preexec_fn=lambda: constrain(args.budget_mib), env=env)
    started, peak = time.monotonic(), 0
    try:
        while child.poll() is None:
            rss = group_rss(child.pid)
            peak = max(peak, rss)
            if rss > args.budget_mib * 1024 ** 2 or available() < reserve or time.monotonic() - started > 600:
                print('Memory/time guard: stopping this build process group', file=sys.stderr)
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                return 125
            time.sleep(.005)
        return child.returncode if child.returncode >= 0 else 128 - child.returncode
    finally:
        # No detached build children may survive the wrapper's exit.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        print(f'Build-tree peak sampled RSS: {peak // 1024 ** 2} MiB', file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
