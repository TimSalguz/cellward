#!/usr/bin/env python3
"""Run local compilation/tests in a bounded user-systemd service.

No fallback to an unbounded process. Run from the host, not a container
without its user bus. Nix daemon builds are NOT children of this service:
resolve dependencies separately; use cargo --offline for compilation.
"""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def verify_limits(root):
    """Refuse to exec the payload if controllers did not apply the limits."""
    for name, maximum in (("memory.max", 1024 ** 3), ("memory.swap.max", 0),
                          ("pids.max", 64)):
        value = (root / name).read_text().strip()
        if value == "max" or int(value) > maximum:
            raise ValueError("ineffective limit: " + name)
    quota, period = (root / "cpu.max").read_text().split()
    if quota == "max" or not 0 < int(quota) <= int(period):
        raise ValueError("ineffective CPU limit")


def guarded_exec(command):
    try:
        group = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                     if line.startswith("0::"))
        root = Path("/sys/fs/cgroup") / group.lstrip("/")
        verify_limits(root)
    except (OSError, ValueError, StopIteration) as error:
        print("Resource limits could not be verified; refusing to start: " + str(error), file=sys.stderr)
        return 125
    os.execvpe(command[0], command, os.environ)


def command_for(command, cwd, executable):
    return [
        executable, "--user", "--wait", "--pipe", "--collect",
        "--service-type=exec", "--quiet",
        "--property=MemoryAccounting=yes",
        "--property=MemoryHigh=512M", "--property=MemoryMax=1G",
        "--property=MemorySwapMax=0", "--property=CPUQuota=100%",
        "--property=TasksMax=64", "--property=Nice=10",
        "--property=RuntimeMaxSec=900", "--property=TimeoutStopSec=5",
        "--property=KillMode=control-group", "--property=OOMPolicy=kill",
        "--working-directory=" + str(cwd),
        "--setenv=CARGO_BUILD_JOBS=1", "--setenv=RUST_TEST_THREADS=1",
        "--", *command,
    ]


def main():
    if sys.argv[1:2] == ["--_guarded-exec"]:
        return guarded_exec(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-command", action="store_true",
                        help="print only; do not contact systemd or launch anything")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    executable = shutil.which("systemd-run")
    if not executable:
        parser.error("systemd-run is unavailable; refusing an unbounded fallback")
    # Resolve the program before crossing into the user manager's environment.
    program = shutil.which(command[0])
    if not program:
        parser.error("command not found: " + command[0])
    command[0] = str(Path(program).absolute())
    command = [sys.executable, str(Path(__file__).resolve()), "--_guarded-exec", *command]
    invocation = command_for(command, Path.cwd(), executable)
    # Preserve explicitly configured build paths, but not arbitrary credentials
    # or unrelated environment from this session.
    for name in ("PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTUP_HOME",
                 "RUSTC", "RUSTC_WRAPPER", "VPN_ZONE_FRAME_FONT",
                 "LIBRARY_PATH", "LD_LIBRARY_PATH", "PKG_CONFIG_PATH"):
        if name in os.environ:
            invocation.insert(-len(command) - 1, "--setenv=" + name + "=" + os.environ[name])
    if args.print_command:
        print(shlex.join(invocation))
        return 0
    return subprocess.run(invocation, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
