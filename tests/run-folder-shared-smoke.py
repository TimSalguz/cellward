#!/usr/bin/env python3
"""Run shared-mount tests and verify write-through from outside the namespace."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    for name in ("tests-binary", "core", "bwrap", "unshare"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    for kind in ("private", "layer"):
        root = Path(tempfile.mkdtemp(prefix="cw-shared-" + kind + "-"))
        home = root / "home"
        home.mkdir()
        runtime = root / "runtime"
        runtime.mkdir(mode=0o700)
        env = dict(os.environ,
            CW_FOLDER_TEST_HOME=str(home), CW_FOLDER_TEST_KIND=kind,
            CW_FOLDER_CORE=args.core, CW_FOLDER_UNSHARE=args.unshare,
            CW_FOLDER_BWRAP=args.bwrap, CW_FOLDER_PYTHON=sys.executable,
            XDG_RUNTIME_DIR=str(runtime))
        print(f"{kind}: {root}", flush=True)
        command = [args.unshare, "--user", "--map-current-user", "--keep-caps",
            "--mount", "--propagation", "private", "--", args.tests_binary,
            "--ignored", "--exact",
            "folder_rules::shared_mount_tests::concurrent_launches_use_the_same_folder_and_home_mounts",
            "--test-threads=1", "--nocapture"]
        result = subprocess.run(command, env=env, capture_output=True,
            text=True, timeout=45)
        (root / "result.log").write_text(result.stdout + result.stderr)
        print(result.stdout + result.stderr, flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)
        # These checks run in the original host mount namespace. Internal
        # coherence alone cannot prove that a Real rule bypasses the HOME layer.
        for name in ("one", "two"):
            assert (home / "Projects/shared" / name).read_text() == "real", (
                f"{kind}: real folder did not write through to host")
            assert not (home / "Projects" / name).exists(), (
                f"{kind}: overlay write escaped to host")
            assert not (home / "Projects/shared/cache" / name).exists(), (
                f"{kind}: nested overlay write escaped to host")
            assert not (home / ("root-" + name)).exists(), (
                f"{kind}: private HOME write escaped to host")
        assert not (home / "Projects/reference/bad").exists()


if __name__ == "__main__":
    main()
