#!/usr/bin/env python3
"""Unit tests only: never launch systemd, Cargo, or a compositor."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "run_limited", Path(__file__).with_name("run-limited.py"))
limited = importlib.util.module_from_spec(spec)
spec.loader.exec_module(limited)


class LimitedRunnerTests(unittest.TestCase):
    def test_guard_rejects_missing_or_unlimited_controllers(self):
        with tempfile.TemporaryDirectory(prefix="cellward-limits-test-") as directory:
            root = Path(directory)
            with self.assertRaises(OSError):
                limited.verify_limits(root)
            for name, value in (("memory.max", "1073741824"), ("memory.swap.max", "0"),
                                ("pids.max", "64"), ("cpu.max", "100000 100000")):
                (root / name).write_text(value)
            limited.verify_limits(root)
            for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max"):
                path = root / name
                previous = path.read_text()
                path.write_text("max 100000" if name == "cpu.max" else "max")
                with self.assertRaises(ValueError):
                    limited.verify_limits(root)
                path.write_text(previous)

    def test_limits_cover_the_whole_service(self):
        command = limited.command_for(["/bin/true"], Path("/tmp"), "/bin/systemd-run")
        for option in ("MemoryHigh=512M", "MemoryMax=1G", "MemorySwapMax=0",
                       "CPUQuota=100%", "RuntimeMaxSec=900", "KillMode=control-group",
                       "OOMPolicy=kill"):
            self.assertIn("--property=" + option, command)
        self.assertIn("--setenv=CARGO_BUILD_JOBS=1", command)
        self.assertIn("--setenv=RUST_TEST_THREADS=1", command)
        self.assertEqual(command[-2:], ["--", "/bin/true"])

    def test_dry_run_never_spawns(self):
        with patch.object(sys, "argv", ["runner", "--print-command", "--", "true"]), \
             patch.object(limited.shutil, "which", side_effect=["/bin/systemd-run", "/bin/true"]), \
             patch.object(limited.subprocess, "run") as run, \
             patch.dict(limited.os.environ, {"PATH": "/test", "CARGO_TARGET_DIR": "/tmp/test target"}, clear=True), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(limited.main(), 0)
            run.assert_not_called()
            self.assertIn("--setenv=CARGO_TARGET_DIR=/tmp/test target", output.getvalue())

    def test_missing_systemd_has_no_unbounded_fallback(self):
        with patch.object(sys, "argv", ["runner", "--", "true"]), \
             patch.object(limited.shutil, "which", return_value=None), \
             patch.object(limited.subprocess, "run") as run, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                limited.main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()

    def test_manager_failure_is_not_retried_without_limits(self):
        with patch.object(sys, "argv", ["runner", "--", "true"]), \
             patch.object(limited.shutil, "which", side_effect=["/bin/systemd-run", "/bin/true"]), \
             patch.object(limited.subprocess, "run") as run:
            run.return_value.returncode = 1
            self.assertEqual(limited.main(), 1)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][0], "/bin/systemd-run")


if __name__ == "__main__":
    unittest.main()
