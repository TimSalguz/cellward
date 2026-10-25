#!/usr/bin/env python3
"""Lightweight checks of the build guard; no compilation or heavy allocations."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'memory_guard', Path(__file__).with_name('run-memory-guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def test_reads_real_proc_format(self):
        self.assertGreater(guard.available(), 0)
        self.assertGreater(guard.group_rss(os.getpgrp()), 0)

    def test_child_gets_kernel_limits_and_one_cpu(self):
        with patch.object(guard.resource, 'setrlimit') as limit, \
             patch.object(guard.os, 'sched_getaffinity', return_value={2, 4}), \
             patch.object(guard.os, 'sched_setaffinity') as affinity, \
             patch.object(guard.os, 'nice'):
            guard.constrain(1536)
            self.assertIn(unittest.mock.call(guard.resource.RLIMIT_AS,
                          (3 * 1024 ** 3, 3 * 1024 ** 3)), limit.call_args_list)
            self.assertIn(unittest.mock.call(guard.resource.RLIMIT_DATA,
                          (1024 ** 3, 1024 ** 3)), limit.call_args_list)
            affinity.assert_called_once_with(0, {2})

    def test_low_available_memory_never_starts_payload(self):
        with patch.object(sys, 'argv', ['guard', '--', 'true']), \
             patch.object(guard, 'available', return_value=1024 ** 3), \
             patch.object(guard.subprocess, 'Popen') as start:
            with self.assertRaises(SystemExit):
                guard.main()
            start.assert_not_called()

    def test_more_than_user_budget_is_rejected(self):
        with patch.object(sys, 'argv', ['guard', '--budget-mib', '5121', '--', 'true']), \
             patch.object(guard.subprocess, 'Popen') as start, \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                guard.main()
            start.assert_not_called()


if __name__ == '__main__':
    unittest.main()
