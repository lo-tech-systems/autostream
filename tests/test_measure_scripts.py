"""The memory and CPU measurement scripts print well-formed lines.

The scripts read the coordinator process through /proc and ask systemd for
its PID. Here /proc is a scratch tree (PROC_ROOT) and systemctl, getconf,
sleep and curl are stubs on PATH, so nothing real is measured.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from conftest import bash_can_run_script_at_windows_path  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent
TOOLS = REPO_ROOT / "tools"
SHELL_SCRIPTS = ("measure_memory.sh", "measure_cpu.sh", "measure_setup_hwm.sh")

bash_capable = pytest.mark.skipif(
    not bash_can_run_script_at_windows_path(),
    reason="bash cannot execute scripts at this path (MSYS2 limitation on Windows)",
)

PID = 4242


def _stat_line(utime: int, stime: int) -> str:
    # pid (comm) state, then fields 4 to 13 and utime, stime (fields 14, 15).
    return (f"{PID} (autostream main) S 1 {PID} {PID} 0 -1 4194560 100 0 0 0 "
            f"{utime} {stime} 0 0 20 0 5 0 12345 100000000 5000 18446744073709551615\n")


def _stub(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/bash\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def proc(tmp_path):
    """A fake /proc with one process, and stubs for the tools the scripts call."""
    root = tmp_path / "proc"
    pid_dir = root / str(PID)
    pid_dir.mkdir(parents=True)
    (pid_dir / "status").write_text(
        "Name:\tautostream\nVmHWM:\t   61000 kB\nVmRSS:\t   58000 kB\nThreads:\t17\n",
        encoding="utf-8")
    (pid_dir / "smaps_rollup").write_text(
        "Rss:\t   58000 kB\nPss:\t   52000 kB\nPss_Anon:\t   40000 kB\n", encoding="utf-8")
    (pid_dir / "stat").write_text(_stat_line(100, 50), encoding="utf-8")
    (root / "meminfo").write_text(
        "MemTotal:\t  500000 kB\nMemFree:\t  100000 kB\nMemAvailable:\t  300000 kB\n",
        encoding="utf-8")

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _stub(bin_dir, "systemctl", f'[ "$1 $2 $3 $4" = "show -p MainPID --value" ] && echo {PID}\n')
    _stub(bin_dir, "getconf", 'echo 100\n')
    # The wait between the two CPU readings: advance the process by 4.5 s of
    # CPU instead of sleeping.
    stat_file = pid_dir / "stat"
    _stub(bin_dir, "sleep", f'printf %s {_stat_line(400, 150).strip()!r} > "{stat_file.as_posix()}"\n')
    _stub(bin_dir, "curl", 'exit 0\n')

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir.as_posix()}:{env['PATH']}"
    env["PROC_ROOT"] = root.as_posix()
    return env, root, bin_dir


def _run(script: str, *args: str, env) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(TOOLS / script), *args],
        capture_output=True, text=True, timeout=30, env=env)


@bash_capable
@pytest.mark.parametrize("script", SHELL_SCRIPTS)
def test_the_script_parses(script):
    result = subprocess.run(
        ["bash", "-n", str(TOOLS / script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@bash_capable
class TestMemory:
    def test_prints_one_csv_line_with_every_column(self, proc):
        env, _root, _bin = proc
        result = _run("measure_memory.sh", "--label", "run1", env=env)
        assert result.returncode == 0, result.stderr
        lines = result.stdout.splitlines()
        assert len(lines) == 1
        label, unix_time, rss, hwm, pss, threads, avail = lines[0].split(",")
        assert label == "run1"
        assert unix_time.isdigit() and int(unix_time) > 1_000_000_000
        assert (rss, hwm, pss, threads, avail) == ("58000", "61000", "52000", "17", "300000")

    def test_the_header_names_the_columns_in_order(self, proc):
        env, _root, _bin = proc
        result = _run("measure_memory.sh", "--header", env=env)
        assert result.stdout.strip() == (
            "label,unix_time,VmRSS_kB,VmHWM_kB,Pss_kB,threads,MemAvailable_kB")

    def test_a_missing_label_is_a_usage_error(self, proc):
        env, _root, _bin = proc
        assert _run("measure_memory.sh", env=env).returncode == 2

    def test_an_unreadable_figure_fails_without_printing_a_line(self, proc):
        env, root, _bin = proc
        (root / str(PID) / "smaps_rollup").unlink()
        result = _run("measure_memory.sh", "--label", "run1", env=env)
        assert result.returncode == 1
        assert result.stdout == ""

    def test_a_service_that_is_not_running_fails(self, proc):
        env, _root, bin_dir = proc
        _stub(bin_dir, "systemctl", "echo 0\n")
        assert _run("measure_memory.sh", "--label", "run1", env=env).returncode == 1


@bash_capable
class TestCpu:
    def test_reports_cpu_seconds_and_percent_of_one_core(self, proc):
        env, _root, _bin = proc
        result = _run("measure_cpu.sh", "--label", "idle", "--seconds", "10", env=env)
        assert result.returncode == 0, result.stderr
        # 300 + 100 more ticks at 100 per second, over 10 seconds.
        assert result.stdout.strip() == "idle,10,4.00,40.00"

    def test_the_default_label_and_interval_are_used_when_not_given(self, proc):
        env, _root, _bin = proc
        result = _run("measure_cpu.sh", env=env)
        assert result.stdout.strip().startswith("cpu,600,")

    @pytest.mark.parametrize("seconds", ["0", "-5", "ten", ""])
    def test_a_bad_interval_is_a_usage_error(self, proc, seconds):
        env, _root, _bin = proc
        assert _run("measure_cpu.sh", "--seconds", seconds, env=env).returncode == 2


@bash_capable
class TestSetupHwm:
    def test_prints_the_peak_before_after_and_the_step(self, proc, tmp_path):
        env, root, bin_dir = proc
        jar = tmp_path / "jar"
        jar.write_text("# cookies\n", encoding="utf-8")
        status = root / str(PID) / "status"
        # Each request raises the peak by 500 kB.
        _stub(bin_dir, "curl",
              f'sed -i "s/VmHWM:.*/VmHWM:\\t   61500 kB/" "{status.as_posix()}"\n')
        result = _run("measure_setup_hwm.sh", "--cookie", str(jar), "--label", "s", env=env)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "s,61000,61500,500"

    def test_a_failed_request_is_an_error(self, proc, tmp_path):
        env, _root, bin_dir = proc
        jar = tmp_path / "jar"
        jar.write_text("# cookies\n", encoding="utf-8")
        _stub(bin_dir, "curl", "exit 7\n")
        result = _run("measure_setup_hwm.sh", "--cookie", str(jar), env=env)
        assert result.returncode == 1

    def test_a_missing_cookie_jar_is_a_usage_error(self, proc, tmp_path):
        env, _root, _bin = proc
        result = _run("measure_setup_hwm.sh", "--cookie", str(tmp_path / "none"), env=env)
        assert result.returncode == 2


class TestPageImportHeap:
    def _module(self):
        spec = importlib.util.spec_from_file_location(
            "measure_page_import_heap", TOOLS / "measure_page_import_heap.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_it_names_the_fourteen_page_modules(self):
        module = self._module()
        assert len(module.PAGE_MODULES) == 14
        for name in module.PAGE_MODULES:
            assert (REPO_ROOT / "core" / f"{name}.py").is_file(), name

    def test_it_prints_one_line_of_four_columns(self, capsys, monkeypatch):
        module = self._module()
        monkeypatch.setattr(sys, "path", list(sys.path))
        assert module.main(["--label", "heap", "--core", str(REPO_ROOT / "core")]) == 0
        label, traced, peak, count = capsys.readouterr().out.strip().split(",")
        assert label == "heap"
        assert int(traced) >= 0 and int(peak) >= int(traced)
        assert count == "14"
