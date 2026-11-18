"""tests/test_logging_module.py

autostream_logging imports with the standard library alone (the dial ships it
without the configuration module) and installs one queue handler on the root
logger.  Each case runs in a fresh interpreter so the root logger is the
process's own.
"""
import subprocess
import sys
import textwrap
from pathlib import Path

_CORE = str(Path(__file__).parent.parent / "core")


def _run(script: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True, text=True, timeout=60,
        env={"PYTHONPATH": _CORE, "PATH": ""},
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_imports_without_the_configuration_module():
    out = _run("""
        import sys
        sys.modules["autostream_config"] = None
        import autostream_logging
        print(autostream_logging.get_live_platform_log_level())
    """)
    assert out == "warning"


def test_setup_installs_exactly_one_queue_handler(tmp_path):
    log_file = tmp_path / "logs" / "app.log"
    out = _run(f"""
        import logging
        import autostream_logging
        autostream_logging.setup_logging({str(log_file)!r}, "info")
        from logging.handlers import QueueHandler
        root = logging.getLogger()
        print(sum(isinstance(h, QueueHandler) for h in root.handlers),
              len(root.handlers), autostream_logging.get_live_platform_log_level())
    """)
    assert out == "1 1 info"


def test_update_live_log_level_changes_the_reported_level():
    out = _run("""
        import logging
        import autostream_logging
        print(autostream_logging.update_live_log_level("DEBUG"),
              autostream_logging.get_live_platform_log_level(),
              logging.getLogger().level == logging.DEBUG)
    """)
    assert out == "debug debug True"


def test_setup_limits_the_queue_handler_but_not_lifecycle_lines(tmp_path):
    log_file = tmp_path / "app.log"
    out = _run(f"""
        import logging, time
        import autostream_logging
        autostream_logging.setup_logging({str(log_file)!r}, "info")
        from autostream_sysutils import log_lifecycle
        for _ in range(20):
            logging.warning("flood")
            log_lifecycle("lifecycle line")
        time.sleep(0.5)
        text = open({str(log_file)!r}).read()
        print("RESULT", text.count("flood"), text.count("lifecycle line"))
    """)
    assert out.splitlines()[-1] == "RESULT 5 20"
