"""dial_config.py — Dial configuration loading and saving.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Two-file split:
  /etc/autostream/autostream-dial.json    — hardware + UUID, root:autostream 0640
  /var/lib/autostream/dial-settings.json — mutable settings, autostream 0600
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

HW_CONFIG_PATH     = Path('/etc/autostream/autostream-dial.json')
SETTINGS_PATH      = Path('/var/lib/autostream/dial-settings.json')
INSTALL_STATE_PATH = Path('/var/lib/autostream/install-state.env')


@dataclass
class DialConfig:
    clk_gpio:     int        = 17
    dt_gpio:      int        = 27
    sw_gpio:      int | None = None
    led_gpio:     int | None = None
    port:         int        = 7842
    uuid:         str        = ''
    step_percent: int        = 2
    name:         str        = ''
    pin:          str        = ''
    auto_update:  bool       = False


def _read_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE env file without executing it."""
    data: dict[str, str] = {}
    try:
        for raw in path.read_text(encoding='utf-8').splitlines():
            line = raw.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, _, v = line.partition('=')
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                v = v[1:-1]
            data[k] = v
    except OSError:
        pass
    return data


def load_config() -> DialConfig:
    """Load hardware config then overlay mutable settings.

    UUID fallback order: dial.json → install-state.env → RuntimeError.
    Never silently generates a new UUID.
    """
    cfg = DialConfig()

    hw = json.loads(HW_CONFIG_PATH.read_text(encoding='utf-8'))
    cfg.clk_gpio  = hw.get('clk_gpio', cfg.clk_gpio)
    cfg.dt_gpio   = hw.get('dt_gpio',  cfg.dt_gpio)
    cfg.sw_gpio   = hw.get('sw_gpio')
    cfg.led_gpio  = hw.get('led_gpio')
    cfg.port      = hw.get('port', cfg.port)
    cfg.uuid      = hw.get('uuid', '')

    if SETTINGS_PATH.exists():
        s = json.loads(SETTINGS_PATH.read_text(encoding='utf-8'))
        cfg.step_percent = s.get('step_percent', cfg.step_percent)
        cfg.name         = s.get('name',         cfg.name)
        cfg.pin          = s.get('pin',             cfg.pin)
        cfg.auto_update  = s.get('auto_update',   cfg.auto_update)

    if not cfg.uuid:
        state = _read_env_file(INSTALL_STATE_PATH)
        cfg.uuid = state.get('DIAL_UUID', '')

    if not cfg.uuid:
        raise RuntimeError(
            "No UUID in dial.json or install-state.env — reinstall required."
        )

    return cfg


_save_lock = threading.Lock()


def save_config(cfg: DialConfig) -> None:
    """Write runtime-mutable fields to dial-settings.json atomically.

    Never writes hardware config or UUID.  Uses mkstemp so concurrent calls
    each get a unique temp file; chmod 0600 before any data is written.
    """
    data = {
        'step_percent': cfg.step_percent,
        'name':         cfg.name,
        'pin':          cfg.pin,
        'auto_update':  cfg.auto_update,
    }
    with _save_lock:
        fd, tmp_path = tempfile.mkstemp(dir=SETTINGS_PATH.parent, suffix='.tmp')
        try:
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            Path(tmp_path).replace(SETTINGS_PATH)
        except:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
