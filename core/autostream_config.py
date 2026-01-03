#!/usr/bin/env python3
"""
autostream_config.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Single source of truth for:
- loading the INI (ConfigParser)
- parsing / defaults / derived values

--

Configuration file example (INI):

[general]
log_file = /var/log/autostream.log
fifo_path = /tmp/autostream
silence_seconds = 30           ; length of time of continuous silence before stopping

[audio1]
capture_device = Cubilux SPDIF ; sounddevice input device name or index (run "python3 -m sounddevice" to see list)
arecord_format = dat           ; ALSA sample format (e.g. cd, dat) (legacy/unused)
silence_threshold = -66        ; dBFS threshold (e.g. -66 ~= 16/32767)

[audio2]
enabled = no                   ; set to yes to enable this channel
capture_device = Cubilux SPDIF ; sounddevice input device name or index (run "python3 -m sounddevice" to see list)
arecord_format = dat           ; ALSA sample format (e.g. cd, dat) (legacy/unused)
silence_threshold = -66        ; dBFS threshold (e.g. -66 ~= 16/32767)

[owntone]
base_url = http://localhost:3689
output_name = Kitchen Speaker
volume_percent = 20

[ffmpeg]
ffmpeg_out_rate = 44100        ; output rate for ffmpeg

[webui]
                               ; hidden_outputs are not shown on the volume control screen
hidden_outputs =
    Computer
    Dining Room
--
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import stat
import threading
import configparser
from typing import Iterable, Optional, Tuple



# -----------------------------
# Raw INI loading
# -----------------------------
def load_config(path: str) -> configparser.ConfigParser:
    """
    Load configuration from `path`.

    If the file does not exist yet, return an *empty* ConfigParser and let
    callers rely on .get(..., fallback=...) defaults.
    """
    cfg = configparser.ConfigParser()

    if not os.path.exists(path):
        return cfg

    read = cfg.read(path)
    if not read:
        raise FileNotFoundError(f"Config file not found or unreadable: {path}")

    return cfg


# -----------------------------
# Parsed / typed config
# -----------------------------
@dataclass(frozen=True)
class AudioInputConfig:
    capture_device: str
    arecord_format: str
    silence_threshold_dbfs: float


@dataclass(frozen=True)
class FFmpegConfig:
    out_rate: int
    in_rate1: int
    in_rate2: int


@dataclass(frozen=True)
class OwntoneConfig:
    base_url: str
    output_name: str
    volume_percent: int


@dataclass(frozen=True)
class GeneralConfig:
    log_file: str
    silence_seconds: int
    fifo_path: str


@dataclass(frozen=True)
class WebUIConfig:
    """Web UI-only configuration.
    This must not affect core streaming logic.
    """
    # Names of Owntone outputs that should be hidden from the Web UI.
    # Matching is case-insensitive.
    hidden_outputs: tuple[str, ...]


@dataclass(frozen=True)
class AutostreamConfig:
    general: GeneralConfig
    audio1: AudioInputConfig
    audio2_enabled: bool
    audio2: AudioInputConfig
    ffmpeg: FFmpegConfig
    owntone: OwntoneConfig
    webui: WebUIConfig


def _split_list(raw: str | None) -> tuple[str, ...]:
    """Parse a comma/newline-separated list from the INI.

    Supports either:
      hidden_outputs = A, B, C
    or
      hidden_outputs =
          A
          B
          C
    """
    if not raw:
        return ()
    items: list[str] = []
    for ln in str(raw).splitlines():
        for part in ln.split(","):
            s = part.strip()
            if s:
                items.append(s)
    # Deduplicate while preserving order (case-insensitive)
    seen: set[str] = set()
    out: list[str] = []
    for s in items:
        key = s.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return tuple(out)


def _infer_in_rate(arecord_format: str) -> int:
    """
    Infer input sample rate from arecord/PCM format.
    Keep behavior identical to the previous core logic.
    """
    return 48000 if arecord_format == "dat" else 44100


def parse_config(cfg: configparser.ConfigParser) -> AutostreamConfig:
    # General
    log_file = cfg.get(
        "general", "log_file",
        fallback="/var/log/autostream/autostream.log"
    )
    silence_seconds = cfg.getint("general", "silence_seconds", fallback=30)
    fifo_path = cfg.get("general", "fifo_path", fallback="/tmp/autostream.fifo")

    general = GeneralConfig(
        log_file=log_file,
        silence_seconds=silence_seconds,
        fifo_path=fifo_path,
    )

    # Audio #1
    capture_device1 = cfg.get("audio1", "input_device", fallback="").strip() \
                 or cfg.get("audio1", "capture_device", fallback="default")
    arecord_format1 = cfg.get("audio1", "arecord_format", fallback="dat")
    silence_threshold1 = cfg.getfloat("audio1", "silence_threshold", fallback=-66.0)

    audio1 = AudioInputConfig(
        capture_device=capture_device1,
        arecord_format=arecord_format1,
        silence_threshold_dbfs=silence_threshold1,
    )

    # Audio #2
    audio2_enabled = cfg.getboolean("audio2", "enabled", fallback=False)
    capture_device2 = cfg.get("audio2", "input_device", fallback="").strip() \
                 or cfg.get("audio2", "capture_device", fallback="default")
    arecord_format2 = cfg.get("audio2", "arecord_format", fallback="dat")
    silence_threshold2 = cfg.getfloat("audio2", "silence_threshold", fallback=-66.0)

    audio2 = AudioInputConfig(
        capture_device=capture_device2,
        arecord_format=arecord_format2,
        silence_threshold_dbfs=silence_threshold2,
    )

    # ffmpeg
    ffmpeg_out_rate = cfg.getint("ffmpeg", "ffmpeg_out_rate", fallback=44100)
    ffmpeg = FFmpegConfig(
        out_rate=ffmpeg_out_rate,
        in_rate1=_infer_in_rate(arecord_format1),
        in_rate2=_infer_in_rate(arecord_format2),
    )

    # Owntone
    owntone = OwntoneConfig(
        base_url=cfg.get("owntone", "base_url", fallback="http://localhost:3689"),
        output_name=cfg.get("owntone", "output_name", fallback=""),
        volume_percent=cfg.getint("owntone", "volume_percent", fallback=20),
    )

    # Web UI
    webui = WebUIConfig(
        hidden_outputs=_split_list(cfg.get("webui", "hidden_outputs", fallback="")),
    )

    return AutostreamConfig(
        general=general,
        audio1=audio1,
        audio2_enabled=audio2_enabled,
        audio2=audio2,
        ffmpeg=ffmpeg,
        owntone=owntone,
        webui=webui,
    )


def load_and_parse(path: str) -> AutostreamConfig:
    return parse_config(load_config(path))


def mark_configured(path: str) -> None:
    """
    After successfully writing the INI, call this to force unconfigured(path) == False
    immediately (until the file changes again).
    """
    try:
        st = os.stat(path)
        sig = (float(st.st_mtime), int(st.st_size))
    except OSError:
        return

    with _unconfigured_lock:
        _unconfigured_cache[path] = (sig, False)

def _is_minimally_valid_ini(path: str) -> bool:
    """
    Return True if INI can be parsed and contains at least one section.
    Keep this lightweight; you can strengthen it later (required keys, etc.).
    """
    p = configparser.ConfigParser()
    try:
        with open(path, "r", encoding="utf-8") as f:
            p.read_file(f)
    except Exception:
        return False
    return len(p.sections()) > 0


# Cache: path -> ((mtime, size), unconfigured_bool)
_unconfigured_lock = threading.Lock()
_unconfigured_cache: dict[str, tuple[tuple[float, int], bool]] = {}


def _get_nonempty(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    """Return a stripped value or '' if missing/blank."""
    try:
        return cfg.get(section, key, fallback="").strip()
    except (configparser.Error, ValueError):
        return ""


def unconfigured(path: str) -> bool:
    """
    True if the system should be treated as unconfigured.

    Requires:
      - [general] fifo_path (non-empty)
      - [audio1] input_device OR capture_device (non-empty)
      - [owntone] output_name (non-empty)

    Cached by (mtime, size) so we only re-parse when the INI changes.
    """
    # Fast stat + basic sanity checks
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return True
        if st.st_size == 0:
            return True
        sig = (float(st.st_mtime), int(st.st_size))
    except FileNotFoundError:
        return True
    except OSError:
        # unreadable, permission denied, sandboxed, etc.
        return True

    # Cache hit?
    with _unconfigured_lock:
        cached = _unconfigured_cache.get(path)
        if cached and cached[0] == sig:
            return cached[1]

    # Parse + validate required fields
    cfg = configparser.ConfigParser()
    read_ok = cfg.read(path)
    if not read_ok:
        is_unconfigured = True
    else:
        fifo_path = _get_nonempty(cfg, "general", "fifo_path")

        # Support both INI key names:
        # - "input_device" (what you want)
        # - "capture_device" (what parse_config currently reads) :contentReference[oaicite:1]{index=1}
        audio1_dev = (
            _get_nonempty(cfg, "audio1", "input_device")
            or _get_nonempty(cfg, "audio1", "capture_device")
        )

        output_name = _get_nonempty(cfg, "owntone", "output_name")

        is_unconfigured = not (fifo_path and audio1_dev and output_name)

    # Update cache
    with _unconfigured_lock:
        _unconfigured_cache[path] = (sig, is_unconfigured)

    return is_unconfigured
