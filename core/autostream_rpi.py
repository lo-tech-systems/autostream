"""autostream_rpi.py

Copyright (c) 2025 Lo-tech Systems Limited. All rights reserved.

Functions specific to the Raspberry Pi platform integration e.g. PSU checks.

This module used to hold four unrelated concerns in one file: PSU/CPU/
system facts, appliance/dial identity derivation, CPU licensing, and dial
GPIO helpers. Each has moved to its own honestly-named module, and this
module now re-exports their names for existing importers:

  - ``autostream_system_stats.py`` -- PSU warning text, CPU temperature,
    CPU busy percent, Pi model, audio-path hardware classification, CPU
    serial reads.
  - ``autostream_appliance_identity.py`` -- appliance/dial identity
    derivation (security-relevant: CPU serial hashing).
  - ``autostream_licensing.py`` -- CPU-locked licensing.
  - ``autostream_dial_gpio.py`` -- rotary encoder / button GPIO helpers.

Everything below is re-imported and re-exported so existing
``from autostream_rpi import ...`` call sites keep working unchanged. New
code should import directly from the module that owns the concern it needs.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Re-exports -- see module docstring for the new home of each concern.
# ---------------------------------------------------------------------------

from autostream_system_stats import (  # noqa: F401 -- re-exported for existing importers
    RPI_MODEL_FILE,
    classify_high_performance_pi,
    get_cpu_busy_percent,
    get_cpu_serial,
    get_cpu_temperature_c,
    get_psu_warning_text,
    get_raspberry_pi_model,
    is_high_performance_pi,
)
from autostream_appliance_identity import (  # noqa: F401 -- re-exported for existing importers
    APPLIANCE_ID_FILE,
    DIAL_ID_FILE,
    get_appliance_id,
    get_dial_id,
)
from autostream_licensing import (  # noqa: F401 -- re-exported for existing importers
    CPU_INFO,
    LICENSE_CHECK,
    check_cpu,
    cpu_is_licensed,
    cpu_matches,
)
from autostream_dial_gpio import (  # noqa: F401 -- re-exported for existing importers
    setup_button,
    setup_rotary_encoder,
)
