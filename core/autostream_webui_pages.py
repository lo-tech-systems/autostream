#!/usr/bin/env python3
"""autostream_webui_pages.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

Legacy facade module — kept for compatibility.  The router
(autostream_webui.py) now imports each page module directly; this file
is no longer the primary import path and may be removed in a future
clean-up.

Implementation modules:
  autostream_webui_api              -- send_json, JSON endpoints, run_updater
  autostream_webui_page_airplay     -- send_airplay_page
  autostream_webui_page_setup       -- send_setup_page
  autostream_webui_page_owntone     -- send_owntone_setup_page, owntone restart
  autostream_webui_page_rebooting   -- send_rebooting_page
  autostream_webui_post_handlers    -- handle_* POST handlers
"""

from __future__ import annotations

from autostream_webui_api import (
    send_json,
    send_owntone_outputs_json,
    send_owntone_outputs_state_json,
    send_status_json,
    send_update_check_json,
    send_update_status_json,
)

from autostream_webui_page_airplay import send_airplay_page

from autostream_webui_page_setup import send_setup_page

from autostream_webui_page_owntone import (
    send_owntone_ready_json,
    send_owntone_restarting_page,
    send_owntone_setup_page,
    start_owntone_restart_async,
)

from autostream_webui_page_rebooting import send_rebooting_page

from autostream_webui_post_handlers import (
    handle_factory_reset_post,
    handle_live_input_eq_update,
    handle_live_input_gain_update,
    handle_output_update,
    handle_owntone_setup_post,
    handle_setup_post,
)

__all__ = [
    "handle_factory_reset_post",
    "handle_live_input_eq_update",
    "handle_live_input_gain_update",
    "handle_output_update",
    "handle_owntone_setup_post",
    "handle_setup_post",
    "send_airplay_page",
    "send_json",
    "send_owntone_outputs_json",
    "send_owntone_outputs_state_json",
    "send_owntone_ready_json",
    "send_owntone_restarting_page",
    "send_owntone_setup_page",
    "send_rebooting_page",
    "send_setup_page",
    "send_status_json",
    "send_update_check_json",
    "send_update_status_json",
    "start_owntone_restart_async",
]
