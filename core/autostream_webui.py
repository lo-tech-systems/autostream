#!/usr/bin/env python3
"""autostream_webui.py

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.

The service entry point: runs the coordinator with the web server.

Usage: python3 autostream_webui.py /etc/autostream/autostream.json
"""
from __future__ import annotations

import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} PATH_TO_CONFIG.json")
        sys.exit(1)
    import autostream_core
    import webui.server
    autostream_core.run_autostream(sys.argv[1], start_webui=webui.server.start_server)
