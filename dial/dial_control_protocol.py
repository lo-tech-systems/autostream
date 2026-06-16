"""dial_control_protocol.py — Shared constants for the local control socket.

Both the socket server (dial_control.py) and the operator CLI
(autostream_dial_control.py) import this module.  Do not duplicate these
values elsewhere.

Copyright (c) 2025-2026 Lo-tech Systems Limited. All rights reserved.
"""

# Path to the Unix-domain socket created by the running autostream-dial service.
CONTROL_SOCKET_PATH = "/run/autostream-dial/control.sock"

# Protocol identifier returned in the 'version' command response.
CONTROL_PROTOCOL_NAME = "autostream-dial-control"

# Protocol version.  Incremented only when existing commands, fields, or
# semantics are removed or redefined.
CONTROL_PROTOCOL_VERSION = 1

# Maximum request size (bytes), including the terminating newline.
CONTROL_REQUEST_MAX_BYTES = 4096

# Maximum response size (bytes), including the terminating newline.
CONTROL_RESPONSE_MAX_BYTES = 65536

# Per-client inactivity timeout on the server side (seconds).
CONTROL_SERVER_CLIENT_TIMEOUT = 2.0

# Connect timeout used by the CLI (seconds).
CONTROL_CLIENT_CONNECT_TIMEOUT = 2.0

# Response timeout used by the CLI (seconds).
CONTROL_CLIENT_RESPONSE_TIMEOUT = 3.0

# Per-target HTTP request timeout for enrichment (seconds).
TARGET_STATUS_TIMEOUT = 1.0

# Overall enrichment deadline (seconds).
TARGET_STATUS_DEADLINE = 1.5

# Maximum bytes accepted from a target status HTTP response.
TARGET_STATUS_MAX_BYTES = 65536
