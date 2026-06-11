"""Session-scoped test configuration.

Registers stubs for optional native dependencies that are declared in
core/requirements.txt but may not be installed in the test environment.
Doing this once here ensures a consistent sys.modules state regardless of
pytest collection order, rather than relying on per-file setdefault() calls.
"""
import sys
from unittest.mock import MagicMock

# requests is a runtime dependency of autostream_players. If it is not
# installed (e.g. in a lightweight CI environment), stub it before any test
# module triggers the import chain autostream_players → requests.
if "requests" not in sys.modules:
    sys.modules["requests"] = MagicMock()
