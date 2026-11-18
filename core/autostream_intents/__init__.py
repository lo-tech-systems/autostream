"""autostream_intents -- the one path for a request to change state.

A caller builds an Intent (a row name, its arguments, who is asking) and
submit()s it. The row validates the arguments, the origin and the rate limit;
the handler bound to the row, in the module that implements it, does the work;
the reply carries the outcome and the store version that shows the change.
"""
from autostream_state import Origin

from .table import Intent, IntentNotBound, Reply, Role, submit

__all__ = ["Intent", "Reply", "Origin", "Role", "submit", "IntentNotBound"]
