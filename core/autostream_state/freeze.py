"""autostream_state.freeze -- immutable containers for published values.

A value handed to the store is frozen first, so that a reader holding a
snapshot can never see it change under it and never needs a copy to be safe.
"""
from __future__ import annotations

import copy
import dataclasses
import enum
from typing import Any


class FrozenDict(dict):
    """A dict that refuses mutation, best effort.

    A dict subclass so that isinstance(x, dict) checks and json.dumps work
    unchanged on published values (the C encoder accepts subclasses). The
    mutating methods raise TypeError. __hash__ is defined over the frozen
    items, so a FrozenDict can sit in a digest or a frozenset, and __reduce__
    pickles back to a FrozenDict. copy.copy, copy.deepcopy and .copy() return
    plain, mutable dicts; readers that copy and then mutate rely on that.

    It cannot stop dict.update(fd, ...) called unbound or writes from C code:
    the guarantee holds for ordinary Python code.
    """

    __slots__ = ()

    def _refuse(self, *args, **kwargs):
        raise TypeError("FrozenDict does not support item assignment or removal")

    __setitem__ = _refuse
    __delitem__ = _refuse
    __ior__ = _refuse
    clear = _refuse
    pop = _refuse
    popitem = _refuse
    setdefault = _refuse
    update = _refuse

    def __hash__(self) -> int:
        return hash(frozenset(self.items()))

    def __reduce__(self):
        return (FrozenDict, (dict(self),))

    def copy(self) -> dict:
        return dict(self)

    def __copy__(self) -> dict:
        return dict(self)

    def __deepcopy__(self, memo) -> dict:
        return {copy.deepcopy(k, memo): copy.deepcopy(v, memo) for k, v in self.items()}


_PASS_THROUGH = (str, int, float, bool, bytes, type(None), enum.Enum)


def deep_freeze(value: Any) -> Any:
    """dict -> FrozenDict, list -> tuple, set -> frozenset, recursively.

    Frozen dataclasses are rebuilt with frozen fields (the same object when
    nothing changed). str, int, float, bool, None and Enum pass. Anything else
    raises TypeError, so a mutable object cannot be published by accident.
    """
    if isinstance(value, _PASS_THROUGH):
        return value
    if isinstance(value, dict):
        frozen = {k: deep_freeze(v) for k, v in value.items()}
        if type(value) is FrozenDict and all(frozen[k] is v for k, v in value.items()):
            return value
        return FrozenDict(frozen)
    if isinstance(value, (list, tuple)):
        items = tuple(deep_freeze(v) for v in value)
        if type(value) is tuple and all(a is b for a, b in zip(items, value)):
            return value
        return items
    if isinstance(value, (set, frozenset)):
        items = frozenset(deep_freeze(v) for v in value)
        return value if type(value) is frozenset and items == value else items
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        if not value.__dataclass_params__.frozen:
            raise TypeError(f"cannot publish a mutable dataclass: {type(value).__name__}")
        changed = {}
        for f in dataclasses.fields(value):
            current = getattr(value, f.name)
            frozen = deep_freeze(current)
            if frozen is not current:
                changed[f.name] = frozen
        return dataclasses.replace(value, **changed) if changed else value
    raise TypeError(f"cannot publish a value of type {type(value).__name__}")


def thaw(value: Any) -> Any:
    """A plain, mutable deep copy: FrozenDict and dict -> dict, tuple and list
    -> list, frozenset and set -> set. Anything else is returned as it is."""
    if isinstance(value, dict):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return set(value)
    return value
