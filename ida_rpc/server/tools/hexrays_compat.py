"""Compatibility helpers for Hex-Rays API changes across IDA releases."""

from __future__ import annotations


def decompile_function(ida_hexrays, address):
    """Decompile an address using the API exposed by the installed IDA SDK."""

    decompile = getattr(ida_hexrays, "decompile_function", None)
    if decompile is None:
        decompile = getattr(ida_hexrays, "decompile_func", None)
    if decompile is None:
        decompile = getattr(ida_hexrays, "decompile", None)
    if decompile is None:
        raise RuntimeError("Hex-Rays decompile API is unavailable")
    return decompile(address)
