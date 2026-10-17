# (c) B. Kerler 2026, MIT license
"""Compatibility helpers for IDA function APIs that changed across SDKs."""

from __future__ import annotations


def function_start(ida_funcs, ea: int, badaddr: int) -> int:
    """Get the containing function start on old and current IDA SDKs."""
    get_func_start = getattr(ida_funcs, "get_func_start", None)
    if get_func_start is not None:
        return get_func_start(ea)

    func = ida_funcs.get_func(ea)
    return func.start_ea if func is not None else badaddr


def function_size(ida_funcs, ea: int) -> int:
    """Get a function's byte size on old and current IDA SDKs."""
    calc_func_size_ea = getattr(ida_funcs, "calc_func_size_ea", None)
    if calc_func_size_ea is not None:
        return calc_func_size_ea(ea)

    func = ida_funcs.get_func(ea)
    return ida_funcs.calc_func_size(func) if func is not None else 0
