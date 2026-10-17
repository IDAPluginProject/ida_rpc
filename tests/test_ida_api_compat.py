from __future__ import annotations

from types import SimpleNamespace

from ida_rpc.server.tools.func_compat import (
    function_flags,
    function_size,
    function_start,
    set_function_flags,
)
from ida_rpc.server.tools.hexrays_compat import decompile_function
from ida_rpc.server.tools.segment_compat import (
    get_segment,
    segment_class,
    segment_name,
    segment_permissions,
)


def test_segment_helpers_support_ida_93_segment_t_api():
    seg = SimpleNamespace(start_ea=0x4000, end_ea=0x5000, perm=5, sclass="CODE32")
    ida_segment = SimpleNamespace(
        getseg=lambda ea: seg if ea == seg.start_ea else None,
        get_segm_name=lambda item: "LOAD",
        get_segm_class=lambda item: item.sclass,
    )

    assert get_segment(ida_segment, 0x4000) is seg
    assert segment_permissions(seg) == 5
    assert segment_name(ida_segment, seg) == "LOAD"
    assert segment_class(ida_segment, seg) == "CODE32"


def test_segment_helpers_keep_legacy_segment_info_api():
    class SegmentInfo:
        def __init__(self):
            self.name = "TEXT"
            self.sclass = "CODE"
            self.perm = 5

        def get_name(self):
            return self.name

        def get_sclass(self):
            return self.sclass

        def get_perm(self):
            return self.perm

    ida_segment = SimpleNamespace(
        segment_info_t=SegmentInfo,
        GSI_ALL=7,
        get_segment_info=lambda seg, ea, flags: ea == 0x4000,
    )
    seg = get_segment(ida_segment, 0x4000)

    assert seg is not None
    assert segment_permissions(seg) == 5
    assert segment_name(ida_segment, seg) == "TEXT"
    assert segment_class(ida_segment, seg) == "CODE"
    assert get_segment(ida_segment, 0x5000) is None


def test_function_start_supports_ida_93_get_func_api():
    funcs = SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=0x4000) if ea < 0x5000 else None)

    assert function_start(funcs, 0x4100, 0xFFFFFFFF) == 0x4000
    assert function_start(funcs, 0x5000, 0xFFFFFFFF) == 0xFFFFFFFF


def test_function_start_prefers_legacy_api_when_available():
    funcs = SimpleNamespace(get_func_start=lambda ea: ea - 4)

    assert function_start(funcs, 0x4004, 0xFFFFFFFF) == 0x4000


def test_function_size_supports_ida_93_func_t_api():
    func = SimpleNamespace(start_ea=0x4000, end_ea=0x4100)
    funcs = SimpleNamespace(
        get_func=lambda ea: func if ea == func.start_ea else None,
        calc_func_size=lambda item: item.end_ea - item.start_ea,
    )

    assert function_size(funcs, 0x4000) == 0x100
    assert function_size(funcs, 0x5000) == 0


def test_function_flags_supports_ida_93_func_t_api():
    func = SimpleNamespace(flags=0x12)
    updates = []
    funcs = SimpleNamespace(
        get_func=lambda ea: func if ea == 0x4000 else None,
        update_func=lambda item: updates.append(item.flags) or True,
    )

    assert function_flags(funcs, 0x4000) == 0x12
    assert set_function_flags(funcs, 0x4000, 0x34)
    assert func.flags == 0x34
    assert updates == [0x34]
    assert function_flags(funcs, 0x5000) == 0


def test_function_flags_prefers_legacy_api_when_available():
    funcs = SimpleNamespace(
        get_func_flags=lambda ea: ea - 0x4000,
        set_func_flags=lambda ea, flags: flags == 0x34,
    )

    assert function_flags(funcs, 0x4004) == 4
    assert set_function_flags(funcs, 0x4000, 0x34)


def test_hexrays_compat_prefers_ida_94_api():
    calls = []
    hexrays = SimpleNamespace(
        decompile_function=lambda ea: calls.append(("9.4", ea)) or "cfunc",
        decompile_func=lambda ea: "old func",
        decompile=lambda ea: "old",
    )

    assert decompile_function(hexrays, 0x4000) == "cfunc"
    assert calls == [("9.4", 0x4000)]


def test_hexrays_compat_supports_ida_93_api():
    calls = []
    hexrays = SimpleNamespace(
        decompile_func=lambda ea: calls.append(("9.3", ea)) or "cfunc",
    )

    assert decompile_function(hexrays, 0x4000) == "cfunc"
    assert calls == [("9.3", 0x4000)]


def test_hexrays_compat_supports_legacy_decompile_api():
    calls = []
    hexrays = SimpleNamespace(
        decompile=lambda ea: calls.append(("legacy", ea)) or "cfunc",
    )

    assert decompile_function(hexrays, 0x4000) == "cfunc"
    assert calls == [("legacy", 0x4000)]
