"""Static guards for IDA 9.4 API compatibility and explicit older fallbacks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
PROJECT_SOURCES = [ROOT / "ida_rpc", ROOT / "ida_rpc_plugin.py"]
COMPATIBILITY_SOURCES = {
    ROOT / "ida_rpc_plugin.py",
    ROOT / "ida_rpc" / "server" / "tools" / "func_compat.py",
    ROOT / "ida_rpc" / "server" / "tools" / "segment_compat.py",
    ROOT / "ida_rpc" / "server" / "tools" / "hexrays_compat.py",
}


@pytest.mark.parametrize(
    "pattern",
    (
        "ida_funcs.get_func(",
        "ida_segment.getseg(",
        "ida_segment.get_segm_name(",
        "ida_segment.get_segm_class(",
        "ida_segment.set_segm_name(",
        "ida_segment.set_segm_class(",
        "ida_segment.set_segm_addressing(",
        "ida_gdl.gen_flow_graph(",
        "ida_frame.get_frame_size(",
        "ida_frame.get_frame_retsize(",
        "ida_frame.get_func_frame(",
        "ida_frame.frame_off_args(",
        "ida_frame.frame_off_lvars(",
        "ida_frame.set_frame_member_type(",
        "ida_frame.build_stkvar_xrefs(",
        "ida_hexrays.decompile(",
        "ida_hexrays.decompile_func(",
        "ida_hexrays.decompile_function(",
    ),
)
def test_no_ida94_deprecated_calls(pattern: str):
    matches = []
    for source in PROJECT_SOURCES:
        paths = [source] if source.is_file() else source.rglob("*.py")
        for path in paths:
            if path in COMPATIBILITY_SOURCES:
                continue
            text = path.read_text(encoding="utf-8")
            if pattern in text:
                matches.append(str(path.relative_to(ROOT)))
    assert not matches, f"deprecated IDA 9.4 call {pattern!r} remains in {matches}"


def test_ida94_install_exposes_replacement_apis():
    ida_root = Path(os.environ.get("IDA_INSTALL_DIR", "/home/bjk/bin/ida-pro-9.4"))
    python_dir = ida_root / "python"
    modules = (
        "ida_segment.py",
        "ida_funcs.py",
        "ida_frame.py",
        "ida_gdl.py",
        "ida_hexrays.py",
    )
    if not python_dir.is_dir() or not all((python_dir / module).is_file() for module in modules):
        pytest.skip("IDA Pro installation is not available")

    funcs_api = (python_dir / "ida_funcs.py").read_text(encoding="utf-8")
    if "get_func_start" not in funcs_api:
        # The configured install is IDA 9.3. Verify its API surface instead
        # of incorrectly requiring the IDA 9.4 wrappers below.
        legacy_required = {
            "ida_funcs.py": ("def get_func(", "def calc_func_size("),
            "ida_frame.py": ("def get_frame_size(", "def get_func_frame("),
            "ida_gdl.py": ("def gen_flow_graph(",),
            "ida_hexrays.py": ("def decompile_func(",),
        }
        for module, symbols in legacy_required.items():
            text = (python_dir / module).read_text(encoding="utf-8")
            for symbol in symbols:
                assert symbol in text, f"IDA 9.3 API {symbol} missing from {module}"
        return

    required = {
        "ida_funcs.py": ("get_func_start", "get_func_entry_info", "calc_func_size_ea"),
        "ida_frame.py": ("get_frame_size_ea", "get_func_frame_ea", "set_frame_member_type_ea"),
        "ida_gdl.py": ("gen_flow_graph_ea", "qflow_chart_ea_t"),
        "ida_hexrays.py": ("decompile_function", "decomp_ranges_t"),
    }
    for module, symbols in required.items():
        text = (python_dir / module).read_text(encoding="utf-8")
        for symbol in symbols:
            assert symbol in text, f"IDA 9.4 replacement {symbol} missing from {module}"

    segment_api = (python_dir / "ida_segment.py").read_text(encoding="utf-8")
    if "get_segment_info" in segment_api:
        assert "get_segment_name" in segment_api
        assert "set_segment_info" in segment_api
    else:
        # IDA 9.3 exposes the segment_t API; ida-rpc supports it through
        # explicit compatibility adapters.
        for symbol in ("class segment_t", "def getseg(", "def set_segm_addressing("):
            assert symbol in segment_api, f"IDA 9.3 segment API {symbol} missing"
