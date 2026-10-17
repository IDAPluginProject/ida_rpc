# (c) B. Kerler 2026, MIT license
"""Small compatibility layer for IDA's changing segment Python API."""

from __future__ import annotations


def get_segment(ida_segment, ea: int):
    """Return a segment record using either the legacy or current IDA API."""
    segment_info_type = getattr(ida_segment, "segment_info_t", None)
    get_segment_info = getattr(ida_segment, "get_segment_info", None)
    if segment_info_type is not None and get_segment_info is not None:
        seg = segment_info_type()
        flags = getattr(ida_segment, "GSI_ALL", None)
        found = get_segment_info(seg, ea, flags) if flags is not None else get_segment_info(seg, ea)
        return seg if found else None

    getseg = getattr(ida_segment, "getseg", None)
    return getseg(ea) if getseg is not None else None


def segment_permissions(seg) -> int:
    """Return segment permissions across legacy records and segment_t."""
    get_perm = getattr(seg, "get_perm", None)
    return get_perm() if get_perm is not None else int(seg.perm)


def segment_name(ida_segment, seg) -> str:
    """Return the segment name across legacy records and segment_t."""
    get_name = getattr(seg, "get_name", None)
    if get_name is not None:
        return get_name() or ""
    return ida_segment.get_segm_name(seg) or ""


def segment_class(ida_segment, seg) -> str:
    """Return the segment class across legacy records and segment_t."""
    get_sclass = getattr(seg, "get_sclass", None)
    if get_sclass is not None:
        return get_sclass() or ""
    return ida_segment.get_segm_class(seg) or ""
