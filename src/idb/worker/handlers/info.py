"""Session handlers: ping, shutdown, save, open_summary, segments."""

import ida_ida
import ida_nalt
import ida_segment
import ida_funcs
import ida_entry
import ida_loader
import idautils
import idc

from idb import protocol, registry
from idb.errors import IdbError
from idb.worker import idahelp
from idb.worker.dispatch import handler, CTX

_SUMMARY = {}


def _perm_str(perm):
    return (
        ("r" if perm & ida_segment.SEGPERM_READ else "-")
        + ("w" if perm & ida_segment.SEGPERM_WRITE else "-")
        + ("x" if perm & ida_segment.SEGPERM_EXEC else "-")
    )


def _hashes():
    md5 = ida_nalt.retrieve_input_file_md5()
    sha = ida_nalt.retrieve_input_file_sha256()
    return (md5.hex() if md5 else None, sha.hex() if sha else None)


def _num_globals():
    n = 0
    for ea, _name in idautils.Names():
        if ida_funcs.get_func(ea) is None:
            n += 1
    return n


def _entry_points():
    out = []
    for i in range(ida_entry.get_entry_qty()):
        ordn = ida_entry.get_entry_ordinal(i)
        out.append({"ea": ida_entry.get_entry(ordn), "name": ida_entry.get_entry_name(ordn) or ""})
    return out


def _compute_summary():
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()
    md5, sha = _hashes()
    return {
        "input": ida_nalt.get_root_filename(),
        "path": ida_nalt.get_input_file_path(),
        "format": ida_loader.get_file_type_name(),
        "arch": ida_ida.inf_get_procname(),
        "bitness": ida_ida.inf_get_app_bitness(),
        "endian": "big" if ida_ida.inf_is_be() else "little",
        "base": ida_nalt.get_imagebase(),
        "min_ea": min_ea,
        "max_ea": max_ea,
        "size": max_ea - min_ea,
        "md5": md5,
        "sha256": sha,
        "num_functions": sum(1 for _ in idautils.Functions()),
        "num_globals": _num_globals(),
        "num_segments": ida_segment.get_segm_qty(),
        "entry_points": _entry_points(),
    }


def warmup():
    try:
        for _ in idautils.Strings():
            pass
    except Exception:
        pass
    _SUMMARY.clear()
    _SUMMARY.update(_compute_summary())


@handler("ping", always=True)
def ping():
    return {
        "status": registry.STATUS_READY if CTX.ready else registry.STATUS_ANALYZING,
        "session": CTX.session_id,
    }


@handler("shutdown", always=True)
def shutdown(save=None):
    CTX.save_override = save
    if CTX.stop is not None:
        CTX.stop.set()
    return {"stopping": True, "save": save}


@handler("open_summary")
def open_summary():
    return dict(_SUMMARY)


@handler("save")
def save():
    path = idc.get_idb_path()
    ok = ida_loader.save_database()
    if not ok:
        raise IdbError(protocol.IDA_ERROR, "save_database returned false")
    return {"saved": path}


@handler("segments")
def segments(offset=0, count=None, total=False):
    def gen():
        for ea in idautils.Segments():
            s = ida_segment.getseg(ea)
            yield {
                "name": ida_segment.get_segm_name(s),
                "class": ida_segment.get_segm_class(s),
                "start": s.start_ea,
                "end": s.end_ea,
                "size": s.end_ea - s.start_ea,
                "perm": _perm_str(s.perm),
            }

    items, next_offset = idahelp.paginate(gen(), offset, count)
    total_count = ida_segment.get_segm_qty() if total else None
    return {"data": items}, idahelp.page_meta(items, next_offset, total_count)
