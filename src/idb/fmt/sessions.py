"""sessions / doctor table formatters."""

from .columns import align


def format_sessions(rows):
    if not rows:
        return "(no sessions)"
    table = [
        (
            r.get("id", "?"),
            r.get("status", "?"),
            r.get("pid") or "-",
            r.get("port") or "-",
            r.get("input_path") or r.get("idb_path") or "-",
        )
        for r in rows
    ]
    return align(table, headers=("SESSION", "STATUS", "PID", "PORT", "INPUT"),
                 aligns=("<", "<", ">", ">", "<"))


def format_doctor(rows):
    table = [(check, status, detail) for check, status, detail in rows]
    return align(table, headers=("CHECK", "STATUS", "DETAIL"))
