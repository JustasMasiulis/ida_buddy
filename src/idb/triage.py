"""Pure heuristics for the `triage` command. No ida_* imports.

The handler (idb.worker.handlers.triage) gathers raw facts from IDA — callee
rows, name lists, per-site argument descriptors — and this module turns them
into the ranked, grouped, aggregated shapes the formatter prints. Keeping the
judgement calls here (prefix splitting, callee ranking, argument roll-up) makes
them Tier-1 testable without a database.
"""

import re

_DECORATION = "_@?$"
_IDENT = re.compile(r"[A-Za-z0-9_]+")
_CAMEL = re.compile(r"[a-z0-9][A-Z]")
_DUMMY = re.compile(r"^(sub|nullsub|j_sub|loc|unknown_libname|def)_", re.IGNORECASE)


def split_prefix(name):
    """The leading subsystem token of a symbol, or '' if it has none worth
    grouping. Strips a leading decoration run ([_@?$]) and any trailing mangling,
    then: if the core has an underscore, the token is the part before the first
    one ('WfpFilter_Add' -> 'WfpFilter', 'sub_140001000' -> 'sub'); otherwise it
    cuts at the first camelCase lower->Upper boundary ('PsLookupX' -> 'Ps')."""
    if not name:
        return ""
    m = _IDENT.match(name.lstrip(_DECORATION))
    if m is None:
        return ""
    core = m.group(0)
    underscore = core.find("_")
    if underscore >= 0:
        return core[:underscore]
    camel = _CAMEL.search(core)
    return core[:camel.start() + 1] if camel is not None else core


def group_prefixes(names, min_group=2, min_prefix=2):
    """Group names by shared leading prefix. Returns [{'prefix','count'}] for
    prefixes of length >= min_prefix shared by >= min_group names, sorted by
    count descending then prefix ascending. Auto-generated names (sub_*, loc_*)
    are excluded — clustering them by 'sub' tells the analyst nothing."""
    counts = {}
    for name in names:
        if is_dummy_name(name):
            continue
        prefix = split_prefix(name)
        if len(prefix) < min_prefix:
            continue
        counts[prefix] = counts.get(prefix, 0) + 1
    groups = [{"prefix": p, "count": c} for p, c in counts.items() if c >= min_group]
    groups.sort(key=lambda g: (-g["count"], g["prefix"]))
    return groups


def humanize_groups(groups):
    """[{'prefix':'Ps','count':5}, ...] -> ['Ps* (5)', ...]."""
    return [f"{g['prefix']}* ({g['count']})" for g in groups]


def is_dummy_name(name):
    """True for IDA auto-generated names (sub_*, loc_*, nullsub_*) — i.e. a
    function nobody has reverse-engineered yet."""
    return bool(name) and _DUMMY.match(name) is not None


def rank_callees(callees, cap=None):
    """Order callees so the best reverse-engineering targets surface first:
    un-named real functions before named ones, then small + heavily-referenced
    helpers, with imports/thunks (no body to read) sinking to the bottom. Stable
    within a tier. Each callee is a dict with name/size/callers/kind/named."""
    indexed = list(enumerate(callees))

    def key(item):
        idx, c = item
        kind = c.get("kind")
        is_code = kind in ("func", "thunk")
        body_less = kind in ("import", "data") or c.get("size", 0) <= 0
        unnamed = is_code and not c.get("named", False)
        return (
            body_less,            # imports/thunks/empty last
            not unnamed,          # un-named real functions first
            c.get("size", 0),     # smaller first
            -c.get("callers", 0), # hotter first
            idx,                  # stable tie-break
        )

    ranked = [c for _, c in sorted(indexed, key=key)]
    return ranked if cap is None else ranked[:cap]


def node_complexity(node):
    """A rough 'how much is there to read' score for a call-graph node, from its
    byte size and direct fan-out. Used to decide where a helper chain stops being
    a quick rename and starts being real work."""
    return int(node.get("size", 0)) + 16 * int(node.get("callees", 0))


def helper_suggested_depth(chain, budget):
    """Given a chain of nodes (target's helper, then its helper, ...), return how
    many levels stay simple before complexity exceeds `budget`. A chain that is
    trivial for two levels then explodes returns 2 — i.e. 'rename down to here,
    then stop'. Always at least 1 when the chain is non-empty."""
    depth = 0
    for node in chain:
        if node_complexity(node) > budget and depth >= 1:
            break
        depth += 1
    return depth


def aggregate_arg_types(sites, max_actuals=4):
    """Roll per-call-site argument descriptors up by parameter position.

    `sites` is [{'args': [{'index','type','expr','member'}, ...]}, ...]; each arg
    carries the underlying type (already resolved through implicit casts by the
    handler), the source expression, and an optional member-access note. Returns
    one row per index: {'index', 'actuals': [{'type','count'}], 'member'} where
    actuals are the distinct underlying types seen, most frequent first, and
    member is the first member-access note observed at that position."""
    by_index = {}
    for site in sites:
        for arg in site.get("args", []):
            idx = arg.get("index")
            slot = by_index.setdefault(idx, {"types": {}, "order": [], "member": None})
            t = arg.get("type") or "?"
            if t not in slot["types"]:
                slot["order"].append(t)
            slot["types"][t] = slot["types"].get(t, 0) + 1
            if slot["member"] is None and arg.get("member"):
                slot["member"] = arg["member"]

    rows = []
    for idx in sorted(by_index):
        slot = by_index[idx]
        actuals = [{"type": t, "count": slot["types"][t]} for t in slot["order"]]
        actuals.sort(key=lambda a: (-a["count"], slot["order"].index(a["type"])))
        rows.append({"index": idx, "actuals": actuals[:max_actuals], "member": slot["member"]})
    return rows
