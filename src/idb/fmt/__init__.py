"""Text formatters. Pure functions over result-dicts; NO ida_* imports, so the
whole package is golden-testable without a worker. Data -> stdout; banners and
[+N more] notices -> stderr (never ingested as data)."""
