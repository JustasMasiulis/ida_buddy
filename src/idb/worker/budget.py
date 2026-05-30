"""Cooperative deadline for PURE-PYTHON worker loops (paginated line generation,
immediate/byte search iteration). It CANNOT interrupt a single in-flight native
call (decompile, a whole-range find_bytes, auto_wait) — those are covered by the
client soft timeout + `idb close --kill`. No ida_* imports."""

import time

from idb import protocol
from idb.errors import IdbError


class Budget:
    def __init__(self, seconds=None):
        self.deadline = (time.monotonic() + seconds) if seconds is not None else None

    @property
    def expired(self):
        return self.deadline is not None and time.monotonic() > self.deadline

    def check(self):
        if self.expired:
            raise IdbError(protocol.TIMEOUT, "operation exceeded its server-side time budget")
