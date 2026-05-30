"""Idle-TTL watchdog: a daemon thread that fires on_expire after `idle_ttl`
seconds without a .touch(). No ida_* deps — it only flips a flag the main-thread
REP loop reads, so the actual shutdown/save still happens on the IDA thread."""

import threading
import time


class WorkerLifecycle:
    def __init__(self, idle_ttl, on_expire):
        self.idle_ttl = float(idle_ttl or 0)
        self._on_expire = on_expire
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="idb-idle-ttl", daemon=True)

    def start(self):
        if self.idle_ttl > 0:
            self._thread.start()
        return self

    def touch(self):
        with self._lock:
            self._last = time.monotonic()

    def _run(self):
        tick = min(self.idle_ttl, 5.0)
        while not self._stop.wait(tick):
            with self._lock:
                idle = time.monotonic() - self._last
            if idle >= self.idle_ttl:
                self._on_expire()
                return

    def stop(self):
        self._stop.set()
