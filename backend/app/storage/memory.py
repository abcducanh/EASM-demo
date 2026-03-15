from __future__ import annotations

from collections import defaultdict
from threading import RLock
from app.models.asset import Alert, Asset, ScanJob, ScheduledScan


class MemoryStore:
    def __init__(self):
        self.assets: dict[str, Asset] = {}
        self.jobs: dict[str, ScanJob] = {}
        self.job_results: dict[str, list[dict]] = {}
        self.asset_jobs: dict[str, list[str]] = defaultdict(list)
        self.schedules: dict[str, ScheduledScan] = {}
        self.asset_schedules: dict[str, list[str]] = defaultdict(list)
        self.alerts: list[Alert] = []
        self.lock = RLock()

    def reset(self) -> None:
        with self.lock:
            self.assets.clear()
            self.jobs.clear()
            self.job_results.clear()
            self.asset_jobs.clear()
            self.schedules.clear()
            self.asset_schedules.clear()
            self.alerts.clear()


store = MemoryStore()
