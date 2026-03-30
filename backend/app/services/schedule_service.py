from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import threading
import time

from app.models.asset import Asset, ScanRequest, ScheduledScan, ScheduledScanCreate
from app.services.scan_service import ScanService
from app.storage.memory import store

logger = logging.getLogger(__name__)


class ScheduleService:
    def __init__(self, scan_service: ScanService):
        self.scan_service = scan_service
        self._started = False
        self._lock = threading.Lock()

    def start_worker(self) -> None:
        with self._lock:
            if self._started:
                return
            thread = threading.Thread(target=self._worker, daemon=True)
            thread.start()
            self._started = True
            logger.info('scheduled scan worker started')

    def create(self, asset: Asset, payload: ScheduledScanCreate) -> ScheduledScan:
        schedule = ScheduledScan(
            asset_id=asset.id,
            scan_type=payload.scan_type,
            interval_minutes=payload.interval_minutes,
            next_run_at=datetime.now(timezone.utc) + timedelta(minutes=payload.interval_minutes),
        )
        with store.lock:
            store.schedules[schedule.id] = schedule
            store.asset_schedules[asset.id].append(schedule.id)
        return schedule

    def list_for_asset(self, asset_id: str) -> list[ScheduledScan]:
        with store.lock:
            return [store.schedules[sid] for sid in store.asset_schedules.get(asset_id, []) if sid in store.schedules]

    def delete(self, schedule_id: str) -> None:
        with store.lock:
            schedule = store.schedules.pop(schedule_id, None)
            if schedule and schedule.asset_id in store.asset_schedules:
                store.asset_schedules[schedule.asset_id] = [sid for sid in store.asset_schedules[schedule.asset_id] if sid != schedule_id]

    def _worker(self) -> None:
        # Lightweight scheduler loop for demo purposes. It periodically checks due
        # schedules and starts the corresponding scan job through ScanService.
        while True:
            now = datetime.now(timezone.utc)
            due: list[ScheduledScan] = []
            with store.lock:
                for schedule in store.schedules.values():
                    if schedule.enabled and schedule.next_run_at <= now:
                        due.append(schedule)
            for schedule in due:
                try:
                    asset = store.assets.get(schedule.asset_id)
                    if not asset:
                        continue
                    self.scan_service.start_scan(asset, ScanRequest(scan_type=schedule.scan_type), triggered_by='schedule')
                    updated = schedule.model_copy(update={
                        'last_run_at': now,
                        'next_run_at': now + timedelta(minutes=schedule.interval_minutes),
                    })
                    with store.lock:
                        store.schedules[schedule.id] = updated
                except Exception:
                    logger.exception('scheduled scan execution failed schedule_id=%s', schedule.id)
            time.sleep(5)
