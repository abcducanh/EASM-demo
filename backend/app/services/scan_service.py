from __future__ import annotations

from datetime import datetime, timedelta, timezone
import csv
import io
import ipaddress
import json
import logging
import threading
from collections import Counter

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors

from app.models.asset import Alert, AlertSeverity, Asset, AssetType, ScanJob, ScanRequest, ScanResultsEnvelope, ScanStatus, ScanType
from app.scanners.asn_scanner import ASNScanner
from app.scanners.cert_trans_scanner import CertTransparencyScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.ip_scanner import IPScanner
from app.scanners.port_scanner import PortScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.subdomain_scanner import SubdomainScanner
from app.scanners.tech_scanner import TechScanner
from app.scanners.whois_scanner import WhoisScanner
from app.services.asset_service import AssetService
from app.storage.memory import store

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self):
        self.asset_service = AssetService()
        self.scanners = {
            ScanType.DNS: DNSScanner(),
            ScanType.WHOIS: WhoisScanner(),
            ScanType.SUBDOMAIN: SubdomainScanner(),
            ScanType.CERT_TRANS: CertTransparencyScanner(),
            ScanType.ASN: ASNScanner(),
            ScanType.IP: IPScanner(),
            ScanType.PORT: PortScanner(),
            ScanType.SSL: SSLScanner(),
            ScanType.TECH: TechScanner(),
        }
        self.scan_all_map = {
            AssetType.DOMAIN: [ScanType.DNS, ScanType.WHOIS, ScanType.SUBDOMAIN, ScanType.CERT_TRANS, ScanType.SSL, ScanType.TECH],
            AssetType.IP: [ScanType.IP, ScanType.ASN, ScanType.PORT],
        }

    def start_scan(self, asset: Asset, payload: ScanRequest, triggered_by: str = 'manual') -> ScanJob:
        # Create a job first and hand the real execution to a background thread.
        # This keeps the HTTP API responsive and matches the pending -> running -> completed flow.
        self._validate_scan(asset, payload.scan_type)
        job = ScanJob(asset_id=asset.id, scan_type=payload.scan_type, status=ScanStatus.PENDING, triggered_by=triggered_by)
        with store.lock:
            store.jobs[job.id] = job
            store.asset_jobs[asset.id].append(job.id)
            store.job_results[job.id] = []
        thread = threading.Thread(target=self._execute_job, args=(asset, job.id, payload.scan_type), daemon=True)
        thread.start()
        logger.info('scan job queued job_id=%s asset=%s scan_type=%s trigger=%s', job.id, asset.name, payload.scan_type.value, triggered_by)
        return job

    def _execute_job(self, asset: Asset, job_id: str, scan_type: ScanType) -> None:
        self._update_job(job_id, status=ScanStatus.RUNNING)
        logger.info('scan job running job_id=%s asset=%s scan_type=%s', job_id, asset.name, scan_type.value)
        try:
            if scan_type == ScanType.ALL:
                results, errors = self._run_scan_all(asset)
                status = ScanStatus.PARTIAL if errors else ScanStatus.COMPLETED
                error_text = '; '.join(errors)
                count = sum(item.get('count', 0) for item in results)
            else:
                results = self._run_single(asset, scan_type)
                self._apply_discovery(asset, scan_type, results)
                errors = []
                status = ScanStatus.COMPLETED if results else ScanStatus.PARTIAL
                error_text = '' if results else 'no results found'
                count = len(results)
            with store.lock:
                store.job_results[job_id] = results
            self._update_job(job_id, status=status, results=count, error=error_text, ended_at=datetime.now(timezone.utc))
            self._emit_alerts(asset, job_id, scan_type, status, error_text, results)
            logger.info('scan job finished job_id=%s asset=%s scan_type=%s status=%s results=%s', job_id, asset.name, scan_type.value, status.value, count)
        except Exception as exc:
            with store.lock:
                store.job_results[job_id] = []
            self._update_job(job_id, status=ScanStatus.FAILED, error=str(exc), ended_at=datetime.now(timezone.utc))
            self._emit_alerts(asset, job_id, scan_type, ScanStatus.FAILED, str(exc), [])
            logger.exception('scan job failed job_id=%s asset=%s scan_type=%s', job_id, asset.name, scan_type.value)

    def _run_scan_all(self, asset: Asset) -> tuple[list[dict], list[str]]:
        combined: list[dict] = []
        errors: list[str] = []
        for item in self.scan_all_map[asset.type]:
            try:
                results = self._run_single(asset, item)
                self._apply_discovery(asset, item, results)
                combined.append({'scan_type': item.value, 'results': results, 'count': len(results)})
            except Exception as exc:
                errors.append(f'{item.value}: {exc}')
                combined.append({'scan_type': item.value, 'results': [], 'count': 0, 'error': str(exc)})
        return combined, errors

    def _validate_scan(self, asset: Asset, scan_type: ScanType) -> None:
        if scan_type == ScanType.ALL:
            return
        if asset.type == AssetType.DOMAIN and scan_type in {ScanType.IP, ScanType.PORT, ScanType.ASN}:
            raise ValueError('scan type not valid for domain asset')
        if asset.type == AssetType.IP and scan_type in {ScanType.DNS, ScanType.WHOIS, ScanType.SUBDOMAIN, ScanType.CERT_TRANS, ScanType.SSL, ScanType.TECH}:
            raise ValueError('scan type not valid for ip asset')

    def _run_single(self, asset: Asset, scan_type: ScanType) -> list[dict]:
        scanner = self.scanners.get(scan_type)
        if not scanner:
            raise ValueError(f'unsupported scan_type: {scan_type.value}')
        self._validate_scan(asset, scan_type)
        return scanner.scan(asset)

    def _update_job(self, job_id: str, **changes) -> None:
        with store.lock:
            job = store.jobs[job_id]
            updated = job.model_copy(update=changes)
            store.jobs[job_id] = updated

    def _apply_discovery(self, asset: Asset, scan_type: ScanType, results: list[dict]) -> None:
        # Discovery is intentionally conservative: DNS A/AAAA can create IP assets,
        # but subdomain scan results are only stored as findings and are NOT auto-created as assets.
        if asset.type == AssetType.DOMAIN and scan_type == ScanType.DNS:
            for row in results:
                if row.get('record_type') in {'A', 'AAAA'} and row.get('value'):
                    try:
                        ipaddress.ip_address(row['value'])
                        self.asset_service.create_if_missing(row['value'], AssetType.IP, tags=['discovered'])
                    except ValueError:
                        continue

    def _emit_alerts(self, asset: Asset, job_id: str, scan_type: ScanType, status: ScanStatus, error_text: str, results: list[dict]) -> None:
        alerts: list[Alert] = []
        if status in {ScanStatus.FAILED, ScanStatus.PARTIAL}:
            alerts.append(Alert(asset_id=asset.id, job_id=job_id, scan_type=scan_type.value, severity=AlertSeverity.WARNING if status == ScanStatus.PARTIAL else AlertSeverity.HIGH, message=error_text or f'{scan_type.value} returned no results'))
        if scan_type == ScanType.PORT:
            ports = results[0].get('open_ports', []) if results else []
            if ports:
                alerts.append(Alert(asset_id=asset.id, job_id=job_id, scan_type=scan_type.value, severity=AlertSeverity.INFO, message=f'Open ports detected: {", ".join(str(p.get("port")) for p in ports[:10])}'))
        if scan_type == ScanType.SSL and results:
            cert = results[0].get('certificate', {})
            days = cert.get('days_until_expiry')
            if days is not None and days <= 30:
                alerts.append(Alert(asset_id=asset.id, job_id=job_id, scan_type=scan_type.value, severity=AlertSeverity.HIGH, message=f'SSL certificate expires in {days} days'))
            if results[0].get('issues'):
                alerts.append(Alert(asset_id=asset.id, job_id=job_id, scan_type=scan_type.value, severity=AlertSeverity.WARNING, message='SSL issues detected'))
        if scan_type == ScanType.ALL:
            failures = [group.get('scan_type') for group in results if group.get('error')]
            if failures:
                alerts.append(Alert(asset_id=asset.id, job_id=job_id, scan_type=scan_type.value, severity=AlertSeverity.WARNING, message=f'Scan all partial failures: {", ".join(failures)}'))
        if alerts:
            with store.lock:
                store.alerts.extend(alerts)

    def get_job(self, job_id: str) -> ScanJob:
        with store.lock:
            job = store.jobs.get(job_id)
        if not job:
            raise KeyError('scan job not found')
        return job

    def get_results(self, job_id: str) -> ScanResultsEnvelope:
        job = self.get_job(job_id)
        with store.lock:
            results = store.job_results.get(job_id, [])
        return ScanResultsEnvelope(job_id=job.id, scan_type=job.scan_type.value, results=results)

    def list_scans_for_asset(self, asset_id: str) -> list[ScanJob]:
        with store.lock:
            return [store.jobs[job_id] for job_id in store.asset_jobs.get(asset_id, [])]

    def get_all_results_for_asset(self, asset_id: str) -> list[dict]:
        output = []
        with store.lock:
            job_ids = list(store.asset_jobs.get(asset_id, []))
            for job_id in job_ids:
                job = store.jobs[job_id]
                output.append({'job_id': job_id, 'scan_type': job.scan_type.value, 'status': job.status.value, 'results': store.job_results.get(job_id, []), 'triggered_by': job.triggered_by})
        return output

    def get_latest_results_by_type(self, asset_id: str, scan_type: ScanType) -> list[dict]:
        with store.lock:
            job_ids = list(reversed(store.asset_jobs.get(asset_id, [])))
            for job_id in job_ids:
                job = store.jobs[job_id]
                if job.scan_type == scan_type:
                    return store.job_results.get(job_id, [])
        return []

    def list_alerts(self, asset_id: str | None = None) -> list[Alert]:
        with store.lock:
            alerts = list(store.alerts)
        if asset_id:
            alerts = [alert for alert in alerts if alert.asset_id == asset_id]
        return list(reversed(alerts))

    def compare_latest_two(self, asset_id: str, scan_type: ScanType) -> dict:
        # Comparison uses a normalized JSON representation so nested dict/list results
        # can be diffed safely without depending on field order.
        with store.lock:
            matching = [store.jobs[job_id] for job_id in store.asset_jobs.get(asset_id, []) if store.jobs[job_id].scan_type == scan_type and store.jobs[job_id].status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL}]
            matching = sorted(matching, key=lambda job: job.created_at, reverse=True)[:2]
            if not matching:
                return {'scan_type': scan_type.value, 'message': 'No completed scans found', 'previous': [], 'current': [], 'added': [], 'removed': []}
            current = store.job_results.get(matching[0].id, [])
            previous = store.job_results.get(matching[1].id, []) if len(matching) > 1 else []
        prev_set = {self._freeze_result(row) for row in previous}
        curr_set = {self._freeze_result(row) for row in current}
        added = [json.loads(item) for item in sorted(curr_set - prev_set)]
        removed = [json.loads(item) for item in sorted(prev_set - curr_set)]
        return {
            'scan_type': scan_type.value,
            'current_job_id': matching[0].id if matching else None,
            'previous_job_id': matching[1].id if len(matching) > 1 else None,
            'current_count': len(current),
            'previous_count': len(previous),
            'added_count': len(added),
            'removed_count': len(removed),
            'added': added,
            'removed': removed,
        }

    def export_asset_results_csv(self, asset_id: str) -> str:
        rows = self.get_all_results_for_asset(asset_id)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(['job_id', 'scan_type', 'status', 'triggered_by', 'result_index', 'result_json'])
        for row in rows:
            for idx, result in enumerate(row['results'] or []):
                writer.writerow([row['job_id'], row['scan_type'], row['status'], row.get('triggered_by', 'manual'), idx, json.dumps(result, ensure_ascii=False, sort_keys=True)])
        return buffer.getvalue()

    def export_asset_results_pdf(self, asset: Asset) -> bytes:
        rows = self.get_all_results_for_asset(asset.id)
        buffer = io.BytesIO()
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
        story = [Paragraph(f'EASM Report - {asset.name}', styles['Title']), Spacer(1, 12)]
        story.append(Paragraph(f'Asset type: {asset.type.value} | Tags: {", ".join(asset.tags) if asset.tags else "-"}', styles['BodyText']))
        story.append(Spacer(1, 12))
        summary_table = Table([
            ['Metric', 'Value'],
            ['Total jobs', str(len(rows))],
            ['Completed jobs', str(sum(1 for r in rows if r['status'] == 'completed'))],
            ['Failed/Partial jobs', str(sum(1 for r in rows if r['status'] in {'failed', 'partial'}))],
        ], colWidths=[160, 280])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f2937')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#94a3b8')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.extend([summary_table, Spacer(1, 16)])
        for row in rows:
            story.append(Paragraph(f"Scan: {row['scan_type']} - {row['status']} ({row.get('triggered_by', 'manual')})", styles['Heading3']))
            for result in row['results'][:10]:
                story.append(Paragraph(esc_pdf(json.dumps(result, ensure_ascii=False, indent=2)), styles['BodyText']))
                story.append(Spacer(1, 4))
            story.append(Spacer(1, 10))
        doc.build(story)
        return buffer.getvalue()

    def dashboard_summary(self) -> dict:
        assets = self.asset_service.list()
        jobs = [self.get_job(job_id) for asset in assets for job_id in store.asset_jobs.get(asset.id, [])]
        status_counts = Counter(job.status.value for job in jobs)
        scan_type_counts = Counter(job.scan_type.value for job in jobs)
        return {
            'total_assets': len(assets),
            'domain_assets': sum(1 for asset in assets if asset.type == AssetType.DOMAIN),
            'ip_assets': sum(1 for asset in assets if asset.type == AssetType.IP),
            'scheduled_scans': len(store.schedules),
            'alerts': len(store.alerts),
            'job_status': dict(status_counts),
            'scan_types': dict(scan_type_counts),
            'tags': self.asset_service.tag_summary(),
        }

    def _freeze_result(self, row: dict) -> str:
        return json.dumps(row, sort_keys=True, ensure_ascii=False)


def esc_pdf(text: str) -> str:
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>')
