import time

import pytest

from app.models.asset import Asset, AssetCreate, AssetType, ScanRequest, ScanStatus, ScanType
from app.scanners.dns_scanner import DNSScanner
from app.services.asset_service import AssetService
from app.services.scan_service import ScanService
from app.storage.memory import store


@pytest.fixture(autouse=True)
def reset_store():
    store.reset()
    yield
    store.reset()


class TestAssetService:
    def test_create_returns_existing_asset_for_duplicate(self):
        service = AssetService()
        first = service.create(AssetCreate(name='example.com', type='domain'))
        second = service.create(AssetCreate(name='example.com', type='domain'))

        assert first.id == second.id
        assert len(service.list()) == 1

    def test_create_if_missing_creates_and_finds(self):
        service = AssetService()
        asset = service.create_if_missing('127.0.0.1', AssetType.IP)

        assert service.find_by_name_and_type('127.0.0.1', AssetType.IP).id == asset.id

    def test_get_raises_for_unknown_asset(self):
        service = AssetService()
        with pytest.raises(KeyError):
            service.get('missing')


class TestScanService:
    def wait_for_job(self, service: ScanService, job_id: str, timeout: float = 3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = service.get_job(job_id)
            if job.status in {ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED}:
                return job
            time.sleep(0.02)
        return service.get_job(job_id)

    def test_start_scan_creates_job_and_results(self, monkeypatch):
        monkeypatch.setattr(DNSScanner, 'scan', lambda self, asset: [
            {'domain': asset.name, 'host': asset.name, 'record_type': 'A', 'value': '127.0.0.1', 'ttl': 60}
        ])
        asset_service = AssetService()
        asset = asset_service.create(AssetCreate(name='example.com', type='domain'))
        service = ScanService()

        job = service.start_scan(asset, ScanRequest(scan_type='dns'))
        finished = self.wait_for_job(service, job.id)
        envelope = service.get_results(job.id)

        assert finished.status == ScanStatus.COMPLETED
        assert envelope.scan_type == 'dns'
        assert envelope.results[0]['value'] == '127.0.0.1'
        assert asset_service.find_by_name_and_type('127.0.0.1', AssetType.IP) is not None

    def test_scan_all_for_ip_returns_grouped_results(self):
        asset = AssetService().create(AssetCreate(name='127.0.0.1', type='ip'))
        service = ScanService()
        service.scanners[ScanType.IP] = SimpleScanner([{'ip_address': '127.0.0.1'}])
        service.scanners[ScanType.ASN] = SimpleScanner([{'ip_address': '127.0.0.1', 'asn': {'number': 64512}}])
        service.scanners[ScanType.PORT] = SimpleScanner([{'ip_address': '127.0.0.1', 'open_ports': []}])

        job = service.start_scan(asset, ScanRequest(scan_type='all'))
        finished = self.wait_for_job(service, job.id)
        results = service.get_results(job.id)

        assert finished.status == ScanStatus.COMPLETED
        assert results.scan_type == 'all'
        assert {item['scan_type'] for item in results.results} == {'ip', 'asn', 'port'}

    def test_validate_scan_rejects_invalid_combo(self):
        service = ScanService()
        asset = Asset(id='a1', name='example.com', type='domain')
        with pytest.raises(ValueError):
            service.start_scan(asset, ScanRequest(scan_type='port'))


class SimpleScanner:
    def __init__(self, payload):
        self.payload = payload

    def scan(self, asset):
        return self.payload
