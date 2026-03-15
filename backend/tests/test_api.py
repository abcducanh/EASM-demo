import time

from fastapi.testclient import TestClient

from app.main import app
from app.scanners.dns_scanner import DNSScanner
from app.scanners.subdomain_scanner import SubdomainScanner
from app.storage.memory import store

client = TestClient(app)


def wait_for_job(job_id: str, timeout: float = 12.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        res = client.get(f'/scan-jobs/{job_id}')
        assert res.status_code == 200
        last = res.json()
        if last['status'] in ['completed', 'failed', 'partial']:
            return last
        time.sleep(0.05)
    return last


def setup_function():
    store.reset()


def test_asset_and_scan_flow():
    asset = client.post('/assets', json={'name': 'example.com', 'type': 'domain'})
    assert asset.status_code == 201
    asset_id = asset.json()['id']

    scan = client.post(f'/assets/{asset_id}/scan', json={'scan_type': 'dns'})
    assert scan.status_code == 202
    assert scan.json()['status'] == 'pending'
    job_id = scan.json()['id']

    status = wait_for_job(job_id)
    assert status['status'] in ['completed', 'partial']

    results = client.get(f'/scan-jobs/{job_id}/results')
    assert results.status_code == 200
    assert results.json()['scan_type'] == 'dns'


def test_scan_all_for_ip():
    asset = client.post('/assets', json={'name': '127.0.0.1', 'type': 'ip'})
    asset_id = asset.json()['id']
    scan = client.post(f'/assets/{asset_id}/scan', json={'scan_type': 'all'})
    assert scan.status_code == 202
    assert scan.json()['status'] == 'pending'
    job_id = scan.json()['id']

    wait_for_job(job_id)
    results = client.get(f'/scan-jobs/{job_id}/results').json()
    assert results['scan_type'] == 'all'
    assert len(results['results']) >= 1
    assert any(item['scan_type'] == 'asn' for item in results['results'])


def test_discovery_from_dns_only(monkeypatch):
    monkeypatch.setattr(DNSScanner, 'scan', lambda self, asset: [
        {'domain': asset.name, 'host': asset.name, 'record_type': 'A', 'value': '127.0.0.1', 'ttl': 60}
    ])
    monkeypatch.setattr(SubdomainScanner, 'scan', lambda self, asset: [
        {'domain': asset.name, 'subdomain': f'api.{asset.name}', 'source': 'test'}
    ])

    asset = client.post('/assets', json={'name': 'example.com', 'type': 'domain'})
    asset_id = asset.json()['id']
    dns_scan = client.post(f'/assets/{asset_id}/scan', json={'scan_type': 'dns'})
    assert dns_scan.status_code == 202
    wait_for_job(dns_scan.json()['id'])

    sub_scan = client.post(f'/assets/{asset_id}/scan', json={'scan_type': 'subdomain'})
    assert sub_scan.status_code == 202
    wait_for_job(sub_scan.json()['id'])

    assets = client.get('/assets').json()
    assert any(a['name'] == '127.0.0.1' and a['type'] == 'ip' for a in assets)
    assert not any(a['name'] == 'api.example.com' and a['type'] == 'domain' for a in assets)


def test_asset_specific_result_endpoints(monkeypatch):
    monkeypatch.setattr(DNSScanner, 'scan', lambda self, asset: [
        {'domain': asset.name, 'host': asset.name, 'record_type': 'A', 'type': 'A', 'value': '1.1.1.1', 'ttl': 300}
    ])

    asset = client.post('/assets', json={'name': 'example.com', 'type': 'domain'}).json()
    job = client.post(f"/assets/{asset['id']}/scan", json={'scan_type': 'dns'}).json()
    wait_for_job(job['id'])

    dns = client.get(f"/assets/{asset['id']}/dns")
    assert dns.status_code == 200
    assert dns.json()[0]['value'] == '1.1.1.1'


def test_delete_all_assets():
    client.post('/assets', json={'name': 'example.com', 'type': 'domain'})
    client.post('/assets', json={'name': '127.0.0.1', 'type': 'ip'})
    res = client.delete('/assets')
    assert res.status_code == 200
    assert client.get('/assets').json() == []
