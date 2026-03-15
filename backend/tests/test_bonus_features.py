import time

from fastapi.testclient import TestClient

from app.main import app
from app.scanners.dns_scanner import DNSScanner
from app.storage.memory import store

client = TestClient(app)


def setup_function():
    store.reset()


def wait_for_job(job_id: str, timeout: float = 2.0):
    end = time.time() + timeout
    while time.time() < end:
        res = client.get(f'/scan-jobs/{job_id}')
        data = res.json()
        if data['status'] in {'completed', 'failed', 'partial'}:
            return data
        time.sleep(0.02)
    return client.get(f'/scan-jobs/{job_id}').json()


def test_asset_tags_and_groups():
    created = client.post('/assets', json={'name': 'example.com', 'type': 'domain', 'tags': ['prod', 'web']})
    assert created.status_code == 201
    groups = client.get('/asset-groups').json()
    assert 'prod' in groups
    updated = client.patch(f"/assets/{created.json()['id']}/tags", json={'tags': ['critical']})
    assert updated.status_code == 200
    assert updated.json()['tags'] == ['critical']


def test_compare_and_export(monkeypatch):
    monkeypatch.setattr(DNSScanner, 'scan', lambda self, asset: [{'host': asset.name, 'record_type': 'A', 'value': '127.0.0.1', 'ttl': 60}])
    asset = client.post('/assets', json={'name': 'example.com', 'type': 'domain'}).json()
    job1 = client.post(f"/assets/{asset['id']}/scan", json={'scan_type': 'dns'}).json()['id']
    wait_for_job(job1)
    monkeypatch.setattr(DNSScanner, 'scan', lambda self, asset: [{'host': asset.name, 'record_type': 'A', 'value': '127.0.0.2', 'ttl': 60}])
    job2 = client.post(f"/assets/{asset['id']}/scan", json={'scan_type': 'dns'}).json()['id']
    wait_for_job(job2)
    compare = client.get(f"/assets/{asset['id']}/compare", params={'scan_type': 'dns'})
    assert compare.status_code == 200
    payload = compare.json()
    assert payload['added_count'] == 1
    assert payload['removed_count'] == 1

    csv_res = client.get(f"/assets/{asset['id']}/export.csv")
    assert csv_res.status_code == 200
    assert 'text/csv' in csv_res.headers['content-type']

    pdf_res = client.get(f"/assets/{asset['id']}/export.pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.content.startswith(b'%PDF')


def test_alerts_generated_for_port_results(monkeypatch):
    from app.scanners.port_scanner import PortScanner
    monkeypatch.setattr(PortScanner, 'scan', lambda self, asset: [{'ip_address': asset.name, 'open_ports': [{'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH'}], 'closed_ports': 998, 'total_scanned': 999, 'scan_duration_ms': 10}])
    asset = client.post('/assets', json={'name': '127.0.0.1', 'type': 'ip'}).json()
    job = client.post(f"/assets/{asset['id']}/scan", json={'scan_type': 'port'}).json()['id']
    wait_for_job(job)
    alerts = client.get('/alerts').json()
    assert any('Open ports detected' in alert['message'] for alert in alerts)
