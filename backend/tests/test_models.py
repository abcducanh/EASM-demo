import pytest
from pydantic import ValidationError

from app.models.asset import AssetCreate, AssetType, ScanJob, ScanRequest, ScanStatus, ScanType


@pytest.mark.parametrize(
    ('name', 'payload', 'want_error'),
    [
        ('valid domain asset', {'name': 'example.com', 'type': 'domain'}, False),
        ('valid ip asset', {'name': '127.0.0.1', 'type': 'ip'}, False),
        ('invalid asset type', {'name': 'test', 'type': 'invalid'}, True),
        ('invalid domain name', {'name': 'not a domain', 'type': 'domain'}, True),
        ('invalid ip', {'name': '999.999.999.999', 'type': 'ip'}, True),
        ('domain can have subdomain', {'name': 'api.example.com', 'type': 'domain'}, False),
    ],
)
def test_asset_validation(name, payload, want_error):
    if want_error:
        with pytest.raises(ValidationError):
            AssetCreate(**payload)
    else:
        asset = AssetCreate(**payload)
        assert asset.name == payload['name']
        assert asset.type.value == payload['type']


def test_scan_request_accepts_extended_scan_types():
    for scan_type in ['dns', 'whois', 'subdomain', 'cert_trans', 'asn', 'all', 'ip', 'port', 'ssl', 'tech']:
        request = ScanRequest(scan_type=scan_type)
        assert request.scan_type.value == scan_type


@pytest.mark.parametrize(
    ('scan_type', 'status'),
    [
        (ScanType.DNS, ScanStatus.PENDING),
        (ScanType.PORT, ScanStatus.RUNNING),
        (ScanType.SSL, ScanStatus.COMPLETED),
    ],
)
def test_scan_job_defaults_and_values(scan_type, status):
    job = ScanJob(asset_id='asset-1', scan_type=scan_type, status=status)
    assert job.asset_id == 'asset-1'
    assert job.scan_type == scan_type
    assert job.status == status
    assert job.results == 0
    assert job.error == ''
    assert job.ended_at is None


def test_asset_type_enum_values_are_stable():
    assert AssetType.DOMAIN.value == 'domain'
    assert AssetType.IP.value == 'ip'
