from types import SimpleNamespace

import pytest

from app.models.asset import Asset
from app.scanners.asn_scanner import ASNScanner
from app.scanners.cert_trans_scanner import CertTransparencyScanner
from app.scanners.dns_scanner import DNSScanner
from app.scanners.ip_scanner import IPScanner
from app.scanners.port_scanner import PortScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.subdomain_scanner import SubdomainScanner
from app.scanners.tech_scanner import TechScanner
from app.scanners.whois_scanner import WhoisScanner


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_dns_scanner_scan(monkeypatch):
    monkeypatch.setattr('socket.getaddrinfo', lambda *args, **kwargs: [(None, None, None, None, ('142.250.72.14', 0))])
    monkeypatch.setattr(DNSScanner, '_query_doh', lambda self, domain, add_record: add_record('MX', f'mx.{domain}', 600) or [])

    scanner = DNSScanner()
    result = scanner.scan(Asset(name='google.com', type='domain'))

    assert any(row['record_type'] == 'A' for row in result)
    assert any(row['record_type'] == 'MX' for row in result)
    assert all('value' in row for row in result)


def test_whois_scanner_scan(monkeypatch):
    monkeypatch.setattr(WhoisScanner, '_scan_with_python_whois', lambda self, domain: {
        'domain': domain,
        'registrar': 'Example Registrar',
        'created_date': '2020-01-01T00:00:00Z',
        'expiration_date': '2030-01-01T00:00:00Z',
        'updated_date': '2024-01-01T00:00:00Z',
        'name_servers': ['ns1.example.com'],
        'status': ['active'],
        'emails': ['admin@example.com'],
        'whois_server': 'whois.example.com',
        'raw_text': 'Domain Name: GOOGLE.COM',
    })

    scanner = WhoisScanner()
    result = scanner.scan(Asset(name='google.com', type='domain'))

    assert result[0]['domain'] == 'google.com'
    assert result[0]['registrar'] == 'Example Registrar'
    assert 'raw_text' in result[0]


def test_subdomain_scanner_scan(monkeypatch):
    monkeypatch.setattr(SubdomainScanner, '_from_crtsh', lambda self, domain: [f'www.{domain}', f'api.{domain}', f'www.{domain}'])
    scanner = SubdomainScanner()

    result = scanner.scan(Asset(name='google.com', type='domain'))

    names = [row['subdomain'] for row in result]
    assert 'www.google.com' in names
    assert 'api.google.com' in names
    assert len(names) == len(set(names))


def test_cert_transparency_scanner_scan(monkeypatch):
    monkeypatch.setattr('requests.get', lambda *args, **kwargs: FakeResponse([
        {'common_name': 'www.google.com', 'issuer_name': 'Google Trust Services'},
        {'common_name': 'www.google.com', 'issuer_name': 'Google Trust Services'},
        {'name_value': 'mail.google.com', 'issuer_name': 'Google Trust Services'},
    ]))
    scanner = CertTransparencyScanner()

    result = scanner.scan(Asset(name='google.com', type='domain'))

    assert len(result) == 2
    assert result[0]['common_name'] == 'www.google.com'


def test_asn_scanner_scan(monkeypatch):
    monkeypatch.setattr('requests.get', lambda *args, **kwargs: FakeResponse({'org': 'AS13335 CLOUDFLARENET', 'network': '104.21.32.0/24', 'country': 'US'}))
    scanner = ASNScanner()

    result = scanner.scan(Asset(name='104.21.32.1', type='ip'))

    assert result[0]['ip_address'] == '104.21.32.1'
    assert result[0]['asn']['number'] == 13335
    assert result[0]['asn']['name'] == 'CLOUDFLARENET'


def test_ip_scanner_scan(monkeypatch):
    monkeypatch.setattr(IPScanner, '_reverse_dns', lambda self, ip: 'one.one.one.one')
    monkeypatch.setattr('requests.get', lambda *args, **kwargs: FakeResponse({
        'country': 'US', 'city': 'San Francisco', 'region': 'California', 'loc': '37.7749,-122.4194', 'org': 'AS13335 CLOUDFLARENET'
    }))
    scanner = IPScanner()

    result = scanner.scan(Asset(name='104.21.32.1', type='ip'))

    assert result[0]['reverse_dns'] == 'one.one.one.one'
    assert result[0]['geolocation']['country'] == 'US'
    assert result[0]['asn']['number'] == 13335


def test_port_scanner_scan(monkeypatch):
    class FakeSocket:
        def __init__(self, *args, **kwargs):
            self.port = None

        def settimeout(self, timeout):
            return None

        def connect_ex(self, target):
            _, self.port = target
            return 0 if self.port in {22, 80} else 1

        def close(self):
            return None

    monkeypatch.setattr('socket.socket', lambda *args, **kwargs: FakeSocket())
    scanner = PortScanner()

    result = scanner.scan(Asset(name='127.0.0.1', type='ip'))

    assert [port['port'] for port in result[0]['open_ports']] == [22, 80]
    assert result[0]['closed_ports'] == result[0]['total_scanned'] - 2


def test_port_scanner_rejects_public_ip():
    scanner = PortScanner()
    with pytest.raises(ValueError):
        scanner.scan(Asset(name='8.8.8.8', type='ip'))


def test_ssl_scanner_scan(monkeypatch):
    class FakeTLS:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def getpeercert(self):
            return {
                'subject': ((('CN', 'example.com'),),),
                'issuer': ((('CN', 'Example CA'),),),
                'serialNumber': '1234',
                'subjectAltName': [('DNS', 'example.com'), ('DNS', 'www.example.com')],
                'notBefore': 'Jan 01 00:00:00 2026 GMT',
                'notAfter': 'Jan 01 00:00:00 2027 GMT',
            }

        def cipher(self):
            return ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)

        def version(self):
            return 'TLS 1.3'

    class FakeSocketContext:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr('socket.create_connection', lambda *args, **kwargs: FakeSocketContext())
    monkeypatch.setattr('ssl.create_default_context', lambda: SimpleNamespace(wrap_socket=lambda sock, server_hostname=None: FakeTLS()))

    scanner = SSLScanner()
    result = scanner.scan(Asset(name='example.com', type='domain'))

    assert result[0]['domain'] == 'example.com'
    assert 'CN=example.com' in result[0]['certificate']['subject']
    assert result[0]['connection']['tls_version'] == 'TLS 1.3'


def test_tech_scanner_scan():
    scanner = TechScanner()
    result = scanner.scan(Asset(name='google.com', type='domain'))

    assert result[0]['domain'] == 'google.com'
    assert len(result[0]['technologies']) >= 1
    assert 'server' in result[0]['headers']
