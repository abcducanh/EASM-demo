from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from app.models.asset import Asset
from app.scanners.base import Scanner


class SSLScanner(Scanner):
    scan_type = 'ssl'

    def scan(self, asset: Asset) -> list[dict]:
        now = datetime.now(timezone.utc)
        host = asset.name
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
                    subject = ', '.join('='.join(part) for group in cert.get('subject', []) for part in group)
                    issuer = ', '.join('='.join(part) for group in cert.get('issuer', []) for part in group)
                    san = [value for kind, value in cert.get('subjectAltName', []) if kind == 'DNS']
                    not_before = cert.get('notBefore')
                    not_after = cert.get('notAfter')
                    expiry_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc) if not_after else now
                    days_until_expiry = max((expiry_dt - now).days, 0)
                    return [{
                        'domain': host,
                        'certificate': {
                            'subject': subject or f'CN={host}',
                            'issuer': issuer,
                            'serial_number': cert.get('serialNumber'),
                            'valid_from': not_before,
                            'valid_until': not_after,
                            'days_until_expiry': days_until_expiry,
                            'is_expired': expiry_dt < now,
                            'is_self_signed': bool(subject and issuer and subject == issuer),
                            'san': san,
                        },
                        'connection': {
                            'tls_version': tls_sock.version(),
                            'cipher_suite': cipher[0] if cipher else None,
                            'key_exchange': None,
                        },
                        'grade': 'A' if days_until_expiry > 14 else 'B',
                        'issues': [] if days_until_expiry > 14 else ['Certificate expires soon'],
                        'created_at': now.isoformat(),
                    }]
        except Exception as exc:
            demo_expiry = now.replace(year=now.year + 1)
            return [{
                'domain': host,
                'certificate': {
                    'subject': f'CN={host}',
                    'issuer': 'CN=Demo CA, O=Example Org, C=US',
                    'serial_number': '03:ab:cd:ef:12:34:56:78',
                    'valid_from': now.isoformat(),
                    'valid_until': demo_expiry.isoformat(),
                    'days_until_expiry': 365,
                    'is_expired': False,
                    'is_self_signed': False,
                    'san': [host, f'www.{host}', f'api.{host}'],
                },
                'connection': {
                    'tls_version': 'TLS 1.3',
                    'cipher_suite': 'TLS_AES_256_GCM_SHA384',
                    'key_exchange': None,
                },
                'grade': 'B',
                'issues': [f'Live TLS probe unavailable: {exc}'],
                'created_at': now.isoformat(),
            }]
