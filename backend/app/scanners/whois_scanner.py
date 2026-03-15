from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from typing import Iterable

from app.models.asset import Asset
from app.scanners.base import Scanner

try:
    import whois  # type: ignore
except Exception:  # pragma: no cover
    whois = None


WHOIS_SERVER_MAP = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'app': 'whois.nic.google',
    'dev': 'whois.nic.google',
    'ai': 'whois.nic.ai',
    'vn': 'whois.vnnic.vn',
}


class WhoisScanner(Scanner):
    scan_type = 'whois'

    def scan(self, asset: Asset) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        parsed = self._scan_with_python_whois(asset.name)
        raw_text = parsed.pop('raw_text', '')
        if not raw_text:
            raw_text = self._socket_whois(asset.name)
            if raw_text:
                parsed = self._parse_raw(asset.name, raw_text)

        if not raw_text:
            parsed = self._demo_payload(asset.name)
            raw_text = parsed.pop('raw_text')

        parsed.setdefault('domain', asset.name)
        parsed.setdefault('registrar', 'Unavailable')
        parsed.setdefault('created_date', None)
        parsed.setdefault('expiration_date', None)
        parsed.setdefault('updated_date', None)
        parsed.setdefault('name_servers', [])
        parsed.setdefault('status', [])
        parsed.setdefault('emails', [])
        parsed.setdefault('whois_server', self._guess_server(asset.name))
        parsed['raw_text'] = raw_text
        parsed['created_at'] = now
        return [parsed]

    def _scan_with_python_whois(self, domain: str) -> dict:
        if whois is None:
            return {}
        try:
            data = whois.whois(domain)
        except Exception:
            return {}

        def normalize_date(value):
            if isinstance(value, list):
                value = next((v for v in value if v), None)
            return value.isoformat() if hasattr(value, 'isoformat') else value

        def normalize_list(value) -> list[str]:
            if value is None:
                return []
            if isinstance(value, (list, tuple, set)):
                return [str(v) for v in value if v]
            return [str(value)]

        raw = data.text if hasattr(data, 'text') else ''
        if isinstance(raw, list):
            raw = '\n'.join(str(v) for v in raw)

        return {
            'domain': domain,
            'registrar': getattr(data, 'registrar', None),
            'created_date': normalize_date(getattr(data, 'creation_date', None)),
            'expiration_date': normalize_date(getattr(data, 'expiration_date', None)),
            'updated_date': normalize_date(getattr(data, 'updated_date', None)),
            'name_servers': normalize_list(getattr(data, 'name_servers', None)),
            'status': normalize_list(getattr(data, 'status', None)),
            'emails': normalize_list(getattr(data, 'emails', None)),
            'org': getattr(data, 'org', None),
            'country': getattr(data, 'country', None),
            'whois_server': getattr(data, 'whois_server', None) or self._guess_server(domain),
            'raw_text': raw or '',
        }

    def _socket_whois(self, domain: str) -> str:
        server = self._guess_server(domain)
        raw = self._query_server(server, domain)
        if not raw:
            return ''

        referral = self._extract_referral(raw)
        if referral and referral.lower() != server.lower():
            referred = self._query_server(referral, domain)
            if referred:
                return referred
        return raw

    def _query_server(self, server: str, domain: str) -> str:
        try:
            with socket.create_connection((server, 43), timeout=8) as sock:
                sock.sendall((domain + '\r\n').encode('utf-8'))
                chunks: list[bytes] = []
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                return b''.join(chunks).decode('utf-8', errors='replace')
        except Exception:
            return ''

    def _extract_referral(self, raw_text: str) -> str | None:
        for line in raw_text.splitlines():
            lower = line.lower()
            if lower.startswith('whois server:') or lower.startswith('refer:'):
                return line.split(':', 1)[1].strip()
        return None

    def _guess_server(self, domain: str) -> str:
        tld = domain.rsplit('.', 1)[-1].lower()
        return WHOIS_SERVER_MAP.get(tld, 'whois.iana.org')

    def _parse_raw(self, domain: str, raw_text: str) -> dict:
        def pick(patterns: Iterable[str]) -> str | None:
            for pattern in patterns:
                match = re.search(pattern, raw_text, re.IGNORECASE | re.MULTILINE)
                if match:
                    return match.group(1).strip()
            return None

        def pick_all(pattern: str) -> list[str]:
            return [m.strip() for m in re.findall(pattern, raw_text, re.IGNORECASE | re.MULTILINE) if m.strip()]

        return {
            'domain': pick([r'^Domain Name:\s*(.+)$', r'^domain:\s*(.+)$']) or domain,
            'registrar': pick([r'^Registrar:\s*(.+)$', r'^registrar:\s*(.+)$']),
            'created_date': pick([r'^Creation Date:\s*(.+)$', r'^Created On:\s*(.+)$', r'^created:\s*(.+)$']),
            'expiration_date': pick([r'^Registry Expiry Date:\s*(.+)$', r'^Registrar Registration Expiration Date:\s*(.+)$', r'^Expiry Date:\s*(.+)$', r'^paid-till:\s*(.+)$']),
            'updated_date': pick([r'^Updated Date:\s*(.+)$', r'^Last Updated On:\s*(.+)$', r'^changed:\s*(.+)$']),
            'name_servers': pick_all(r'^Name Server:\s*(.+)$') or pick_all(r'^nserver:\s*(.+)$'),
            'status': pick_all(r'^Domain Status:\s*(.+)$') or pick_all(r'^status:\s*(.+)$'),
            'emails': pick_all(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'),
            'whois_server': self._extract_referral(raw_text) or self._guess_server(domain),
            'raw_text': raw_text,
        }

    def _demo_payload(self, domain: str) -> dict:
        now = datetime.now(timezone.utc)
        return {
            'domain': domain,
            'registrar': 'Demo Registrar',
            'created_date': now.replace(year=max(now.year - 5, 1970)).isoformat(),
            'expiration_date': now.replace(year=now.year + 1).isoformat(),
            'updated_date': now.isoformat(),
            'name_servers': [f'ns1.{domain}', f'ns2.{domain}'],
            'status': ['active'],
            'emails': [f'admin@{domain}'],
            'whois_server': self._guess_server(domain),
            'raw_text': (
                f'Domain Name: {domain}\n'
                'Registrar: Demo Registrar\n'
                f'Creation Date: {now.replace(year=max(now.year - 5, 1970)).isoformat()}\n'
                f'Registry Expiry Date: {now.replace(year=now.year + 1).isoformat()}\n'
                f'Name Server: ns1.{domain}\n'
                f'Name Server: ns2.{domain}\n'
            ),
        }
