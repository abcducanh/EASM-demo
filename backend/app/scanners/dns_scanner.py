from __future__ import annotations

import socket
from datetime import datetime, timezone

import requests

from app.models.asset import Asset
from app.scanners.base import Scanner


class DNSScanner(Scanner):
    scan_type = 'dns'

    def scan(self, asset: Asset) -> list[dict]:
        records: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()
        seen: set[tuple[str, str]] = set()

        def add_record(record_type: str, value: str, ttl: int | None = None, host: str | None = None):
            key = (record_type, value)
            if key in seen or not value:
                return
            seen.add(key)
            records.append({
                'domain': asset.name,
                'host': host or asset.name,
                'record_type': record_type,
                'type': record_type,
                'value': value,
                'ttl': ttl if ttl is not None else 300,
                'created_at': now,
            })

        try:
            infos = socket.getaddrinfo(asset.name, None, proto=socket.IPPROTO_TCP)
            for info in infos:
                address = info[4][0]
                add_record('AAAA' if ':' in address else 'A', address)
        except Exception:
            pass

        records.extend(self._query_doh(asset.name, add_record))

        if not records:
            add_record('A', '0.0.0.0')
        return records

    def _query_doh(self, domain: str, add_record) -> list[dict]:
        collected: list[dict] = []
        for record_type in ['A', 'MX', 'NS']:
            try:
                response = requests.get(
                    'https://cloudflare-dns.com/dns-query',
                    headers={'accept': 'application/dns-json'},
                    params={'name': domain, 'type': record_type},
                    timeout=2,
                )
                response.raise_for_status()
                payload = response.json()
                for item in payload.get('Answer', []) or []:
                    value = str(item.get('data', ''))
                    ttl = item.get('TTL', 300)
                    add_record(record_type, value, ttl)
            except Exception:
                continue
        return collected
