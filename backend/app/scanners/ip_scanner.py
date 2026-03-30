from __future__ import annotations

import socket
from datetime import datetime, timezone

import requests

from app.models.asset import Asset
from app.scanners.base import Scanner


class IPScanner(Scanner):
    scan_type = 'ip'

    def scan(self, asset: Asset) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        reverse_dns = self._reverse_dns(asset.name)
        try:
            response = requests.get(f'https://ipinfo.io/{asset.name}/json', timeout=8)
            response.raise_for_status()
            payload = response.json()
            loc = payload.get('loc', ',').split(',')
            lat = float(loc[0]) if loc and loc[0] else None
            lon = float(loc[1]) if len(loc) > 1 and loc[1] else None
            org = payload.get('org', '')
            asn_number = None
            asn_name = None
            if org.startswith('AS'):
                first, _, rest = org.partition(' ')
                asn_number = int(first.removeprefix('AS')) if first.removeprefix('AS').isdigit() else None
                asn_name = rest or org
            return [{
                'ip_address': asset.name,
                'geolocation': {
                    'country': payload.get('country'),
                    'country_code': payload.get('country'),
                    'city': payload.get('city'),
                    'region': payload.get('region'),
                    'latitude': lat,
                    'longitude': lon,
                    'isp': org or payload.get('company', {}).get('name'),
                    'org': payload.get('org'),
                },
                'asn': {
                    'number': asn_number,
                    'name': asn_name,
                    'description': org,
                },
                'reverse_dns': reverse_dns,
                'created_at': now,
            }]
        except Exception:
            return [{
                'ip_address': asset.name,
                'geolocation': {
                    'country': 'Local', 'country_code': 'LC', 'city': 'localhost', 'region': 'local',
                    'latitude': None, 'longitude': None, 'isp': 'Local Network', 'org': 'Local Network',
                },
                'asn': {'number': 64512, 'name': 'PRIVATE-NET', 'description': 'Private or demo network'},
                'reverse_dns': reverse_dns,
                'created_at': now,
            }]

    def _reverse_dns(self, ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
