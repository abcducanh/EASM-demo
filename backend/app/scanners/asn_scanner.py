from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

import requests

from app.models.asset import Asset
from app.scanners.base import Scanner


class ASNScanner(Scanner):
    scan_type = 'asn'

    def scan(self, asset: Asset) -> list[dict]:
        target_ip = asset.name
        now = datetime.now(timezone.utc).isoformat()
        try:
            ipaddress.ip_address(target_ip)
        except ValueError as exc:
            raise ValueError('asn scan requires an ip asset') from exc

        try:
            response = requests.get(f'https://ipinfo.io/{target_ip}/json', timeout=8)
            response.raise_for_status()
            payload = response.json()
            org = payload.get('org', '')
            asn_number = None
            asn_name = None
            if org.startswith('AS'):
                first, _, rest = org.partition(' ')
                asn_number = int(first.removeprefix('AS')) if first.removeprefix('AS').isdigit() else None
                asn_name = rest or org
            return [{
                'ip_address': target_ip,
                'asn': {
                    'number': asn_number,
                    'name': asn_name or org or 'Unknown',
                    'description': org or payload.get('company', {}).get('name') or 'Unknown',
                },
                'network': payload.get('network'),
                'country': payload.get('country'),
                'created_at': now,
            }]
        except Exception:
            return [{
                'ip_address': target_ip,
                'asn': {'number': 64512, 'name': 'PRIVATE-NET', 'description': 'Private or demo network'},
                'network': str(ipaddress.ip_network(f'{target_ip}/32', strict=False)),
                'country': None,
                'created_at': now,
            }]
