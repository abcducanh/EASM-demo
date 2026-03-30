from __future__ import annotations

from datetime import datetime, timezone

import requests

from app.models.asset import Asset
from app.scanners.base import Scanner


COMMON_PREFIXES = ['www', 'api', 'mail', 'dev', 'staging', 'blog']


class SubdomainScanner(Scanner):
    scan_type = 'subdomain'

    def scan(self, asset: Asset) -> list[dict]:
        now = datetime.now(timezone.utc).isoformat()
        items: list[dict] = []
        seen: set[str] = set()

        for name in self._from_crtsh(asset.name) + [f'{prefix}.{asset.name}' for prefix in COMMON_PREFIXES]:
            subdomain = name.lower().strip('*.')
            if not subdomain or subdomain == asset.name or subdomain in seen:
                continue
            seen.add(subdomain)
            items.append({'domain': asset.name, 'subdomain': subdomain, 'source': 'crt.sh' if subdomain not in [f'{p}.{asset.name}' for p in COMMON_PREFIXES] else 'wordlist', 'created_at': now})
        return items[:50]

    def _from_crtsh(self, domain: str) -> list[str]:
        try:
            response = requests.get('https://crt.sh/', params={'q': f'%.{domain}', 'output': 'json'}, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except Exception:
            return []

        names: list[str] = []
        for row in payload[:200]:
            raw = row.get('name_value', '')
            for entry in str(raw).splitlines():
                entry = entry.strip()
                if entry.endswith(domain):
                    names.append(entry)
        return names
