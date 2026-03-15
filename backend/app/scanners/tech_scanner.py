from datetime import datetime, timezone
from app.scanners.base import Scanner
from app.models.asset import Asset

class TechScanner(Scanner):
    scan_type = 'tech'

    def scan(self, asset: Asset) -> list[dict]:
        return [{
            'domain': asset.name,
            'technologies': [
                {'name': 'nginx', 'category': 'Web Server', 'version': '1.24.0', 'confidence': 100},
                {'name': 'React', 'category': 'JavaScript Framework', 'version': '18.2.0', 'confidence': 95},
                {'name': 'Cloudflare', 'category': 'CDN', 'version': None, 'confidence': 100},
            ],
            'headers': {
                'server': 'nginx/1.24.0',
                'content-type': 'text/html; charset=utf-8',
                'x-frame-options': 'SAMEORIGIN',
            },
            'meta_tags': {
                'generator': 'React 18.2.0',
                'viewport': 'width=device-width, initial-scale=1',
            },
            'created_at': datetime.now(timezone.utc).isoformat(),
        }]
