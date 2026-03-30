import socket
from datetime import datetime, timezone
from app.scanners.base import Scanner
from app.models.asset import Asset
from app.scanners.helpers import is_safe_ip

class PortScanner(Scanner):
    scan_type = 'port'
    ports = [22, 53, 80, 443, 3306, 5432, 6379, 8080]

    def scan(self, asset: Asset) -> list[dict]:
        if not is_safe_ip(asset.name):
            raise ValueError('port scan only allowed for localhost/private IP ranges')
        open_ports = []
        for port in self.ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.15)
            try:
                if sock.connect_ex((asset.name, port)) == 0:
                    service = {
                        22: 'ssh', 53: 'dns', 80: 'http', 443: 'https',
                        3306: 'mysql', 5432: 'postgresql', 6379: 'redis', 8080: 'http-alt'
                    }.get(port, 'unknown')
                    open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service,
                        'version': '',
                    })
            finally:
                sock.close()
        total = len(self.ports)
        return [{
            'ip_address': asset.name,
            'open_ports': open_ports,
            'closed_ports': total - len(open_ports),
            'total_scanned': total,
            'scan_duration_ms': total * 150,
            'created_at': datetime.now(timezone.utc).isoformat(),
        }]
