from abc import ABC, abstractmethod
from app.models.asset import Asset

class Scanner(ABC):
    scan_type: str

    @abstractmethod
    def scan(self, asset: Asset) -> list[dict]:
        raise NotImplementedError
