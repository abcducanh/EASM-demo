from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4
from pydantic import BaseModel, Field, model_validator
import ipaddress
import re

DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$')

class AssetType(str, Enum):
    DOMAIN = 'domain'
    IP = 'ip'

class ScanType(str, Enum):
    DNS = 'dns'
    WHOIS = 'whois'
    SUBDOMAIN = 'subdomain'
    CERT_TRANS = 'cert_trans'
    ASN = 'asn'
    ALL = 'all'
    IP = 'ip'
    PORT = 'port'
    SSL = 'ssl'
    TECH = 'tech'

class ScanStatus(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    PARTIAL = 'partial'

class AssetCreate(BaseModel):
    name: str
    type: AssetType
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def validate_name(self):
        self.tags = sorted({tag.strip().lower() for tag in self.tags if tag and tag.strip()})
        if self.type == AssetType.DOMAIN and not DOMAIN_RE.match(self.name):
            raise ValueError('invalid domain')
        if self.type == AssetType.IP:
            try:
                ipaddress.ip_address(self.name)
            except ValueError as exc:
                raise ValueError('invalid ip') from exc
        return self

class AssetUpdateTags(BaseModel):
    tags: list[str] = Field(default_factory=list)

class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    type: AssetType
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanRequest(BaseModel):
    scan_type: ScanType

class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    asset_id: str
    scan_type: ScanType
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None
    error: str = ''
    results: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    triggered_by: str = 'manual'

class ScanResultsEnvelope(BaseModel):
    job_id: str
    scan_type: str
    results: list[dict]

class ScheduledScanCreate(BaseModel):
    scan_type: ScanType
    interval_minutes: int = Field(ge=1, le=1440)

class ScheduledScan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    asset_id: str
    scan_type: ScanType
    interval_minutes: int
    enabled: bool = True
    last_run_at: Optional[datetime] = None
    next_run_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AlertSeverity(str, Enum):
    INFO = 'info'
    WARNING = 'warning'
    HIGH = 'high'

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    asset_id: str
    job_id: str
    scan_type: str
    severity: AlertSeverity
    message: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
