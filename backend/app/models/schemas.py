"""
NetSentinel - Database & API Schemas

SQLAlchemy ORM models for persisting scan data, and Pydantic schemas
for request/response validation.
"""

import enum
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Enum, ForeignKey, Text, Boolean, JSON, Float
)
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field
from app.models.database import Base


# ──────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ──────────────────────────────────────────────
# SQLAlchemy ORM Models
# ──────────────────────────────────────────────

class Scan(Base):
    """Represents a single network scan job."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)  # e.g. "192.168.1.0/24"
    scan_type = Column(String(50), default="full")  # full, quick, arp_only, port_only
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    total_hosts = Column(Integer, default=0)
    total_open_ports = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # Relationships
    hosts = relationship("Host", back_populates="scan", cascade="all, delete-orphan")


class Host(Base):
    """A discovered host on the network."""
    __tablename__ = "hosts"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    ip_address = Column(String(45), nullable=False)
    mac_address = Column(String(17), nullable=True)
    hostname = Column(String(255), nullable=True)
    os_guess = Column(String(255), nullable=True)
    os_confidence = Column(Float, nullable=True)
    ttl = Column(Integer, nullable=True)
    is_up = Column(Boolean, default=True)
    response_time_ms = Column(Float, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")


class Port(Base):
    """An open or filtered port on a discovered host."""
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")  # tcp or udp
    state = Column(Enum(PortState), default=PortState.OPEN)
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(255), nullable=True)
    banner = Column(Text, nullable=True)

    # Relationships
    host = relationship("Host", back_populates="ports")


class Vulnerability(Base):
    """A detected vulnerability or compliance finding."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(Integer, ForeignKey("hosts.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.INFO)
    port_number = Column(Integer, nullable=True)
    service = Column(String(100), nullable=True)
    remediation = Column(Text, nullable=True)  # AI-generated fix
    cve_id = Column(String(20), nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    host = relationship("Host", back_populates="vulnerabilities")


class GoldenBaseline(Base):
    """A baseline configuration for compliance checking."""
    __tablename__ = "golden_baselines"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    framework = Column(String(50), nullable=True)  # e.g., "CIS", "NIST", "Custom"
    rules = Column(JSON, nullable=False)  # JSON array of compliance rules
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SystemEvent(Base):
    """System-wide activity log events."""
    __tablename__ = "system_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False) # 'scan_started', 'scan_completed', 'baseline_created', etc.
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="info") # 'info', 'warning', 'error'
    created_at = Column(DateTime, default=datetime.utcnow)
    metadata_json = Column(JSON, nullable=True) # Extra context


# ──────────────────────────────────────────────
# Pydantic Schemas (API Request/Response)
# ──────────────────────────────────────────────

# -- Scan Schemas --

class ScanCreate(BaseModel):
    """Request body to create a new scan."""
    target: str = Field(..., description="Target network (e.g. 192.168.1.0/24 or single IP)")
    scan_type: str = Field(default="full", description="Scan type: full, quick, arp_only, port_only")
    ports: Optional[str] = Field(default=None, description="Port range (e.g. '1-1024' or '22,80,443')")
    timeout: Optional[int] = Field(default=5, description="Timeout per probe in seconds")


class PortResponse(BaseModel):
    id: int
    port_number: int
    protocol: str
    state: PortState
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None

    model_config = {"from_attributes": True}


class VulnerabilityResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: SeverityLevel
    port_number: Optional[int] = None
    service: Optional[str] = None
    remediation: Optional[str] = None
    cve_id: Optional[str] = None
    detected_at: datetime

    model_config = {"from_attributes": True}


class HostResponse(BaseModel):
    id: int
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    os_confidence: Optional[float] = None
    ttl: Optional[int] = None
    is_up: bool
    response_time_ms: Optional[float] = None
    discovered_at: datetime
    ports: list[PortResponse] = []
    vulnerabilities: list[VulnerabilityResponse] = []

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_hosts: int
    total_open_ports: int
    total_vulnerabilities: int
    error_message: Optional[str] = None
    hosts: list[HostResponse] = []

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    """Lightweight scan response (no nested hosts)."""
    id: int
    target: str
    scan_type: str
    status: ScanStatus
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_hosts: int
    total_open_ports: int
    total_vulnerabilities: int

    model_config = {"from_attributes": True}


# -- Baseline Schemas --

class BaselineCreate(BaseModel):
    name: str
    description: Optional[str] = None
    framework: Optional[str] = None
    rules: list[dict] = Field(..., description="List of compliance rule objects")


class BaselineResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    framework: Optional[str] = None
    rules: list[dict]
    created_at: datetime

    model_config = {"from_attributes": True}


# -- Remediation Schemas --

class RemediationRequest(BaseModel):
    host_ip: str
    findings: list[dict] = Field(..., description="List of findings to get remediation for")


class RemediationResponse(BaseModel):
    host_ip: str
    remediation_steps: str
    severity_summary: dict
    generated_at: datetime


# -- Dashboard Stats --

class DashboardStats(BaseModel):
    total_scans: int
    total_hosts_discovered: int
    total_open_ports: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    recent_scans: list[ScanSummary]

class SystemEventResponse(BaseModel):
    id: int
    event_type: str
    description: str
    severity: str
    created_at: datetime
    metadata_json: Optional[dict] = None

    class Config:
        from_attributes = True

