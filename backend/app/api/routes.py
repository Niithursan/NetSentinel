"""
NetSentinel - API Routes

FastAPI endpoints for managing scans, hosts, baselines, and AI remediation.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.database import get_db
from app.models.schemas import (
    Scan, Host, Port, Vulnerability, GoldenBaseline, SystemEvent,
    ScanCreate, ScanResponse, ScanSummary, HostResponse,
    BaselineCreate, BaselineResponse,
    RemediationRequest, RemediationResponse,
    DashboardStats, ScanStatus, SeverityLevel,
    VulnerabilityResponse, SystemEventResponse
)
from app.scanner.engine import ScannerEngine, TOP_100_PORTS
from app.core.gemini import gemini_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["NetSentinel API"])


# ──────────────────────────────────────────────
# Background Scan Task
# ──────────────────────────────────────────────

async def log_activity(db: AsyncSession, event_type: str, description: str, severity: str = "info", metadata: dict = None):
    """Helper to log system events."""
    event = SystemEvent(
        event_type=event_type,
        description=description,
        severity=severity,
        metadata_json=metadata
    )
    db.add(event)
    await db.commit()

async def run_scan_task(scan_id: int, target: str, scan_type: str,
                        ports: Optional[str], timeout: int):
    """Execute a scan in the background and persist results."""
    from app.models.database import async_session

    async with async_session() as db:
        try:
            # Update status to RUNNING
            scan = await db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            await db.commit()

            # Parse ports
            engine = ScannerEngine(timeout=timeout)
            port_list = engine.parse_port_range(ports) if ports else TOP_100_PORTS

            # Run scan based on type
            if scan_type == "arp_only":
                hosts = await engine.arp_discover(target)
            elif scan_type == "quick":
                port_list = [22, 80, 443, 8080, 3389]  # Quick scan: top 5
                hosts = await engine.full_scan(target, port_list)
            else:
                hosts = await engine.full_scan(target, port_list, scan_udp=(scan_type == "full"))

            # Persist discovered hosts
            total_open_ports = 0
            for host_result in hosts:
                db_host = Host(
                    scan_id=scan_id,
                    ip_address=host_result.ip,
                    mac_address=host_result.mac or None,
                    hostname=host_result.hostname or None,
                    os_guess=host_result.os_guess or None,
                    os_confidence=host_result.os_confidence or None,
                    ttl=host_result.ttl or None,
                    is_up=host_result.is_up,
                    response_time_ms=host_result.response_time_ms,
                )
                db.add(db_host)
                await db.flush()  # Get the host ID

                for port_result in host_result.ports:
                    if port_result.state == "open":
                        total_open_ports += 1
                    db_port = Port(
                        host_id=db_host.id,
                        port_number=port_result.port,
                        protocol=port_result.protocol,
                        state=port_result.state,
                        service_name=port_result.service or None,
                        service_version=port_result.version or None,
                        banner=port_result.banner or None,
                    )
                    db.add(db_port)

            await db.flush()

            # AI Vulnerability Analysis
            scan_data = {
                "target": target,
                "hosts": [
                    {
                        "ip": h.ip,
                        "os": h.os_guess,
                        "ports": [
                            {
                                "port": p.port,
                                "protocol": p.protocol,
                                "state": p.state,
                                "service": p.service,
                                "version": p.version,
                                "banner": p.banner,
                            }
                            for p in h.ports
                        ],
                    }
                    for h in hosts
                ],
            }

            vulns = await gemini_client.analyze_vulnerabilities(scan_data)

            # Persist vulnerabilities
            total_vulns = 0
            for vuln in vulns:
                # Find the host this vuln belongs to
                for host_result in hosts:
                    host_ports = [p.port for p in host_result.ports]
                    vuln_port = vuln.get("port")
                    if vuln_port and vuln_port in host_ports:
                        # Look up the db host
                        stmt = select(Host).where(
                            Host.scan_id == scan_id,
                            Host.ip_address == host_result.ip
                        )
                        result = await db.execute(stmt)
                        db_host = result.scalars().first()
                        if db_host:
                            db_vuln = Vulnerability(
                                host_id=db_host.id,
                                title=vuln.get("title", "Unknown"),
                                description=vuln.get("description", ""),
                                severity=SeverityLevel(vuln.get("severity", "info").lower()),
                                port_number=vuln_port,
                                service=vuln.get("service", ""),
                                cve_id=vuln.get("cve_id"),
                            )
                            db.add(db_vuln)
                            total_vulns += 1
                        break

            # Check if cancelled during execution
            scan = await db.get(Scan, scan_id)
            if scan.status == ScanStatus.CANCELLED:
                logger.info(f"Scan {scan_id} was cancelled by user. Discarding results.")
                await log_activity(db, "scan_cancelled", f"Scan {scan_id} on {target} was cancelled during execution.", "warning", {"scan_id": scan_id})
                return

            # Update scan status
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.total_hosts = len(hosts)
            scan.total_open_ports = total_open_ports
            scan.total_vulnerabilities = total_vulns
            await db.commit()
            
            await log_activity(db, "scan_completed", f"Scan {scan_id} on {target} completed successfully. Found {len(hosts)} hosts and {total_vulns} vulnerabilities.", "info", {"scan_id": scan_id, "hosts": len(hosts)})

            logger.info(f"Scan {scan_id} completed: {len(hosts)} hosts, "
                        f"{total_open_ports} open ports, {total_vulns} vulnerabilities")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                await db.commit()
                await log_activity(db, "scan_failed", f"Scan {scan_id} on {target} failed: {str(e)}", "error", {"scan_id": scan_id})


# ──────────────────────────────────────────────
# Scan Endpoints
# ──────────────────────────────────────────────

@router.options("/{path:path}")
async def options_handler(path: str):
    return {"status": "ok"}

@router.post("/scans", response_model=ScanSummary, status_code=201)
async def create_scan(
    scan_req: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create and launch a new network scan."""
    scan = Scan(
        target=scan_req.target,
        scan_type=scan_req.scan_type,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch scan in background
    background_tasks.add_task(
        run_scan_task,
        scan.id,
        scan_req.target,
        scan_req.scan_type,
        scan_req.ports,
        scan_req.timeout or 5,
    )

    await log_activity(db, "scan_started", f"Started {scan_req.scan_type} scan on {scan_req.target}", "info", {"scan_id": scan.id, "target": scan_req.target})
    logger.info(f"Scan {scan.id} created for target: {scan_req.target}")
    return scan


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List all scans, ordered by most recent."""
    stmt = (
        select(Scan)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get full scan details including hosts, ports, and vulnerabilities."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.hosts)
            .selectinload(Host.ports),
            selectinload(Scan.hosts)
            .selectinload(Host.vulnerabilities),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


# ──────────────────────────────────────────────
# Vulnerabilities Endpoints
# ──────────────────────────────────────────────

@router.get("/vulnerabilities", response_model=list[dict])
async def list_vulnerabilities(db: AsyncSession = Depends(get_db)):
    """List all vulnerabilities across all scans with context."""
    # We will join Vulnerability -> Host -> Scan to return a flattened dictionary
    stmt = (
        select(Vulnerability, Host.ip_address, Scan.id, Scan.target)
        .join(Host, Vulnerability.host_id == Host.id)
        .join(Scan, Host.scan_id == Scan.id)
        .order_by(Vulnerability.severity, Vulnerability.id.desc())
    )
    result = await db.execute(stmt)
    
    vulns = []
    for vuln, ip, scan_id, target in result.all():
        vuln_dict = {
            "id": vuln.id,
            "title": vuln.title,
            "severity": vuln.severity,
            "port_number": vuln.port_number,
            "service": vuln.service,
            "cve_id": vuln.cve_id,
            "description": vuln.description,
            "host_ip": ip,
            "scan_id": scan_id,
            "scan_target": target,
            "created_at": vuln.created_at.isoformat() if vuln.created_at else None
        }
        vulns.append(vuln_dict)
        
    return vulns



@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a scan and all its associated data."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.hosts).selectinload(Host.ports),
            selectinload(Scan.hosts).selectinload(Host.vulnerabilities),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    await db.delete(scan)
    await db.commit()

@router.post("/scans/{scan_id}/cancel", status_code=204)
async def cancel_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan."""
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status == ScanStatus.RUNNING:
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        await db.commit()
        await log_activity(db, "scan_cancelled", f"Scan {scan_id} cancelled by user.", "warning", {"scan_id": scan_id})


# ──────────────────────────────────────────────
# System Activity
# ──────────────────────────────────────────────

@router.get("/activity", response_model=list[SystemEventResponse])
async def list_activity(limit: int = 100, db: AsyncSession = Depends(get_db)):
    """List recent system activity events."""
    stmt = select(SystemEvent).order_by(SystemEvent.created_at.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


# ──────────────────────────────────────────────
# Remediation Endpoints
# ──────────────────────────────────────────────

@router.post("/remediation", response_model=RemediationResponse)
async def get_remediation(request: RemediationRequest):
    """Get AI-generated remediation steps for a set of findings."""
    remediation_text = await gemini_client.generate_remediation(
        request.host_ip, request.findings
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in request.findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return RemediationResponse(
        host_ip=request.host_ip,
        remediation_steps=remediation_text,
        severity_summary=severity_counts,
        generated_at=datetime.utcnow(),
    )


# ──────────────────────────────────────────────
# Baseline Endpoints
# ──────────────────────────────────────────────

@router.post("/baselines", response_model=BaselineResponse, status_code=201)
async def create_baseline(
    baseline: BaselineCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new golden configuration baseline."""
    db_baseline = GoldenBaseline(
        name=baseline.name,
        description=baseline.description,
        framework=baseline.framework,
        rules=baseline.rules,
    )
    db.add(db_baseline)
    await db.commit()
    await db.refresh(db_baseline)
    return db_baseline


@router.get("/baselines", response_model=list[BaselineResponse])
async def list_baselines(db: AsyncSession = Depends(get_db)):
    """List all golden configuration baselines."""
    result = await db.execute(select(GoldenBaseline))
    return result.scalars().all()


@router.post("/compliance/check")
async def check_compliance(
    scan_id: int,
    baseline_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Check a scan's results against a golden baseline."""
    # Load scan data
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.hosts)
            .selectinload(Host.ports),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Load baseline
    baseline = await db.get(GoldenBaseline, baseline_id)
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    # Build scan data dict for AI analysis
    scan_data = {
        "target": scan.target,
        "hosts": [
            {
                "ip": h.ip_address,
                "os": h.os_guess,
                "ports": [
                    {
                        "port": p.port_number,
                        "protocol": p.protocol,
                        "state": p.state.value if hasattr(p.state, 'value') else p.state,
                        "service": p.service_name,
                    }
                    for p in h.ports
                ],
            }
            for h in scan.hosts
        ],
    }

    compliance_result = await gemini_client.check_compliance(scan_data, baseline.rules)
    return compliance_result


# ──────────────────────────────────────────────
# Dashboard Stats
# ──────────────────────────────────────────────

@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get aggregated statistics for the dashboard."""
    # Total scans
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar() or 0

    # Total hosts
    total_hosts = (await db.execute(select(func.count(Host.id)))).scalar() or 0

    # Total open ports
    total_ports = (await db.execute(
        select(func.count(Port.id)).where(Port.state == "open")
    )).scalar() or 0

    # Vulnerability counts
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0

    critical = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.CRITICAL)
    )).scalar() or 0
    high = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.HIGH)
    )).scalar() or 0
    medium = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.MEDIUM)
    )).scalar() or 0
    low = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.severity == SeverityLevel.LOW)
    )).scalar() or 0

    # Recent scans
    recent_stmt = select(Scan).order_by(Scan.created_at.desc()).limit(5)
    recent_result = await db.execute(recent_stmt)
    recent_scans = recent_result.scalars().all()

    return DashboardStats(
        total_scans=total_scans,
        total_hosts_discovered=total_hosts,
        total_open_ports=total_ports,
        total_vulnerabilities=total_vulns,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        recent_scans=recent_scans,
    )
