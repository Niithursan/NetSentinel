"""Core scanning engine using Scapy."""

import asyncio
import socket
import time
import logging
from typing import Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

from scapy.all import (
    ARP, Ether, IP, TCP, UDP, ICMP, sr, sr1, srp, conf
)

logger = logging.getLogger(__name__)

# Suppress Scapy's verbose output
conf.verb = 0

# Common service-to-port mappings for quick identification
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1521: "oracle",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb",
}

# Top 100 most commonly scanned ports
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8080, 8443, 8888, 9100,
    9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

# TTL-based OS guessing heuristics
OS_TTL_MAP = [
    (0, 32, "Windows 95/98"),
    (33, 64, "Linux/Unix/macOS"),
    (65, 128, "Windows (NT/2000/XP/7/10/11)"),
    (129, 255, "Cisco/Network Device"),
]


@dataclass
class PortResult:
    """A single scanned port."""
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class HostResult:
    """A discovered host and its ports."""
    ip: str
    mac: str = ""
    hostname: str = ""
    os_guess: str = ""
    os_confidence: float = 0.0
    ttl: int = 0
    is_up: bool = True
    response_time_ms: float = 0.0
    ports: list[PortResult] = field(default_factory=list)


class ScannerEngine:
    """Scanner engine using a thread pool for blocking Scapy calls."""

    def __init__(self, timeout: int = 3, executor: Optional[ThreadPoolExecutor] = None):
        self.timeout = timeout
        self._executor = executor or ThreadPoolExecutor(max_workers=10)

    async def _run_in_thread(self, func, *args, **kwargs):
        """Runs a function in the thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: func(*args, **kwargs))

    # ─── ARP Discovery ────────────────────────────────────────

    def _arp_discover(self, target: str) -> list[HostResult]:
        """
        Perform ARP discovery on a local subnet.
        Args:
            target: CIDR notation (e.g. '192.168.1.0/24') or single IP.
        Returns:
            List of discovered HostResult objects.
        """
        logger.info(f"Starting ARP discovery on {target}")
        hosts = []

        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = srp(arp_request, timeout=self.timeout, retry=1)

            seen_ips = set()
            for sent, received in answered:
                if received.psrc in seen_ips:
                    continue
                seen_ips.add(received.psrc)
                
                start = time.time()
                host = HostResult(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    is_up=True,
                    response_time_ms=round((time.time() - start) * 1000, 2),
                )

                hosts.append(host)
                logger.info(f"  Discovered: {host.ip} ({host.mac})")

        except PermissionError:
            logger.error("ARP discovery requires root/admin privileges")
            raise
        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
            raise

        logger.info(f"ARP discovery complete. Found {len(hosts)} host(s).")
        return hosts

    async def arp_discover(self, target: str) -> list[HostResult]:
        """Async wrapper for ARP discovery."""
        return await self._run_in_thread(self._arp_discover, target)

    # ─── ICMP Ping Discovery ──────────────────────────────────

    def _ping_host(self, ip: str) -> Optional[HostResult]:
        """Send an ICMP echo request to check if a host is alive."""
        try:
            start = time.time()
            pkt = IP(dst=ip) / ICMP()
            reply = sr1(pkt, timeout=self.timeout)

            if reply:
                elapsed = round((time.time() - start) * 1000, 2)
                host = HostResult(
                    ip=ip,
                    is_up=True,
                    ttl=reply.ttl,
                    response_time_ms=elapsed,
                    os_guess=self._guess_os_from_ttl(reply.ttl),
                )
                try:
                    host.hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror):
                    pass
                return host
        except Exception as e:
            logger.debug(f"Ping to {ip} failed: {e}")
        return None

    async def ping_host(self, ip: str) -> Optional[HostResult]:
        """Async wrapper for ICMP ping."""
        return await self._run_in_thread(self._ping_host, ip)

    # ─── TCP SYN Scan ─────────────────────────────────────────

    def _tcp_syn_scan(self, ip: str, ports: list[int]) -> list[PortResult]:
        """
        Perform a TCP SYN (half-open) scan on specified ports in parallel.
        A SYN-ACK response means the port is open.
        """
        logger.info(f"TCP SYN scan on {ip} — {len(ports)} port(s)")
        results = []

        if not ports:
            return results

        try:
            # Send all packets at once
            pkt = IP(dst=ip) / TCP(dport=ports, flags="S")
            answered, _ = sr(pkt, timeout=self.timeout, verbose=0)

            for sent, reply in answered:
                port = sent[TCP].dport
                result = PortResult(port=port, protocol="tcp")

                if reply.haslayer(TCP):
                    tcp_flags = reply[TCP].flags
                    if tcp_flags == 0x12:  # SYN-ACK
                        result.state = "open"
                        result.service = COMMON_SERVICES.get(port, "")
                        # Send RST to cleanly close half-open connection
                        sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
                    elif tcp_flags == 0x14:  # RST-ACK
                        result.state = "closed"
                elif reply.haslayer(ICMP):
                    result.state = "filtered"

                if result.state == "open":
                    results.append(result)
                    logger.info(f"  {ip}:{port} — OPEN ({result.service})")

        except Exception as e:
            logger.debug(f"Error TCP scanning {ip}: {e}")

        return results

    async def tcp_syn_scan(self, ip: str, ports: list[int]) -> list[PortResult]:
        """Async wrapper for TCP SYN scan."""
        return await self._run_in_thread(self._tcp_syn_scan, ip, ports)

    # ─── UDP Scan ─────────────────────────────────────────────

    def _udp_scan(self, ip: str, ports: list[int]) -> list[PortResult]:
        """
        Perform a UDP scan in parallel. If an ICMP 'port unreachable' is returned,
        the port is closed. No response likely means open|filtered.
        """
        logger.info(f"UDP scan on {ip} — {len(ports)} port(s)")
        results = []

        if not ports:
            return results

        try:
            pkt = IP(dst=ip) / UDP(dport=ports)
            answered, unans = sr(pkt, timeout=self.timeout, verbose=0)

            # Ports that didn't answer are likely open|filtered
            for sent in unans:
                if UDP in sent:
                    port = sent[UDP].dport
                    result = PortResult(port=port, protocol="udp", state="open")
                    result.service = COMMON_SERVICES.get(port, "")
                    results.append(result)

            for sent, reply in answered:
                if UDP not in sent:
                    continue
                port = sent[UDP].dport
                result = PortResult(port=port, protocol="udp")

                if reply.haslayer(ICMP):
                    icmp_type = reply[ICMP].type
                    icmp_code = reply[ICMP].code
                    if icmp_type == 3 and icmp_code == 3:
                        result.state = "closed"
                    elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
                        result.state = "filtered"
                elif reply.haslayer(UDP):
                    result.state = "open"
                    result.service = COMMON_SERVICES.get(port, "")

                if result.state in ("open", "filtered"):
                    results.append(result)

        except Exception as e:
            logger.debug(f"Error UDP scanning {ip}: {e}")

        return results

    async def udp_scan(self, ip: str, ports: list[int]) -> list[PortResult]:
        """Async wrapper for UDP scan."""
        return await self._run_in_thread(self._udp_scan, ip, ports)

    # ─── Banner Grabbing ──────────────────────────────────────

    def _grab_banner(self, ip: str, port: int, timeout: int = 3) -> str:
        """Attempt to grab a service banner via a raw TCP connection."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % ip.encode())
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            sock.close()
            return banner
        except Exception:
            return ""

    async def grab_banner(self, ip: str, port: int) -> str:
        """Async wrapper for banner grabbing."""
        return await self._run_in_thread(self._grab_banner, ip, port)

    # ─── OS Fingerprinting ────────────────────────────────────

    @staticmethod
    def _guess_os_from_ttl(ttl: int) -> str:
        """Guess the operating system based on the TTL value."""
        for low, high, os_name in OS_TTL_MAP:
            if low <= ttl <= high:
                return os_name
        return "Unknown"

    # ─── Full Scan Orchestrator ───────────────────────────────

    async def full_scan(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        scan_udp: bool = False,
    ) -> list[HostResult]:
        """
        Perform a complete scan:
        1. ARP discovery to find live hosts
        2. TCP SYN scan on each host
        3. (Optional) UDP scan
        4. Banner grabbing on open ports
        5. OS fingerprinting via TTL
        """
        if ports is None:
            ports = TOP_100_PORTS

        # Step 1: Discover hosts
        logger.info(f"=== Starting full scan on {target} ===")
        hosts = await self.arp_discover(target)

        if not hosts:
            logger.warning("No hosts found via ARP. Attempting ICMP ping fallback.")
            # Fallback: try pinging the target directly (single IP)
            host = await self.ping_host(target.split("/")[0])
            if host:
                hosts = [host]

        # Step 2-5: Scan each host
        for host in hosts:
            # TCP SYN scan
            tcp_results = await self.tcp_syn_scan(host.ip, ports)
            host.ports.extend(tcp_results)

            # Optional UDP scan (slower)
            if scan_udp:
                udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1900]
                udp_results = await self.udp_scan(host.ip, udp_ports)
                host.ports.extend(udp_results)

            # Banner grabbing for open TCP ports
            for port_result in host.ports:
                if port_result.state == "open" and port_result.protocol == "tcp":
                    banner = await self.grab_banner(host.ip, port_result.port)
                    if banner:
                        port_result.banner = banner
                        # Try to extract version info from banner
                        port_result.version = self._extract_version(banner)

            # OS guess from ICMP if not already set
            if not host.os_guess and not host.ttl:
                ping_result = await self.ping_host(host.ip)
                if ping_result:
                    host.ttl = ping_result.ttl
                    host.os_guess = ping_result.os_guess
                    host.os_confidence = 0.6  # TTL-based guess confidence

        logger.info(f"=== Full scan complete. {len(hosts)} host(s) scanned ===")
        return hosts

    @staticmethod
    def _extract_version(banner: str) -> str:
        """Try to extract a version string from a service banner."""
        import re
        # Match patterns like "Apache/2.4.41" or "OpenSSH_8.2"
        match = re.search(r'[\w.-]+/[\d.]+', banner)
        if match:
            return match.group(0)
        match = re.search(r'[\w]+[\s_][\d.]+', banner)
        if match:
            return match.group(0)
        return ""

    @staticmethod
    def parse_port_range(port_string: str) -> list[int]:
        """
        Parse a port specification string into a list of port numbers.
        Supports: '80', '80,443', '1-1024', '22,80,443,8000-8100'
        """
        ports = set()
        for part in port_string.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)
