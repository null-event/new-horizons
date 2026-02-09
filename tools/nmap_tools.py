import logging

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from llm.provider import get_scanning_config
from tools.docker_runner import get_docker_runner

logger = logging.getLogger(__name__)


class NmapPortResult(BaseModel):
    """A single open port from Nmap scan."""

    port: int = Field(description="Port number")
    protocol: str = Field(description="Protocol (tcp/udp)")
    state: str = Field(description="Port state")
    service: str = Field(description="Detected service name")
    product: str = Field(description="Product name")
    version: str = Field(description="Version string")
    extra_info: str = Field(description="Extra service info")


class NmapHostResult(BaseModel):
    """Nmap scan results for a single host."""

    host: str = Field(description="Hostname or IP")
    ip: str = Field(description="IP address")
    hostnames: list[str] = Field(description="Resolved hostnames")
    state: str = Field(description="Host state (up/down)")
    ports: list[NmapPortResult] = Field(description="Open ports found")
    os_matches: list[dict] = Field(description="OS detection results")


class NmapScanResult(BaseModel):
    """Full Nmap scan results."""

    targets_scanned: int = Field(description="Number of targets scanned")
    hosts_up: int = Field(description="Number of hosts responding")
    results: list[NmapHostResult] = Field(description="Per-host results")


@tool
def nmap_scan(targets: list[str]) -> NmapScanResult:
    """
    Run a targeted Nmap scan on a list of hosts.

    Performs service version detection (-sV), default scripts (-sC),
    and scans the top 1000 ports. Runs inside Docker for isolation.

    Args:
        targets: List of IPs or hostnames to scan (max 25)
    """
    scan_config = get_scanning_config()
    max_targets = scan_config.get("max_nmap_targets", 25)
    ports = scan_config.get("nmap_ports", "--top-ports 1000")
    flags = scan_config.get("nmap_flags", "-sV -sC -T4")

    targets = targets[:max_targets]

    logger.info(f"Starting Nmap scan on {len(targets)} targets")

    runner = get_docker_runner()

    try:
        raw_results = runner.run_nmap(
            targets=targets,
            ports=ports,
            flags=flags,
            timeout=scan_config.get("docker_timeout", 300),
        )

        host_results = []
        for r in raw_results:
            port_results = [NmapPortResult(**p) for p in r.get("ports", [])]
            host_results.append(
                NmapHostResult(
                    host=r.get("host", ""),
                    ip=r.get("ip", ""),
                    hostnames=r.get("hostnames", []),
                    state=r.get("state", ""),
                    ports=port_results,
                    os_matches=r.get("os_matches", []),
                )
            )

        logger.info(
            f"Nmap scan complete: {len(host_results)} hosts up, "
            f"{sum(len(h.ports) for h in host_results)} open ports found"
        )

        return NmapScanResult(
            targets_scanned=len(targets),
            hosts_up=len(host_results),
            results=host_results,
        ).model_dump()

    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return NmapScanResult(
            targets_scanned=len(targets), hosts_up=0, results=[],
        ).model_dump()
