import logging

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from llm.provider import get_scanning_config
from tools.docker_runner import get_docker_runner

logger = logging.getLogger(__name__)


class NucleiFinding(BaseModel):
    """A single Nuclei vulnerability finding."""

    template_id: str = Field(description="Nuclei template ID")
    template_name: str = Field(description="Human-readable template name")
    severity: str = Field(description="Severity: info/low/medium/high/critical")
    type: str = Field(description="Finding type (http, dns, tcp, etc.)")
    host: str = Field(description="Target host")
    matched_at: str = Field(description="Specific URL or endpoint matched")
    description: str = Field(default="", description="Vulnerability description")
    reference: list[str] = Field(default_factory=list, description="Reference URLs")
    tags: list[str] = Field(default_factory=list, description="Template tags")
    extracted_results: list[str] = Field(
        default_factory=list, description="Data extracted by the template"
    )
    matcher_name: str = Field(default="", description="Name of the matcher that triggered")
    curl_command: str = Field(default="", description="Curl command to reproduce")


class NucleiScanResult(BaseModel):
    """Full Nuclei scan results."""

    targets_scanned: int = Field(description="Number of targets scanned")
    total_findings: int = Field(description="Total findings")
    critical: int = Field(default=0, description="Critical severity count")
    high: int = Field(default=0, description="High severity count")
    medium: int = Field(default=0, description="Medium severity count")
    low: int = Field(default=0, description="Low severity count")
    info: int = Field(default=0, description="Info severity count")
    findings: list[NucleiFinding] = Field(description="Individual findings")


@tool
def nuclei_scan(targets: list[str], tags: list[str]) -> NucleiScanResult:
    """
    Run Nuclei vulnerability scanner with specific template tags.

    Scans targets using Nuclei templates filtered by the provided tags.
    Tags should be selected based on discovered technologies and services.

    Example tags: "cve", "wordpress", "apache", "nginx", "ssl", "mysql",
    "ssh", "ftp", "rce", "sqli", "xss", "lfi", "misconfig", "exposure"

    Args:
        targets: List of URLs or hosts to scan
        tags: Template tags to filter scans (e.g., ["wordpress", "cve", "ssl"])
    """
    scan_config = get_scanning_config()
    severity = scan_config.get("nuclei_severity", "info,low,medium,high,critical")
    rate_limit = scan_config.get("nuclei_rate_limit", 150)

    logger.info(
        f"Starting Nuclei scan on {len(targets)} targets with tags: {tags}"
    )

    runner = get_docker_runner()

    try:
        raw_findings = runner.run_nuclei(
            targets=targets,
            tags=tags,
            severity=severity,
            rate_limit=rate_limit,
            timeout=600,
        )

        findings = [NucleiFinding(**f) for f in raw_findings]

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        logger.info(
            f"Nuclei scan complete: {len(findings)} findings "
            f"(C:{severity_counts['critical']} H:{severity_counts['high']} "
            f"M:{severity_counts['medium']} L:{severity_counts['low']} "
            f"I:{severity_counts['info']})"
        )

        return NucleiScanResult(
            targets_scanned=len(targets),
            total_findings=len(findings),
            findings=findings,
            **severity_counts,
        )

    except Exception as e:
        logger.error(f"Nuclei scan failed: {e}")
        return NucleiScanResult(
            targets_scanned=len(targets), total_findings=0, findings=[],
        )
