import json
import logging
from datetime import datetime, timezone

from llm.provider import get_llm

logger = logging.getLogger(__name__)


def generate_report(state: dict) -> tuple[dict, str]:
    """
    Generate both JSON and Markdown reports from scan results.

    Args:
        state: The full ReconState with all scan results

    Returns:
        Tuple of (report_json dict, report_markdown string)
    """
    report_json = _build_json_report(state)
    report_markdown = _generate_markdown_report(state, report_json)
    return report_json, report_markdown


def _build_json_report(state: dict) -> dict:
    """Build structured JSON report from state."""
    nuclei_findings = state.get("nuclei_findings", [])

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in nuclei_findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Collect all unique IPs from nmap results
    all_ips = set()
    total_open_ports = 0
    for host in state.get("nmap_results", []):
        if host.get("ip"):
            all_ips.add(host["ip"])
        total_open_ports += len(host.get("ports", []))

    return {
        "target": state.get("target", ""),
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_subdomains": len(state.get("subdomains", [])),
            "shodan_hosts": len(state.get("shodan_results", [])),
            "nmap_hosts_up": len(state.get("nmap_results", [])),
            "total_open_ports": total_open_ports,
            "unique_ips": len(all_ips),
            "technologies_detected": len(state.get("technologies", [])),
            "total_findings": len(nuclei_findings),
            **severity_counts,
        },
        "subdomains": state.get("subdomains", []),
        "shodan_results": state.get("shodan_results", []),
        "nmap_results": state.get("nmap_results", []),
        "technologies": state.get("technologies", []),
        "nuclei_findings": nuclei_findings,
        "errors": state.get("errors", []),
    }


def _generate_markdown_report(state: dict, report_json: dict) -> str:
    """Use LLM to generate a narrative Markdown report."""
    llm = get_llm("report_agent")

    # Build a concise summary for the LLM (avoid sending raw data overload)
    summary = json.dumps(report_json["summary"], indent=2)

    # Include top findings by severity
    critical_high = [
        f for f in report_json["nuclei_findings"]
        if f.get("severity", "").lower() in ("critical", "high")
    ][:20]

    # Sample of technologies
    tech_sample = report_json["technologies"][:15]

    # Sample of nmap results
    nmap_sample = []
    for host in report_json["nmap_results"][:10]:
        nmap_sample.append({
            "host": host.get("host", ""),
            "ip": host.get("ip", ""),
            "ports": host.get("ports", [])[:10],
        })

    findings_data = {
        "target": state["target"],
        "summary": report_json["summary"],
        "subdomains_sample": report_json["subdomains"][:30],
        "shodan_results_sample": report_json["shodan_results"][:10],
        "nmap_sample": nmap_sample,
        "technologies_sample": tech_sample,
        "critical_high_findings": critical_high,
        "all_findings_count": len(report_json["nuclei_findings"]),
        "errors": report_json["errors"],
    }

    prompt = f"""Generate a professional reconnaissance and attack surface management report based on these findings:

{json.dumps(findings_data, indent=2, default=str)}

Structure the report as follows:

# Recon & ASM Report: {state['target']}

## Executive Summary
Brief overview of findings, overall security posture, and risk level.

## Discovered Assets
- Total subdomains found and notable ones (admin panels, APIs, dev environments)
- IP addresses, hosting providers, and ASN information

## Exposed Services (Shodan + Nmap)
- Open ports and services by host
- Service versions and potential vulnerabilities
- Services that should not be publicly exposed

## Technology Stack
- Web servers, frameworks, CMS platforms
- Notable version information and EOL software
- Security headers assessment

## Vulnerability Findings (Nuclei)
- Critical and high severity findings with details
- Medium findings summary
- Low/info findings summary
- For each critical/high finding, include: what it is, why it matters, and remediation

## Risk Assessment
Prioritized list of findings by security impact. Rate overall risk.

## Recommendations
Actionable next steps ordered by priority:
1. Immediate actions (critical/high findings)
2. Short-term improvements
3. Long-term hardening

Be specific, technical, and actionable. This report is for a security professional."""

    response = llm.invoke(
        [
            (
                "system",
                "You are a senior penetration tester writing a reconnaissance and attack surface management report. Be thorough, precise, and prioritize findings by exploitability and impact.",
            ),
            ("user", prompt),
        ]
    )

    return response.content
