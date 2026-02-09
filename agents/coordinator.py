import json
import logging
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from agents.fingerprint_agent import create_fingerprint_agent
from agents.nmap_agent import create_nmap_agent
from agents.nuclei_agent import create_nuclei_agent
from agents.recon_agent import create_recon_agent
from agents.report_agent import generate_report
from agents.shodan_agent import create_shodan_agent
from agents.state import ReconState
from llm.provider import get_scanning_config

logger = logging.getLogger(__name__)


def _extract_json_from_content(content: Any) -> dict | None:
    """Safely extract JSON from message content."""
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None
    return None


def create_coordinator(checkpointer=None):
    """
    Create the multi-agent recon & ASM coordinator.

    Supervisor orchestrates specialized agents through the pipeline:
    recon → shodan → nmap → fingerprint → nuclei → report
    """

    # Initialize all sub-agents
    recon_agent = create_recon_agent()
    shodan_agent = create_shodan_agent()
    nmap_agent = create_nmap_agent()
    fingerprint_agent = create_fingerprint_agent()
    nuclei_agent = create_nuclei_agent()

    scan_config = get_scanning_config()

    # ==================== NODES ====================

    def supervisor_node(state: ReconState) -> Command:
        """Route to the next phase based on current progress."""
        completed = state.get("completed_phases", [])
        logger.info(f"Supervisor: completed phases = {completed}")

        if "recon" not in completed:
            return Command(goto="recon_node", update={"current_phase": "recon"})

        elif "shodan" not in completed:
            return Command(goto="shodan_node", update={"current_phase": "shodan"})

        elif "nmap" not in completed:
            # Build target list from subdomains + Shodan IPs
            targets = list(set(state.get("subdomains", [])))
            shodan_ips = [
                h.get("ip") for h in state.get("shodan_results", []) if h.get("ip")
            ]
            targets.extend(ip for ip in shodan_ips if ip not in targets)

            if targets:
                return Command(goto="nmap_node", update={"current_phase": "nmap"})
            else:
                return Command(
                    goto="report_node",
                    update={
                        "current_phase": "reporting",
                        "completed_phases": completed + ["nmap", "fingerprint", "nuclei"],
                    },
                )

        elif "fingerprint" not in completed:
            # Only fingerprint if we have subdomains and nmap found HTTP ports
            subdomains = state.get("subdomains", [])
            if subdomains:
                return Command(
                    goto="fingerprint_node", update={"current_phase": "fingerprint"}
                )
            else:
                return Command(
                    goto="report_node",
                    update={
                        "current_phase": "reporting",
                        "completed_phases": completed + ["fingerprint", "nuclei"],
                    },
                )

        elif "nuclei" not in completed:
            # Run nuclei if we have any scan data to work with
            has_nmap = len(state.get("nmap_results", [])) > 0
            has_tech = len(state.get("technologies", [])) > 0
            if has_nmap or has_tech:
                return Command(
                    goto="nuclei_node", update={"current_phase": "nuclei"}
                )
            else:
                return Command(
                    goto="report_node",
                    update={
                        "current_phase": "reporting",
                        "completed_phases": completed + ["nuclei"],
                    },
                )

        else:
            return Command(goto="report_node", update={"current_phase": "reporting"})

    def recon_node(state: ReconState) -> dict:
        """Execute subdomain enumeration."""
        logger.info(f"Starting reconnaissance for: {state['target']}")

        try:
            result = recon_agent.invoke(
                {"messages": [("user", f"Find all subdomains for: {state['target']}")]}
            )

            subdomains = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name") and msg.name == "enumerate_subdomains":
                    content = _extract_json_from_content(msg.content)
                    if content:
                        subdomains.extend(content.get("subdomains", []))

            subdomains = list(set(subdomains))

            return {
                "messages": result["messages"],
                "subdomains": subdomains,
                "completed_phases": state.get("completed_phases", []) + ["recon"],
            }

        except Exception as e:
            logger.error(f"Recon failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Recon error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["recon"],
            }

    def shodan_node(state: ReconState) -> dict:
        """Execute Shodan reconnaissance."""
        logger.info(f"Starting Shodan lookup for: {state['target']}")

        try:
            subdomains_sample = state.get("subdomains", [])[:20]
            result = shodan_agent.invoke(
                {
                    "messages": [
                        (
                            "user",
                            f"Search Shodan for hosts related to: {state['target']}. "
                            f"We found these subdomains: {subdomains_sample}",
                        )
                    ]
                }
            )

            shodan_results = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name"):
                    content = _extract_json_from_content(msg.content)
                    if content:
                        if msg.name == "shodan_domain_search":
                            shodan_results.extend(content.get("hosts", []))
                        elif msg.name == "shodan_host_lookup":
                            shodan_results.append(content)

            return {
                "messages": result["messages"],
                "shodan_results": shodan_results,
                "completed_phases": state.get("completed_phases", []) + ["shodan"],
            }

        except Exception as e:
            logger.error(f"Shodan lookup failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Shodan error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["shodan"],
            }

    def nmap_node(state: ReconState) -> dict:
        """Execute Nmap scanning on discovered targets."""
        # Build target list: subdomains + unique Shodan IPs
        targets = list(set(state.get("subdomains", [])))
        shodan_ips = [
            h.get("ip") for h in state.get("shodan_results", []) if h.get("ip")
        ]
        targets.extend(ip for ip in set(shodan_ips) if ip not in targets)

        max_targets = scan_config.get("max_nmap_targets", 25)
        targets = targets[:max_targets]

        logger.info(f"Starting Nmap scan on {len(targets)} targets")

        try:
            result = nmap_agent.invoke(
                {
                    "messages": [
                        (
                            "user",
                            f"Scan these targets discovered during recon of {state['target']}:\n"
                            f"{json.dumps(targets)}",
                        )
                    ]
                }
            )

            # Extract nmap results from tool messages
            nmap_results = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name") and msg.name == "nmap_scan":
                    content = _extract_json_from_content(msg.content)
                    if content:
                        nmap_results.extend(content.get("results", []))

            return {
                "messages": result["messages"],
                "nmap_results": nmap_results,
                "completed_phases": state.get("completed_phases", []) + ["nmap"],
            }

        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Nmap error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["nmap"],
            }

    def fingerprint_node(state: ReconState) -> dict:
        """Execute technology fingerprinting."""
        subdomains = state.get("subdomains", [])

        # If nmap found HTTP ports, prioritize those hosts
        http_hosts = set()
        for host in state.get("nmap_results", []):
            for port in host.get("ports", []):
                if port.get("service") in ("http", "https", "http-proxy"):
                    http_hosts.add(host.get("host", host.get("ip", "")))

        # Use HTTP hosts if available, otherwise fall back to subdomains
        if http_hosts:
            targets = list(http_hosts)
        else:
            targets = subdomains

        max_targets = scan_config.get("max_subdomains_to_scan", 50)
        targets = targets[:max_targets]

        if not targets:
            logger.info("No targets to fingerprint, skipping")
            return {
                "completed_phases": state.get("completed_phases", []) + ["fingerprint"]
            }

        logger.info(f"Fingerprinting {len(targets)} targets")

        urls = []
        for t in targets:
            if not t.startswith(("http://", "https://")):
                urls.append(f"https://{t}")
            else:
                urls.append(t)

        try:
            result = fingerprint_agent.invoke(
                {
                    "messages": [
                        (
                            "user",
                            f"Fingerprint these URLs to identify their technology stack: {urls}",
                        )
                    ]
                }
            )

            technologies = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name") and "fingerprint" in msg.name:
                    content = _extract_json_from_content(msg.content)
                    if content:
                        if "results" in content:
                            technologies.extend(content["results"])
                        elif "technologies" in content:
                            technologies.append(content)

            return {
                "messages": result["messages"],
                "technologies": technologies,
                "completed_phases": state.get("completed_phases", []) + ["fingerprint"],
            }

        except Exception as e:
            logger.error(f"Fingerprinting failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Fingerprint error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["fingerprint"],
            }

    def nuclei_node(state: ReconState) -> dict:
        """Execute AI-driven Nuclei vulnerability scanning."""
        logger.info("Starting Nuclei vulnerability scanning")

        # Build context for the nuclei agent
        nmap_summary = []
        for host in state.get("nmap_results", []):
            ports_info = [
                f"{p['port']}/{p['protocol']} ({p.get('service', '?')} {p.get('product', '')} {p.get('version', '')})"
                for p in host.get("ports", [])
            ]
            nmap_summary.append({
                "host": host.get("host", host.get("ip", "")),
                "ip": host.get("ip", ""),
                "open_ports": ports_info,
            })

        tech_summary = []
        for tech in state.get("technologies", []):
            if isinstance(tech, dict):
                tech_summary.append({
                    "url": tech.get("url", ""),
                    "technologies": tech.get("technologies", []),
                })

        context = (
            f"Based on our reconnaissance of {state['target']}, here are the findings:\n\n"
            f"NMAP SCAN RESULTS:\n{json.dumps(nmap_summary, indent=2)}\n\n"
            f"TECHNOLOGY FINGERPRINTS:\n{json.dumps(tech_summary, indent=2)}\n\n"
            f"Analyze these findings and run targeted Nuclei scans with appropriate "
            f"template tags for each target. Select tags based on the detected services "
            f"and technologies."
        )

        try:
            result = nuclei_agent.invoke(
                {"messages": [("user", context)]}
            )

            nuclei_findings = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name") and msg.name == "nuclei_scan":
                    content = _extract_json_from_content(msg.content)
                    if content:
                        nuclei_findings.extend(content.get("findings", []))

            return {
                "messages": result["messages"],
                "nuclei_findings": nuclei_findings,
                "completed_phases": state.get("completed_phases", []) + ["nuclei"],
            }

        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Nuclei error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["nuclei"],
            }

    def report_node(state: ReconState) -> dict:
        """Generate JSON and Markdown reports."""
        logger.info("Generating final reports")

        try:
            report_json, report_markdown = generate_report(state)
            return {
                "report_json": report_json,
                "report_markdown": report_markdown,
            }
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return {
                "report_json": {"error": str(e)},
                "report_markdown": f"# Report Generation Failed\n\nError: {e}",
                "errors": state.get("errors", []) + [f"Report error: {str(e)}"],
            }

    # ==================== BUILD GRAPH ====================

    builder = StateGraph(ReconState)

    builder.add_node("supervisor", supervisor_node)
    builder.add_node("recon_node", recon_node)
    builder.add_node("shodan_node", shodan_node)
    builder.add_node("nmap_node", nmap_node)
    builder.add_node("fingerprint_node", fingerprint_node)
    builder.add_node("nuclei_node", nuclei_node)
    builder.add_node("report_node", report_node)

    builder.add_edge(START, "supervisor")
    builder.add_edge("recon_node", "supervisor")
    builder.add_edge("shodan_node", "supervisor")
    builder.add_edge("nmap_node", "supervisor")
    builder.add_edge("fingerprint_node", "supervisor")
    builder.add_edge("nuclei_node", "supervisor")
    builder.add_edge("report_node", END)

    if checkpointer:
        return builder.compile(checkpointer=checkpointer)
    return builder.compile()
