import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from langgraph.checkpoint.memory import MemorySaver

from agents.coordinator import create_coordinator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

load_dotenv()


def run_recon(target: str, use_checkpointing: bool = False) -> tuple[dict, str]:
    """
    Run a complete recon & ASM investigation on a target domain.

    Args:
        target: Domain to investigate (e.g., "example.com")
        use_checkpointing: Enable state persistence for resume capability

    Returns:
        Tuple of (report_json, report_markdown)
    """

    checkpointer = MemorySaver() if use_checkpointing else None
    coordinator = create_coordinator(checkpointer=checkpointer)

    initial_state = {
        "target": target,
        "messages": [],
        "subdomains": [],
        "shodan_results": [],
        "nmap_results": [],
        "technologies": [],
        "nuclei_findings": [],
        "current_phase": "",
        "completed_phases": [],
        "errors": [],
        "report_json": {},
        "report_markdown": "",
    }

    config = (
        {"configurable": {"thread_id": f"recon-{target}"}}
        if use_checkpointing
        else {}
    )

    print(
        f"""
+================================================================+
|           Recon & ASM Multi-Agent Investigation                |
+================================================================+
|  Target: {target:<54}|
|  Phases: Recon → Shodan → Nmap → Fingerprint → Nuclei         |
+================================================================+
    """
    )

    print("[*] Starting investigation...\n")

    final_state = None
    for event in coordinator.stream(initial_state, config):
        for node_name, node_output in event.items():
            if node_name == "__end__":
                continue

            if node_name == "supervisor":
                phase = node_output.get("current_phase", "")
                if phase:
                    print(f"[->] Moving to phase: {phase}")
            elif node_name == "recon_node":
                subs = node_output.get("subdomains", [])
                print(f"[OK] Recon complete: found {len(subs)} subdomains")
            elif node_name == "shodan_node":
                hosts = node_output.get("shodan_results", [])
                print(f"[OK] Shodan complete: found {len(hosts)} hosts")
            elif node_name == "nmap_node":
                results = node_output.get("nmap_results", [])
                total_ports = sum(len(r.get("ports", [])) for r in results)
                print(
                    f"[OK] Nmap complete: {len(results)} hosts up, "
                    f"{total_ports} open ports"
                )
            elif node_name == "fingerprint_node":
                techs = node_output.get("technologies", [])
                print(f"[OK] Fingerprinting complete: scanned {len(techs)} targets")
            elif node_name == "nuclei_node":
                findings = node_output.get("nuclei_findings", [])
                print(f"[OK] Nuclei complete: {len(findings)} findings")
            elif node_name == "report_node":
                print("[OK] Reports generated")

            final_state = node_output

    print("\n" + "=" * 64)
    print("INVESTIGATION COMPLETE")
    print("=" * 64 + "\n")

    report_json = final_state.get("report_json", {}) if final_state else {}
    report_markdown = final_state.get("report_markdown", "") if final_state else ""

    return report_json, report_markdown


def save_reports(target: str, report_json: dict, report_markdown: str) -> tuple[str, str]:
    """Save reports to output directory."""
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_")

    json_path = output_dir / f"report_{safe_target}_{timestamp}.json"
    md_path = output_dir / f"report_{safe_target}_{timestamp}.md"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2, default=str)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report_markdown)

    return str(json_path), str(md_path)


def main():
    if len(sys.argv) < 2:
        print(
            """
Usage: python main.py <target_domain> [--checkpoint]

Arguments:
    target_domain    Domain to investigate (e.g., example.com)
    --checkpoint     Enable state persistence for resume capability

Examples:
    python main.py example.com
    python main.py example.com --checkpoint
        """
        )
        sys.exit(1)

    target = sys.argv[1]
    use_checkpointing = "--checkpoint" in sys.argv

    try:
        report_json, report_markdown = run_recon(target, use_checkpointing)

        # Print the markdown report
        print(report_markdown)

        # Save both reports
        json_path, md_path = save_reports(target, report_json, report_markdown)
        print(f"\n[*] JSON report saved to: {json_path}")
        print(f"[*] Markdown report saved to: {md_path}")

    except KeyboardInterrupt:
        print("\n[!] Investigation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception("Investigation failed")
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
