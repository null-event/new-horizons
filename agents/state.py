from typing import Annotated, TypedDict

from langgraph.graph.message import add_messages


class ReconState(TypedDict):
    """Shared state for the recon & ASM multi-agent system."""

    # Target
    target: str

    # LLM conversation history
    messages: Annotated[list, add_messages]

    # Phase 1: Subdomain enumeration
    subdomains: list[str]

    # Phase 2: Shodan passive recon
    shodan_results: list[dict]

    # Phase 3: Nmap active scanning
    nmap_results: list[dict]

    # Phase 4: Technology fingerprinting
    technologies: list[dict]

    # Phase 5: Nuclei vulnerability scanning
    nuclei_findings: list[dict]

    # Workflow control
    current_phase: str
    completed_phases: list[str]
    errors: list[str]

    # Output
    report_json: dict
    report_markdown: str
