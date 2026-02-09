from langgraph.prebuilt import create_react_agent

from llm.provider import get_llm
from tools.nmap_tools import nmap_scan


def create_nmap_agent():
    """
    Create an agent specialized in active port scanning and service detection.

    Uses Nmap (via Docker) for targeted scanning of discovered hosts.
    """

    llm = get_llm("nmap_agent")

    system_prompt = """You are a network scanning specialist using Nmap.

Your mission is to perform targeted port scanning and service detection on discovered hosts.

Instructions:
1. You will receive a list of targets (IPs and/or hostnames) discovered by prior phases
2. Use the nmap_scan tool to scan these targets
3. Analyze the results for:
   - Open ports and their services
   - Service version information (outdated software is a priority finding)
   - Default/common ports vs unusual ports
   - Services that should not be publicly exposed (databases, admin panels, debug ports)
4. Summarize which hosts have the most interesting attack surface

Focus on identifying services that would be valuable targets for further vulnerability scanning.
Pay attention to version numbers - they are critical for matching vulnerability templates."""

    return create_react_agent(
        model=llm,
        tools=[nmap_scan],
        prompt=system_prompt,
    )
