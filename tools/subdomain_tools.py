import logging

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from tools.docker_runner import get_docker_runner

logger = logging.getLogger(__name__)


class SubdomainResult(BaseModel):
    """Result from subdomain enumeration."""

    domain: str = Field(description="The target domain")
    subdomains: list[str] = Field(description="List of discovered subdomains")
    count: int = Field(description="Number of subdomains found")
    source: str = Field(description="Tool used for enumeration")


@tool
def enumerate_subdomains(domain: str) -> SubdomainResult:
    """
    Enumerate subdomains for a target domain using Subfinder.

    Runs inside a Docker container. Uses passive sources including
    certificate transparency, DNS datasets, and web archives.

    Args:
        domain: The target domain to enumerate (e.g., "example.com")
    """
    logger.info(f"Starting subdomain enumeration for: {domain}")

    runner = get_docker_runner()

    try:
        subdomains = runner.run_subfinder(domain, timeout=180)
        unique_subs = sorted(set(subdomains))
        logger.info(f"Found {len(unique_subs)} subdomains for {domain}")

        return SubdomainResult(
            domain=domain,
            subdomains=unique_subs,
            count=len(unique_subs),
            source="subfinder",
        ).model_dump()
    except Exception as e:
        logger.error(f"Subdomain enumeration failed: {e}")
        return SubdomainResult(
            domain=domain,
            subdomains=[],
            count=0,
            source=f"subfinder (error: {str(e)})",
        ).model_dump()
