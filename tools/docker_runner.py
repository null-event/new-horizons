import json
import logging
import shlex
from typing import Optional

import docker

from llm.provider import get_scanning_config

logger = logging.getLogger(__name__)


class DockerToolRunner:
    """Execute reconnaissance tools inside Docker containers."""

    def __init__(self, image: str | None = None):
        self.client = docker.from_env()
        scan_config = get_scanning_config()
        self.image = image or scan_config.get("docker_image", "new-horizons-tools:latest")
        self.default_timeout = scan_config.get("docker_timeout", 300)
        self._ensure_image_exists()

    def _ensure_image_exists(self) -> None:
        try:
            self.client.images.get(self.image)
        except docker.errors.ImageNotFound:
            raise RuntimeError(
                f"Docker image '{self.image}' not found. "
                f"Build it with: docker build -t {self.image} -f docker/Dockerfile.tools ."
            )

    def run_command(
        self,
        command: str,
        timeout: int | None = None,
        network_mode: str = "bridge",
        env_vars: dict | None = None,
    ) -> tuple[str, str, int]:
        """
        Run a command inside the Docker container.

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        timeout = timeout or self.default_timeout
        container = None
        try:
            container = self.client.containers.run(
                self.image,
                command=f"/bin/bash -c {shlex.quote(command)}",
                detach=True,
                remove=False,
                network_mode=network_mode,
                environment=env_vars or {},
                mem_limit="1g",
                cpu_period=100000,
                cpu_quota=50000,
            )

            result = container.wait(timeout=timeout)
            exit_code = result["StatusCode"]

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8")

            return stdout, stderr, exit_code

        except docker.errors.ContainerError as e:
            logger.error(f"Container error: {e}")
            return "", str(e), 1
        except Exception as e:
            logger.error(f"Docker execution failed: {e}")
            raise
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def run_subfinder(self, domain: str, timeout: int = 120) -> list[str]:
        """Run Subfinder for subdomain enumeration."""
        safe_domain = shlex.quote(domain)
        command = f"subfinder -d {safe_domain} -silent -json"
        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        subdomains = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host:
                        subdomains.append(host)
                except json.JSONDecodeError:
                    cleaned = line.strip()
                    if cleaned and "." in cleaned:
                        subdomains.append(cleaned)

        return [s for s in subdomains if s]

    def run_nmap(
        self, targets: list[str], ports: str = "--top-ports 1000", flags: str = "-sV -sC -T4", timeout: int = 300
    ) -> list[dict]:
        """
        Run Nmap for port scanning and service detection.

        Args:
            targets: List of IPs or hostnames to scan
            ports: Port specification (e.g., "--top-ports 1000", "-p 80,443,8080")
            flags: Additional nmap flags
            timeout: Max execution time in seconds

        Returns:
            List of scan results per host
        """
        if not targets:
            return []

        # Write targets to a temp file inside the container
        targets_str = "\\n".join(shlex.quote(t) for t in targets)
        command = (
            f"echo -e '{targets_str}' > /tmp/targets.txt && "
            f"nmap {flags} {ports} -iL /tmp/targets.txt -oX /tmp/scan.xml -oN - 2>/dev/null && "
            f"cat /tmp/scan.xml"
        )

        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        return self._parse_nmap_xml(stdout)

    def _parse_nmap_xml(self, xml_output: str) -> list[dict]:
        """Parse Nmap XML output into structured results."""
        import xml.etree.ElementTree as ET

        results = []

        # Find the XML portion of the output (after the normal output)
        xml_start = xml_output.find("<?xml")
        if xml_start == -1:
            logger.warning("No XML output found from nmap")
            return results

        xml_data = xml_output[xml_start:]

        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as e:
            logger.error(f"Failed to parse nmap XML: {e}")
            return results

        for host_elem in root.findall(".//host"):
            host_result = {
                "host": "",
                "ip": "",
                "hostnames": [],
                "state": "",
                "ports": [],
                "os_matches": [],
            }

            # Get address
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    host_result["ip"] = addr.get("addr", "")

            # Get hostnames
            for hostname in host_elem.findall(".//hostname"):
                name = hostname.get("name", "")
                if name:
                    host_result["hostnames"].append(name)

            host_result["host"] = (
                host_result["hostnames"][0]
                if host_result["hostnames"]
                else host_result["ip"]
            )

            # Get host state
            status = host_elem.find("status")
            if status is not None:
                host_result["state"] = status.get("state", "")

            # Get ports
            for port_elem in host_elem.findall(".//port"):
                port_info = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "state": "",
                    "service": "",
                    "version": "",
                    "product": "",
                    "extra_info": "",
                }

                state_elem = port_elem.find("state")
                if state_elem is not None:
                    port_info["state"] = state_elem.get("state", "")

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    port_info["service"] = service_elem.get("name", "")
                    port_info["product"] = service_elem.get("product", "")
                    port_info["version"] = service_elem.get("version", "")
                    port_info["extra_info"] = service_elem.get("extrainfo", "")

                # Only include open ports
                if port_info["state"] == "open":
                    host_result["ports"].append(port_info)

            # Get OS matches
            for os_match in host_elem.findall(".//osmatch"):
                host_result["os_matches"].append(
                    {
                        "name": os_match.get("name", ""),
                        "accuracy": os_match.get("accuracy", ""),
                    }
                )

            if host_result["state"] == "up":
                results.append(host_result)

        return results

    def run_whatweb(self, url: str, timeout: int = 60) -> dict:
        """Run WhatWeb for technology fingerprinting."""
        safe_url = shlex.quote(url)
        command = f"whatweb {safe_url} --log-json=/dev/stdout --quiet"

        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        result = {
            "url": url,
            "technologies": [],
            "raw_output": stdout,
            "error": stderr if exit_code != 0 else None,
        }

        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    if isinstance(data, list):
                        for item in data:
                            result["technologies"].extend(
                                self._parse_whatweb_plugins(item)
                            )
                    elif isinstance(data, dict):
                        result["technologies"].extend(self._parse_whatweb_plugins(data))
                except json.JSONDecodeError:
                    continue

        return result

    def _parse_whatweb_plugins(self, data: dict) -> list[dict]:
        """Parse WhatWeb plugin output into structured format."""
        technologies = []
        plugins = data.get("plugins", {})

        for plugin_name, plugin_data in plugins.items():
            tech = {"name": plugin_name, "version": None, "details": {}}

            if isinstance(plugin_data, dict):
                if "version" in plugin_data:
                    versions = plugin_data["version"]
                    if versions:
                        tech["version"] = (
                            versions[0] if isinstance(versions, list) else versions
                        )

                for key in ["string", "account", "module"]:
                    if key in plugin_data and plugin_data[key]:
                        tech["details"][key] = plugin_data[key]

            technologies.append(tech)

        return technologies

    def run_nuclei(
        self,
        targets: list[str],
        tags: list[str] | None = None,
        severity: str = "info,low,medium,high,critical",
        rate_limit: int = 150,
        timeout: int = 600,
    ) -> list[dict]:
        """
        Run Nuclei vulnerability scanner with specified template tags.

        Args:
            targets: List of URLs or hosts to scan
            tags: Template tags to use (e.g., ["wordpress", "cve", "ssl"])
            severity: Comma-separated severity filter
            rate_limit: Requests per second limit
            timeout: Max execution time

        Returns:
            List of vulnerability findings
        """
        if not targets:
            return []

        targets_str = "\\n".join(shlex.quote(t) for t in targets)

        tag_flag = f"-tags {','.join(tags)}" if tags else ""
        command = (
            f"echo -e '{targets_str}' > /tmp/nuclei_targets.txt && "
            f"nuclei -l /tmp/nuclei_targets.txt "
            f"{tag_flag} "
            f"-severity {severity} "
            f"-rate-limit {rate_limit} "
            f"-jsonl -silent"
        )

        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        findings = []
        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = {
                    "template_id": data.get("template-id", ""),
                    "template_name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", "unknown"),
                    "type": data.get("type", ""),
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "extracted_results": data.get("extracted-results", []),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", []),
                    "tags": data.get("info", {}).get("tags", []),
                    "matcher_name": data.get("matcher-name", ""),
                    "curl_command": data.get("curl-command", ""),
                }
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def run_httpx(self, targets: list[str], timeout: int = 120) -> list[dict]:
        """Run httpx to probe live hosts."""
        targets_str = "\\n".join(targets)
        command = f"echo -e '{targets_str}' | httpx -silent -json -status-code -title -tech-detect"

        stdout, stderr, exit_code = self.run_command(command, timeout=timeout)

        results = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    data = json.loads(line)
                    results.append(
                        {
                            "url": data.get("url", ""),
                            "status_code": data.get("status_code"),
                            "title": data.get("title", ""),
                            "technologies": data.get("tech", []),
                            "content_length": data.get("content_length"),
                        }
                    )
                except json.JSONDecodeError:
                    continue

        return results


_runner: Optional[DockerToolRunner] = None


def get_docker_runner() -> DockerToolRunner:
    """Get or create the Docker runner singleton."""
    global _runner
    if _runner is None:
        _runner = DockerToolRunner()
    return _runner
