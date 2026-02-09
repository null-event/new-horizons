# New Horizons Multi-Agent System Design

## Overview

Multi-agent reconnaissance and attack surface management system using LangGraph supervisor architecture. A coordinator agent orchestrates specialized sub-agents through a sequential scanning pipeline, with AI-driven vulnerability template selection.

## Architecture

```
Coordinator (Supervisor - LangGraph StateGraph)
├── Recon Agent       → Subfinder subdomain enumeration (passive)
├── Shodan Agent      → Shodan host/service lookup (passive)
├── Nmap Agent        → Targeted port scan + service detection (active)
├── Fingerprint Agent → WhatWeb technology fingerprinting (active)
├── Nuclei Agent      → AI-selected vuln templates based on findings (active)
└── Report Agent      → JSON + Markdown report generation
```

## Data Flow

```
Target Domain
    │
    ▼
Recon Agent → subdomains[]
    │
    ▼
Shodan Agent → shodan_results[] (IPs, ports, CVEs, services)
    │
    ▼
Nmap Agent → nmap_results[] (open ports, service versions)
    │         reads: subdomains + shodan IPs
    ▼
Fingerprint Agent → technologies[] (tech stack per host)
    │                 reads: subdomains, nmap (HTTP ports)
    ▼
Nuclei Agent → nuclei_findings[] (vulnerabilities)
    │            reads: nmap_results + technologies
    │            LLM selects template tags per host
    ▼
Report Agent → report_json{} + report_markdown
                reads: all prior results
```

## State Schema

```python
class ReconState(TypedDict):
    target: str
    messages: Annotated[list, add_messages]
    subdomains: list[str]
    shodan_results: list[dict]
    nmap_results: list[dict]
    technologies: list[dict]
    nuclei_findings: list[dict]
    current_phase: str
    completed_phases: list[str]
    errors: list[str]
    report_json: dict
    report_markdown: str
```

## LLM Configuration

Multi-provider factory supporting Anthropic, OpenAI, DeepSeek, and Ollama. Config maps agent names to provider/model pairs via `config.yaml`. Scanning agents use cheap models (Haiku); Nuclei reasoning and report generation use strong models (Sonnet).

## Nuclei Template Selection

AI-driven: the Nuclei agent receives a summary of all findings (ports, services, tech stacks) and reasons about which Nuclei template tags to run per host. Example: Apache 2.4.49 → `cve2021`, WordPress → `wordpress`, exposed MySQL → `mysql`.

## Output

- `output/report_<target>_<timestamp>.json` - structured findings
- `output/report_<target>_<timestamp>.md` - LLM-generated narrative report

## Tool Execution

All scanning tools (subfinder, whatweb, nmap, nuclei, httpx) run inside a single Docker container for isolation. `DockerToolRunner` handles container lifecycle, timeouts, and resource limits.

## Key Decisions

1. Targeted Nmap scans (top 1000 ports + service version detection)
2. Configurable multi-provider LLM backend
3. AI-driven Nuclei template selection
4. JSON + Markdown dual output format
