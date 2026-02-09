# New Horizons

A multi-agent reconnaissance and attack surface management framework built with [LangGraph](https://github.com/langchain-ai/langgraph). A coordinator agent orchestrates six specialized AI agents through a full recon-to-vulnerability-scanning pipeline, with AI-driven Nuclei template selection based on discovered services and technologies.

## Overview

New Horizons uses a supervisor architecture where a coordinator agent routes execution through six phases. Each phase feeds results into the next, culminating in AI-selected vulnerability scans and dual-format reporting.

```
┌──────────────────────────────────────────────────────────────────────┐
│                           COORDINATOR                                │
│                        (Supervisor Agent)                            │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
       ┌───────────┬───────────┼───────────┬──────────────┐
       │           │           │           │              │
       ▼           ▼           ▼           ▼              ▼
 ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────────┐ ┌─────────┐
 │  RECON   │ │  SHODAN  │ │  NMAP  │ │FINGERPRINT │ │ NUCLEI  │
 │  AGENT   │ │  AGENT   │ │ AGENT  │ │   AGENT    │ │  AGENT  │
 └────┬─────┘ └────┬─────┘ └───┬────┘ └─────┬──────┘ └────┬────┘
      │            │            │            │             │
      ▼            ▼            ▼            ▼             ▼
 ┌──────────┐ ┌──────────┐ ┌────────┐ ┌────────────┐ ┌─────────┐
 │Subfinder │ │ Shodan   │ │  Nmap  │ │  WhatWeb   │ │ Nuclei  │
 │ (Docker) │ │   API    │ │(Docker)│ │  (Docker)  │ │(Docker) │
 └──────────┘ └──────────┘ └────────┘ └────────────┘ └─────────┘
                                                            │
                                                            ▼
                                                     ┌────────────┐
                                                     │   REPORT   │
                                                     │   AGENT    │
                                                     │ JSON + MD  │
                                                     └────────────┘
```

**Pipeline:**
1. **Reconnaissance** - Subdomain enumeration using Subfinder (passive)
2. **Shodan Intelligence** - Exposed services, CVEs, and banners (passive)
3. **Nmap Scanning** - Targeted port scan + service version detection on discovered hosts (active)
4. **Fingerprinting** - Technology stack identification with WhatWeb (active)
5. **Nuclei Scanning** - AI-selected vulnerability templates based on ports + tech stack (active)
6. **Reporting** - Dual JSON + Markdown output with risk-ranked findings

## Features

- **6-Agent Pipeline**: Specialized agents for each reconnaissance phase
- **AI-Driven Vulnerability Scanning**: Nuclei agent reasons about which template tags to run per host based on discovered services and technologies
- **Multi-Provider LLM Support**: Configurable per-agent models across Anthropic, OpenAI, DeepSeek, and Ollama
- **Docker Isolation**: All scanning tools run in containers with resource limits
- **Dual Output**: Machine-readable JSON and LLM-generated Markdown reports
- **Targeted Nmap**: Scans only hosts discovered by prior phases (top 1000 ports, `-sV -sC -T4`)
- **State Management**: LangGraph handles workflow routing and data accumulation
- **Checkpointing**: Optional resume capability for long-running investigations

## Project Structure

```
new-horizons/
├── agents/
│   ├── state.py               # ReconState shared state (TypedDict)
│   ├── coordinator.py         # Supervisor graph & phase routing
│   ├── recon_agent.py         # Subdomain enumeration agent
│   ├── shodan_agent.py        # Shodan reconnaissance agent
│   ├── nmap_agent.py          # Port scanning & service detection agent
│   ├── fingerprint_agent.py   # Technology fingerprinting agent
│   ├── nuclei_agent.py        # AI-driven vulnerability scanning agent
│   └── report_agent.py        # JSON + Markdown report generation
├── tools/
│   ├── docker_runner.py       # Docker execution + output parsing
│   ├── subdomain_tools.py     # Subfinder integration
│   ├── shodan_tools.py        # Shodan API tools
│   ├── nmap_tools.py          # Nmap scan tool + XML parser
│   ├── fingerprint_tools.py   # WhatWeb integration
│   └── nuclei_tools.py        # Nuclei scan tool + JSONL parser
├── llm/
│   └── provider.py            # Multi-provider LLM factory
├── docker/
│   └── Dockerfile.tools       # Subfinder + WhatWeb + httpx + Nmap + Nuclei
├── config.yaml                # LLM + scanning configuration
├── main.py                    # CLI entry point
├── requirements.txt
└── .env.example
```

## Prerequisites

- Python 3.11+
- Docker
- At least one LLM API key (Anthropic, OpenAI, or DeepSeek)
- [Shodan API Key](https://account.shodan.io/)

## Quick Start

### 1. Clone and Enter the Repository

```bash
git clone https://github.com/null-event/new-horizons.git
cd new-horizons
```

### 2. Build the Docker Image

The Docker image contains Subfinder, WhatWeb, httpx, Nmap, and Nuclei:

```bash
docker build -t new-horizons-tools:latest -f docker/Dockerfile.tools .
```

### 3. Install Python Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```env
ANTHROPIC_API_KEY=your-anthropic-key
SHODAN_API_KEY=your-shodan-key
```

### 5. Run

```bash
python main.py example.com
```

With checkpointing for resume capability:

```bash
python main.py example.com --checkpoint
```

## Configuration

All configuration lives in `config.yaml`.

### LLM Configuration

Each agent can use a different provider and model. This lets you use cheap models for simple tool-calling agents and stronger models for reasoning-heavy agents:

```yaml
llm:
  default_provider: "anthropic"
  default_model: "claude-sonnet-4-5-20250929"

  agents:
    recon_agent:
      provider: "anthropic"
      model: "claude-haiku-4-5-20251001"      # cheap - simple tool calls
    nuclei_agent:
      provider: "anthropic"
      model: "claude-sonnet-4-5-20250929"      # strong - template reasoning
    report_agent:
      provider: "anthropic"
      model: "claude-sonnet-4-5-20250929"      # strong - report writing

  providers:
    anthropic:
      api_key: "${ANTHROPIC_API_KEY}"
    openai:
      api_key: "${OPENAI_API_KEY}"
    deepseek:
      api_key: "${DEEPSEEK_API_KEY}"
      base_url: "https://api.deepseek.com"
    ollama:
      base_url: "http://localhost:11434"
```

### Scanning Configuration

```yaml
scanning:
  docker_image: "new-horizons-tools:latest"
  docker_timeout: 300
  max_subdomains_to_scan: 50
  max_nmap_targets: 25
  nmap_ports: "--top-ports 1000"
  nmap_flags: "-sV -sC -T4"
  nuclei_severity: "info,low,medium,high,critical"
  nuclei_rate_limit: 150
```

| Setting | Default | Description |
|---------|---------|-------------|
| `docker_image` | `new-horizons-tools:latest` | Docker image with scanning tools |
| `docker_timeout` | `300` | Max container execution time (seconds) |
| `max_subdomains_to_scan` | `50` | Max subdomains to fingerprint |
| `max_nmap_targets` | `25` | Max hosts for Nmap scanning |
| `nmap_ports` | `--top-ports 1000` | Nmap port specification |
| `nmap_flags` | `-sV -sC -T4` | Nmap scan flags |
| `nuclei_severity` | `info,low,medium,high,critical` | Nuclei severity filter |
| `nuclei_rate_limit` | `150` | Nuclei requests per second |

## How It Works

### Supervisor Routing

The coordinator implements a state machine that routes execution sequentially through phases. Each agent completes, returns results to state, and the supervisor picks the next phase:

```python
def supervisor_node(state: ReconState) -> Command:
    completed = state.get("completed_phases", [])
    if "recon" not in completed:
        return Command(goto="recon_node", update={"current_phase": "recon"})
    elif "shodan" not in completed:
        return Command(goto="shodan_node", update={"current_phase": "shodan"})
    elif "nmap" not in completed:
        return Command(goto="nmap_node", update={"current_phase": "nmap"})
    # ... continues through fingerprint → nuclei → report
```

### AI-Driven Nuclei Template Selection

The Nuclei agent receives a summary of all prior findings and reasons about which template tags to run per host:

```
Given:  api.example.com → Apache 2.4.49, PHP 7.4, ports 80/443/22
Agent:  Apache 2.4.49 → tag "apache", "cve"
        PHP 7.4 (EOL) → tag "php"
        Port 22 open  → tag "ssh"
        HTTPS present → tag "ssl"

Given:  dev.example.com → Nginx, WordPress 6.1, ports 80/3306
Agent:  WordPress 6.1  → tag "wordpress"
        Port 3306      → tag "mysql"
        Nginx          → tag "nginx"
```

### Data Flow

State accumulates across phases. Each agent reads what it needs from prior results:

```
ReconState
├── subdomains[]        ← Recon Agent writes
├── shodan_results[]    ← Shodan Agent writes
├── nmap_results[]      ← Nmap Agent writes (reads: subdomains + shodan IPs)
├── technologies[]      ← Fingerprint Agent writes (reads: subdomains, nmap HTTP ports)
├── nuclei_findings[]   ← Nuclei Agent writes (reads: nmap_results + technologies)
├── report_json{}       ← Report Agent writes (reads: everything)
└── report_markdown     ← Report Agent writes (reads: everything)
```

### Graph Visualization

```
                    ┌─────────┐
                    │  START  │
                    └────┬────┘
                         │
                         ▼
                 ┌────────────────┐
          ┌──────│   SUPERVISOR   │◄──────────────────────────┐
          │      └────────────────┘                           │
          │       │    │    │    │    │                        │
          ▼       ▼    ▼    ▼    ▼    ▼                        │
       ┌──────┐┌──────┐┌────┐┌──────┐┌───────┐                │
       │RECON ││SHODAN││NMAP││FINGER││NUCLEI │                │
       │ NODE ││ NODE ││NODE││ NODE ││ NODE  │                │
       └──┬───┘└──┬───┘└─┬──┘└──┬───┘└───┬───┘                │
          │       │      │      │        │                    │
          └───────┴──────┴──────┴────────┴────────────────────┘
                         │
                         ▼ (all phases complete)
                  ┌────────────┐
                  │   REPORT   │
                  │    NODE    │
                  └─────┬──────┘
                        │
                        ▼
                    ┌───────┐
                    │  END  │
                    └───────┘
```

## Output

Reports are saved to `output/` in both formats:

- `output/report_<target>_<timestamp>.json` - Structured findings for tooling/dashboards
- `output/report_<target>_<timestamp>.md` - LLM-generated narrative report

### Sample CLI Output

```
+================================================================+
|           New Horizons Multi-Agent Investigation               |
+================================================================+
|  Target: example.com                                           |
|  Phases: Recon → Shodan → Nmap → Fingerprint → Nuclei         |
+================================================================+

[*] Starting investigation...

[->] Moving to phase: recon
[OK] Recon complete: found 47 subdomains
[->] Moving to phase: shodan
[OK] Shodan complete: found 12 hosts
[->] Moving to phase: nmap
[OK] Nmap complete: 8 hosts up, 34 open ports
[->] Moving to phase: fingerprint
[OK] Fingerprinting complete: scanned 8 targets
[->] Moving to phase: nuclei
[OK] Nuclei complete: 15 findings
[->] Moving to phase: reporting
[OK] Reports generated

================================================================
INVESTIGATION COMPLETE
================================================================

[*] JSON report saved to: output/report_example_com_20260208_153022.json
[*] Markdown report saved to: output/report_example_com_20260208_153022.md
```

### JSON Report Structure

```json
{
  "target": "example.com",
  "scan_time": "2026-02-08T15:30:22Z",
  "summary": {
    "total_subdomains": 47,
    "shodan_hosts": 12,
    "nmap_hosts_up": 8,
    "total_open_ports": 34,
    "technologies_detected": 8,
    "total_findings": 15,
    "critical": 2,
    "high": 5,
    "medium": 4,
    "low": 2,
    "info": 2
  },
  "subdomains": ["..."],
  "shodan_results": ["..."],
  "nmap_results": ["..."],
  "technologies": ["..."],
  "nuclei_findings": [
    {
      "template_id": "CVE-2021-41773",
      "severity": "critical",
      "host": "api.example.com",
      "matched_at": "https://api.example.com/cgi-bin/.%2e/.%2e/etc/passwd"
    }
  ]
}
```

## Programmatic Usage

```python
from agents.coordinator import create_coordinator
from langgraph.checkpoint.memory import MemorySaver

coordinator = create_coordinator(checkpointer=MemorySaver())

initial_state = {
    "target": "example.com",
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

config = {"configurable": {"thread_id": "scan-example"}}
for event in coordinator.stream(initial_state, config):
    for node_name, output in event.items():
        print(f"[{node_name}] {list(output.keys())}")
```

## Extending the System

### Adding a New Agent

1. Create a tool in `tools/`:

```python
# tools/new_tools.py
from langchain_core.tools import tool
from pydantic import BaseModel, Field

class NewResult(BaseModel):
    data: list[str] = Field(description="Results")

@tool
def new_tool(target: str) -> NewResult:
    """Tool description for the LLM."""
    # Implementation
    return NewResult(data=["result"])
```

2. Create an agent in `agents/`:

```python
# agents/new_agent.py
from langgraph.prebuilt import create_react_agent
from llm.provider import get_llm
from tools.new_tools import new_tool

def create_new_agent():
    llm = get_llm("new_agent")
    return create_react_agent(
        model=llm,
        tools=[new_tool],
        prompt="Your system prompt",
    )
```

3. Add agent config to `config.yaml`:

```yaml
llm:
  agents:
    new_agent:
      provider: "anthropic"
      model: "claude-haiku-4-5-20251001"
```

4. Register in the coordinator graph in `agents/coordinator.py`:

```python
builder.add_node("new_node", new_node_function)
builder.add_edge("new_node", "supervisor")
```

### Using Different LLM Providers

Switch any agent to a different provider by editing `config.yaml`:

```yaml
agents:
  nuclei_agent:
    provider: "openai"
    model: "gpt-4o"
  recon_agent:
    provider: "ollama"
    model: "llama3.1"
```

## Security Considerations

- **Docker Isolation**: All scanning tools run in containers with memory (1GB) and CPU (50%) limits
- **Input Sanitization**: All user inputs are escaped via `shlex.quote()` before shell execution
- **API Key Management**: Credentials loaded from environment variables, never committed
- **Rate Limiting**: Configurable Nuclei rate limit, Shodan results capped at 25 per search
- **Timeouts**: All Docker containers have configurable execution timeouts
- **No Credential Storage**: Reports exclude API keys and sensitive configuration

## Acknowledgments

- [LangGraph](https://github.com/langchain-ai/langgraph) - Multi-agent orchestration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain enumeration
- [Shodan](https://www.shodan.io/) - Internet intelligence
- [Nmap](https://nmap.org/) - Network scanning
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Technology fingerprinting
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanning
- [OSINT_AI_Agent](https://github.com/dazzyddos/OSINT_AI_Agent) - Original inspiration

---

**Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before conducting reconnaissance on any target.
