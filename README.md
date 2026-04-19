# ASO — Automated Security Operator

> AI-powered pentest agent for bug bounty programs across Web, API, Web3, LLM, Thick Client, Mobile, and Infrastructure.

---

## Overview

ASO is an agentic security testing framework powered by [Claude](https://anthropic.com) (claude-opus-4-7). It combines AI reasoning with real security tooling to conduct comprehensive penetration tests across seven major domains. ASO plans the attack, executes tools, interprets output, chains findings, and generates professional reports — all in a single command.

```
aso scan --target https://example.com --domain web --depth standard
```

---

## Architecture

```
ASO/
├── main.py                  # CLI entry point (Click)
├── config.yaml              # Default configuration
├── .env.example             # Environment template
├── requirements.txt
└── aso/
    ├── agent.py             # Core AI agent (Claude tool-use loop)
    ├── config.py            # Config management
    ├── domains/
    │   ├── base.py          # BaseDomain class
    │   ├── web.py           # Web Application (OWASP Top 10)
    │   ├── api.py           # Web Service / API (OWASP API Top 10)
    │   ├── web3.py          # Web3 / Blockchain (SWC Registry)
    │   ├── llm.py           # LLM Security (OWASP LLM Top 10)
    │   ├── thick_client.py  # Thick Client (binary, traffic, storage)
    │   ├── mobile.py        # Mobile App (OWASP MASVS)
    │   └── infra.py         # Infrastructure (network, cloud)
    ├── reports/
    │   └── generator.py     # HTML / JSON / Markdown report generation
    └── utils/
        ├── http.py          # HTTP utilities
        └── logger.py        # Structured logging
```

### How it works

1. `main.py` parses the CLI and builds a `Config` object
2. `ASO.scan()` auto-detects or accepts the testing domain
3. The domain module provides a **system prompt** (methodology), **tool schemas**, and an **initial message**
4. Claude runs in a tool-use loop — reasoning, calling tools, receiving results, until `finish_assessment()` is called
5. The agent's structured findings are extracted and passed to `ReportGenerator`
6. Reports are written to the output directory (HTML, JSON, Markdown)

---

## Supported Domains

| Flag | Domain | Methodology |
|------|--------|-------------|
| `web` | Web Application | OWASP Top 10 — XSS, SQLi, CSRF, SSRF, IDOR, auth, headers |
| `api` | Web Service / API | OWASP API Top 10 — BOLA, broken auth, injection, rate limiting |
| `web3` | Web3 / Blockchain | SWC Registry — reentrancy, access control, flash loans, oracle manipulation |
| `llm` | LLM Security | OWASP LLM Top 10 — prompt injection, jailbreak, data exfil, DoS |
| `thick` | Thick Client | Binary analysis, network interception, local storage, DLL hijacking |
| `mobile` | Mobile App | OWASP MASVS — insecure storage, cert pinning, root detection, platform misuse |
| `infra` | Infrastructure | PTES/NIST — port scanning, default creds, misconfigs, cloud storage |
| `auto` | Auto-detect | Infers domain from target URL/path |

---

## Installation

### Prerequisites

```bash
python >= 3.11
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=your_key
```

### Optional security tools (install for full coverage)

```bash
# Debian/Ubuntu
sudo apt install nmap nikto gobuster ffuf nuclei sqlmap amass subfinder

# Additional
pip install web3        # Web3 domain
pip install slither-analyzer  # Solidity static analysis
```

---

## Usage

### Scan a web application

```bash
python main.py scan --target https://example.com --domain web
```

### Quick API assessment

```bash
python main.py scan --target https://api.example.com/v1 --domain api --depth quick
```

### Infrastructure scan with scope

```bash
python main.py scan --target 192.168.1.0/24 --domain infra \
  --scope 192.168.1.0/24 --depth standard
```

### Smart contract audit

```bash
python main.py scan --target 0xContractAddress --domain web3 --depth deep
```

### LLM endpoint assessment

```bash
python main.py scan --target https://chatapp.example.com/api/chat --domain llm
```

### Generate report from saved JSON

```bash
python main.py report --input results/aso_web_example_20260418_120000.json --format html
```

### List available domains and tools

```bash
python main.py list --domains
python main.py list --tools
```

---

## Output

Results are saved to the `results/` directory (configurable):

| File | Description |
|------|-------------|
| `aso_<domain>_<target>_<ts>.json` | Raw JSON with all findings and conversation log |
| `aso_<domain>_<target>_<ts>.html` | Interactive HTML report with collapsible findings |
| `aso_<domain>_<target>_<ts>.md` | Markdown report for issue trackers / GitHub |

### Finding structure

```json
{
  "title": "Reflected XSS in search parameter",
  "severity": "high",
  "cwe": "CWE-79",
  "cvss_score": 7.2,
  "description": "The 'q' parameter reflects user input without sanitization.",
  "evidence": "GET /search?q=<script>alert(1)</script>\nResponse: 200 OK\n...<script>alert(1)</script>...",
  "remediation": "Encode all user-controlled output. Use Content-Security-Policy.",
  "references": ["https://owasp.org/www-community/attacks/xss/", "CWE-79"]
}
```

---

## Configuration

Edit `config.yaml` to customize:

```yaml
aso:
  model: "claude-opus-4-7"   # Claude model to use
  max_tokens: 8192
  max_iterations: 50         # Max agent loop iterations

scan:
  rate_limit: 10             # Requests per second
  verify_ssl: false          # TLS verification
  proxy: "http://127.0.0.1:7080"  # Caido proxy (auto-started by Docker Compose)

tools:
  nmap:
    enabled: true
    default_args: "-sV -sC --open"
  sqlmap:
    enabled: false           # Enable only when needed
    safe_mode: true
```

---

## Ethical Use

ASO is intended **exclusively for authorized security testing**:

- Only use against targets you own or have explicit written permission to test
- Respect bug bounty program scope and rules of engagement
- Do not use for unauthorized access, data exfiltration, or service disruption
- Findings must be reported responsibly through the program's disclosure channels

---

## Roadmap

- [x] Caido proxy integration (traffic interception, history, replay, sitemap)
- [ ] Continuous scanning mode with delta reports
- [ ] Team collaboration (shared findings database)
- [ ] Custom methodology templates (YAML-defined)
- [ ] CI/CD integration mode
- [ ] Web UI dashboard
- [ ] SARIF output for GitHub Advanced Security

---

## License

MIT License — see [LICENSE](LICENSE)
