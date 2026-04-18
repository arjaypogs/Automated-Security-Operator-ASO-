"""Core ASO AI agent — orchestrates the pentest using Claude tool-use loop."""

import asyncio
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import anthropic
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import Config

console = Console()


class ASO:
    """Automated Security Operator — AI-powered pentest agent."""

    DOMAIN_LABELS = {
        "web": "Web Application",
        "api": "Web Service / API",
        "web3": "Web3 / Blockchain",
        "llm": "LLM Security",
        "thick": "Thick Client",
        "mobile": "Mobile Application",
        "infra": "Infrastructure",
    }

    def __init__(self, config: Config):
        self.config = config
        self.client = anthropic.AsyncAnthropic(api_key=config.api_key)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def scan(
        self,
        target: str,
        domain: str = "auto",
        scope: list[str] | None = None,
        output_dir: str = "results",
        report_format: str = "html",
        depth: str = "standard",
        verbose: bool = False,
    ) -> dict:
        scope = scope or [target]
        start_ts = datetime.utcnow()

        if domain == "auto":
            domain = await self._detect_domain(target)
            console.print(f"[dim]Auto-detected domain:[/dim] [bold cyan]{self.DOMAIN_LABELS.get(domain, domain)}[/bold cyan]")

        domain_module = self._load_domain(domain)

        console.print(Panel(
            f"[bold]Starting {self.DOMAIN_LABELS.get(domain, domain)} Assessment[/bold]\n"
            f"Target: [cyan]{target}[/cyan]  |  Depth: [yellow]{depth}[/yellow]",
            style="green"
        ))

        system_prompt = domain_module.system_prompt(target, scope, depth)
        tools = domain_module.tools()
        initial_message = domain_module.initial_message(target, depth)

        findings = await self._agent_loop(
            system=system_prompt,
            tools=tools,
            initial_message=initial_message,
            tool_executor=domain_module.execute_tool,
            verbose=verbose,
        )

        end_ts = datetime.utcnow()
        elapsed = (end_ts - start_ts).total_seconds()

        result = {
            "meta": {
                "target": target,
                "domain": domain,
                "domain_label": self.DOMAIN_LABELS.get(domain, domain),
                "scope": scope,
                "depth": depth,
                "started_at": start_ts.isoformat() + "Z",
                "finished_at": end_ts.isoformat() + "Z",
                "elapsed_seconds": round(elapsed, 1),
                "aso_version": "1.0.0",
            },
            "findings": findings.get("findings", []),
            "summary": findings.get("summary", ""),
            "recommendations": findings.get("recommendations", []),
            "raw_conversation": findings.get("conversation", []),
        }

        output_path = self._save_results(result, output_dir)
        console.print(f"\n[bold green]Results saved:[/bold green] {output_path}")

        self._print_summary(result)
        self._render_report(result, output_dir, report_format)

        return result

    def generate_report(self, input_file: str, fmt: str, output_dir: str) -> None:
        with open(input_file) as f:
            result = json.load(f)
        self._render_report(result, output_dir, fmt)

    def list_domains(self) -> None:
        t = Table(title="Testing Domains", show_header=True, header_style="bold cyan")
        t.add_column("Flag", style="green")
        t.add_column("Domain", style="bold")
        t.add_column("Description")
        rows = [
            ("web",   "Web Application",   "OWASP Top 10, XSS, SQLi, CSRF, SSRF, auth, headers…"),
            ("api",   "Web Service / API", "REST/GraphQL/SOAP, OWASP API Top 10, fuzzing…"),
            ("web3",  "Web3 / Blockchain", "Smart contracts, DeFi, reentrancy, flash-loans…"),
            ("llm",   "LLM Security",      "Prompt injection, jailbreak, data extraction…"),
            ("thick", "Thick Client",       "Binary analysis, traffic interception, local storage…"),
            ("mobile","Mobile App",         "OWASP MASVS, Android/iOS, insecure storage…"),
            ("infra", "Infrastructure",     "Network, cloud, misconfigs, exposed services…"),
        ]
        for flag, name, desc in rows:
            t.add_row(flag, name, desc)
        console.print(t)

    def list_tools(self) -> None:
        t = Table(title="Supported External Tools", show_header=True, header_style="bold cyan")
        t.add_column("Tool", style="green")
        t.add_column("Purpose")
        t.add_column("Domains")
        rows = [
            ("nmap",      "Port/service discovery",          "all"),
            ("nikto",     "Web vulnerability scanner",       "web, api"),
            ("gobuster",  "Directory/subdomain bruteforce",  "web, api"),
            ("ffuf",      "Web fuzzer",                      "web, api"),
            ("nuclei",    "Template-based vuln scanner",     "web, api, infra"),
            ("sqlmap",    "SQL injection tester",            "web, api"),
            ("amass",     "Subdomain enumeration",           "web, api"),
            ("subfinder", "Passive subdomain discovery",     "web, api"),
            ("wfuzz",     "Web application fuzzer",          "web, api"),
            ("curl",      "HTTP request crafting",           "all"),
            ("whois",     "Domain/IP registration info",     "all"),
            ("dig/nslookup","DNS queries",                   "all"),
            ("openssl",   "SSL/TLS analysis",                "web, api, infra"),
        ]
        for name, purpose, domains in rows:
            t.add_row(name, purpose, domains)
        console.print(t)

    def list_checks(self) -> None:
        checks = self.config.domain_checks
        for domain, data in checks.items():
            t = Table(title=f"{self.DOMAIN_LABELS.get(domain, domain)} Checks",
                      show_header=False)
            t.add_column("Check", style="cyan")
            for check in data.get("checks", []):
                t.add_row(check)
            console.print(t)
            console.print("")

    # ------------------------------------------------------------------
    # Agent loop
    # ------------------------------------------------------------------

    async def _agent_loop(
        self,
        system: str,
        tools: list[dict],
        initial_message: str,
        tool_executor,
        verbose: bool = False,
    ) -> dict:
        messages: list[dict] = [{"role": "user", "content": initial_message}]
        iteration = 0
        max_iter = self.config.max_iterations
        conversation_log = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("Agent thinking…", total=None)

            while iteration < max_iter:
                iteration += 1
                progress.update(task, description=f"[cyan]Agent iteration {iteration}/{max_iter}…[/cyan]")

                response = await self.client.messages.create(
                    model=self.config.model,
                    max_tokens=self.config.max_tokens,
                    system=system,
                    tools=tools,
                    messages=messages,
                )

                # Append assistant turn
                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                for block in assistant_content:
                    if hasattr(block, "text") and block.text:
                        conversation_log.append({"role": "assistant", "text": block.text})
                        if verbose:
                            console.print(Panel(block.text, title="[bold blue]Agent[/bold blue]", style="blue"))

                if response.stop_reason == "end_turn":
                    break

                if response.stop_reason == "tool_use":
                    tool_results = []
                    for block in assistant_content:
                        if block.type == "tool_use":
                            progress.update(task, description=f"[yellow]Running tool: {block.name}…[/yellow]")
                            result = await self._run_tool(block.name, block.input, tool_executor)

                            if verbose:
                                console.print(f"[dim]Tool:[/dim] [bold yellow]{block.name}[/bold yellow]")
                                console.print(f"[dim]{json.dumps(block.input, indent=2)}[/dim]")
                                console.print(f"[dim]Result (truncated):[/dim] {str(result)[:500]}")

                            conversation_log.append({
                                "role": "tool",
                                "name": block.name,
                                "input": block.input,
                                "result": str(result)[:2000],
                            })
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": block.id,
                                "content": json.dumps(result) if isinstance(result, dict) else str(result),
                            })

                    messages.append({"role": "user", "content": tool_results})

        # Extract structured findings from the last assistant message
        findings = self._extract_findings(messages, conversation_log)
        return findings

    async def _run_tool(self, name: str, inputs: dict, tool_executor) -> Any:
        try:
            if asyncio.iscoroutinefunction(tool_executor):
                return await tool_executor(name, inputs)
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: tool_executor(name, inputs))
        except Exception as exc:
            return {"error": str(exc), "tool": name}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_findings(self, messages: list, conversation_log: list) -> dict:
        """Pull structured findings from the agent's final response."""
        last_text = ""
        for msg in reversed(messages):
            if msg.get("role") == "assistant":
                for block in (msg.get("content") or []):
                    if hasattr(block, "text") and block.text:
                        last_text = block.text
                        break
                if last_text:
                    break

        # Try to parse a JSON block the agent may have emitted
        findings_data = self._try_parse_json_block(last_text)
        if findings_data and isinstance(findings_data, dict):
            findings_data["conversation"] = conversation_log
            return findings_data

        return {
            "findings": [],
            "summary": last_text,
            "recommendations": [],
            "conversation": conversation_log,
        }

    @staticmethod
    def _try_parse_json_block(text: str) -> dict | None:
        import re
        patterns = [
            r"```json\s*([\s\S]+?)\s*```",
            r"```\s*([\{][\s\S]+?)\s*```",
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    pass
        # Fallback: try the whole text
        try:
            return json.loads(text)
        except Exception:
            return None

    async def _detect_domain(self, target: str) -> str:
        """Heuristic auto-detect of domain type from the target string."""
        t = target.lower()
        if any(k in t for k in ["0x", ".eth", "contract", "defi", "nft", "blockchain", "web3"]):
            return "web3"
        if any(k in t for k in ["/api/", "/graphql", "/rest/", "/soap", "/v1/", "/v2/"]):
            return "api"
        if any(k in t for k in ["llm", "gpt", "openai", "anthropic", "model", "chat", "ai"]):
            return "llm"
        if any(k in t for k in ["apk", "ipa", "android", "ios", "mobile"]):
            return "mobile"
        # Default: web
        return "web"

    def _load_domain(self, domain: str):
        """Lazy-import and instantiate the requested domain module."""
        mapping = {
            "web":    ("aso.domains.web",          "WebDomain"),
            "api":    ("aso.domains.api",           "APIDomain"),
            "web3":   ("aso.domains.web3",          "Web3Domain"),
            "llm":    ("aso.domains.llm",           "LLMDomain"),
            "thick":  ("aso.domains.thick_client",  "ThickClientDomain"),
            "mobile": ("aso.domains.mobile",        "MobileDomain"),
            "infra":  ("aso.domains.infra",         "InfraDomain"),
        }
        if domain not in mapping:
            raise ValueError(f"Unknown domain: {domain}")
        mod_path, cls_name = mapping[domain]
        import importlib
        mod = importlib.import_module(mod_path)
        cls = getattr(mod, cls_name)
        return cls(self.config)

    def _save_results(self, result: dict, output_dir: str) -> Path:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        target_slug = result["meta"]["target"].replace("://", "_").replace("/", "_").strip("_")[:40]
        fname = f"aso_{result['meta']['domain']}_{target_slug}_{ts}.json"
        out = Path(output_dir) / fname
        with open(out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        return out

    def _render_report(self, result: dict, output_dir: str, fmt: str) -> None:
        from .reports.generator import ReportGenerator
        gen = ReportGenerator(result, output_dir)
        if fmt in ("html", "all"):
            path = gen.html()
            console.print(f"[bold green]HTML report:[/bold green] {path}")
        if fmt in ("json", "all"):
            path = gen.json_report()
            console.print(f"[bold green]JSON report:[/bold green] {path}")
        if fmt in ("md", "all"):
            path = gen.markdown()
            console.print(f"[bold green]Markdown report:[/bold green] {path}")

    def _print_summary(self, result: dict) -> None:
        findings = result.get("findings", [])
        meta = result["meta"]

        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        t = Table(title="Assessment Summary", show_header=True, header_style="bold")
        t.add_column("Severity", style="bold")
        t.add_column("Count", justify="right")

        colors = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                  "LOW": "blue", "INFO": "dim"}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count:
                t.add_row(f"[{colors.get(sev, 'white')}]{sev}[/]", str(count))

        if not severity_counts:
            t.add_row("[dim]No findings[/dim]", "0")

        console.print(t)
        console.print(f"\n[dim]Elapsed: {meta['elapsed_seconds']}s  |  "
                      f"Domain: {meta['domain_label']}  |  Target: {meta['target']}[/dim]")
