#!/usr/bin/env python3
"""ASO - Automated Security Operator: AI Pentest Agent for Bug Bounty"""

import asyncio
import sys
import os

import click
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

console = Console()

BANNER = """
[bold red]
    ___   _____ ____
   /   | / ___// __ \\
  / /| | \\__ \\/ / / /
 / ___ |___/ / /_/ /
/_/  |_/____/\\____/
[/bold red]
[bold white]Automated Security Operator[/bold white]
[dim]AI Pentest Agent for Bug Bounty[/dim]
[dim]Domains: Web | API | Web3 | LLM | Thick Client | Mobile | Infrastructure[/dim]
"""

DOMAINS = ["web", "api", "web3", "llm", "thick", "mobile", "infra", "auto"]
DEPTHS = ["quick", "standard", "deep"]
FORMATS = ["html", "json", "md", "all"]


@click.group()
@click.version_option("1.0.0", prog_name="aso")
def cli():
    """ASO - Automated Security Operator: AI-powered pentest agent."""
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL, IP, or domain")
@click.option(
    "--domain", "-d", default="auto", type=click.Choice(DOMAINS),
    help="Testing domain (default: auto-detect)"
)
@click.option("--scope", "-s", multiple=True, help="In-scope targets (can specify multiple)")
@click.option("--output", "-o", default="results", help="Output directory for results")
@click.option(
    "--format", "-f", "fmt", default="html", type=click.Choice(FORMATS),
    help="Report format"
)
@click.option(
    "--depth", default="standard", type=click.Choice(DEPTHS),
    help="Scan depth: quick=recon only, standard=full scan, deep=exhaustive"
)
@click.option("--config", "-c", default="config.yaml", help="Config file path")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--no-banner", is_flag=True, hidden=True)
def scan(target, domain, scope, output, fmt, depth, config, verbose, no_banner):
    """Run a security assessment against a target."""
    if not no_banner:
        console.print(BANNER)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] ANTHROPIC_API_KEY not set. Copy .env.example to .env and add your key.")
        sys.exit(1)

    from aso.agent import ASO
    from aso.config import Config

    cfg = Config(config)
    agent = ASO(cfg)

    scope_list = list(scope) if scope else [target]

    console.print(f"\n[bold green]Target:[/bold green] {target}")
    console.print(f"[bold green]Domain:[/bold green] {domain}")
    console.print(f"[bold green]Depth:[/bold green] {depth}")
    console.print(f"[bold green]Scope:[/bold green] {', '.join(scope_list)}\n")

    asyncio.run(agent.scan(
        target=target,
        domain=domain,
        scope=scope_list,
        output_dir=output,
        report_format=fmt,
        depth=depth,
        verbose=verbose,
    ))


@cli.command()
@click.option("--input", "-i", "input_file", required=True, help="Input JSON results file")
@click.option(
    "--format", "-f", "fmt", default="html", type=click.Choice(FORMATS),
    help="Report format"
)
@click.option("--output", "-o", default="reports", help="Output directory")
def report(input_file, fmt, output):
    """Generate a report from a previous scan's JSON results."""
    console.print(BANNER)

    from aso.agent import ASO
    from aso.config import Config

    cfg = Config("config.yaml")
    agent = ASO(cfg)
    agent.generate_report(input_file, fmt, output)


@cli.command("list")
@click.option("--domains", "show_domains", is_flag=True, help="List testing domains")
@click.option("--tools", "show_tools", is_flag=True, help="List available tools")
@click.option("--checks", "show_checks", is_flag=True, help="List checks per domain")
def list_items(show_domains, show_tools, show_checks):
    """List available domains, tools, and checks."""
    console.print(BANNER)

    from aso.agent import ASO
    from aso.config import Config

    cfg = Config("config.yaml")
    agent = ASO(cfg)

    if show_domains:
        agent.list_domains()
    elif show_tools:
        agent.list_tools()
    elif show_checks:
        agent.list_checks()
    else:
        agent.list_domains()
        console.print("")
        agent.list_tools()


if __name__ == "__main__":
    cli()
