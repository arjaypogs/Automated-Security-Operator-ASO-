"""Base class for all ASO domain modules."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from abc import ABC, abstractmethod
from typing import Any

from ..config import Config


class BaseDomain(ABC):
    """Every domain module inherits from this class."""

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        """Return the Claude system prompt for this domain."""

    @abstractmethod
    def tools(self) -> list[dict]:
        """Return Claude tool definitions for this domain."""

    @abstractmethod
    def initial_message(self, target: str, depth: str) -> str:
        """Return the first user message that kicks off the pentest."""

    @abstractmethod
    def execute_tool(self, name: str, inputs: dict) -> Any:
        """Execute a tool by name and return the result."""

    # ------------------------------------------------------------------
    # Shared tool implementations
    # ------------------------------------------------------------------

    def _run_command(self, cmd: list[str], timeout: int = 120) -> dict:
        """Run a shell command, forwarding to the tester service if TOOL_RUNNER_URL is set."""
        tester_url = os.getenv("TOOL_RUNNER_URL", "").rstrip("/")
        if tester_url:
            return self._remote_command(tester_url, cmd, timeout)
        return self._local_command(cmd, timeout)

    def _local_command(self, cmd: list[str], timeout: int) -> dict:
        """Execute command locally via subprocess."""
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return {
                "stdout": proc.stdout[:8000],
                "stderr": proc.stderr[:2000],
                "returncode": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"error": f"Command timed out after {timeout}s", "cmd": " ".join(cmd)}
        except FileNotFoundError:
            return {"error": f"Tool not found: {cmd[0]}. Install it or disable in config."}
        except Exception as exc:
            return {"error": str(exc)}

    def _remote_command(self, tester_url: str, cmd: list[str], timeout: int) -> dict:
        """Forward command to the tester microservice."""
        import httpx
        try:
            resp = httpx.post(
                f"{tester_url}/exec",
                json={"command": cmd, "timeout": timeout},
                timeout=timeout + 10,
            )
            data = resp.json()
            if data.get("error"):
                return {"error": data["error"], "stdout": "", "stderr": ""}
            return {
                "stdout": data.get("stdout", ""),
                "stderr": data.get("stderr", ""),
                "returncode": data.get("returncode", 0),
            }
        except Exception as exc:
            return {"error": f"Tester service error: {exc}"}

    def _tool_enabled(self, name: str) -> bool:
        return self.config.tool(name).get("enabled", False)

    def _tool_path(self, name: str) -> str:
        return self.config.tool(name).get("path", name)

    # ------------------------------------------------------------------
    # Common tool schemas shared across domains
    # ------------------------------------------------------------------

    @staticmethod
    def _schema_run_command() -> dict:
        return {
            "name": "run_command",
            "description": "Run an arbitrary shell command (security tools only). Returns stdout/stderr.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command and arguments as an array, e.g. ['nmap', '-sV', '10.0.0.1']",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 120)",
                        "default": 120,
                    },
                },
                "required": ["command"],
            },
        }

    @staticmethod
    def _schema_http_request() -> dict:
        return {
            "name": "http_request",
            "description": "Make an HTTP request to a target URL. Returns status, headers, body.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                        "default": "GET",
                    },
                    "headers": {
                        "type": "object",
                        "description": "HTTP headers as key-value pairs",
                    },
                    "body": {"type": "string", "description": "Request body"},
                    "follow_redirects": {"type": "boolean", "default": True},
                },
                "required": ["url"],
            },
        }

    @staticmethod
    def _schema_save_finding() -> dict:
        return {
            "name": "save_finding",
            "description": "Save a confirmed vulnerability or security finding.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short finding title"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "CVSS-based severity",
                    },
                    "cwe": {"type": "string", "description": "CWE identifier, e.g. CWE-79"},
                    "cvss_score": {"type": "number", "description": "CVSS 3.1 base score 0-10"},
                    "description": {"type": "string", "description": "Detailed description"},
                    "evidence": {"type": "string", "description": "Proof / reproduction steps"},
                    "remediation": {"type": "string", "description": "How to fix"},
                    "references": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "URLs / CVEs / OWASP references",
                    },
                },
                "required": ["title", "severity", "description", "evidence", "remediation"],
            },
        }

    @staticmethod
    def _schema_finish_assessment() -> dict:
        return {
            "name": "finish_assessment",
            "description": "Signal that the assessment is complete and submit the final report.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "severity": {"type": "string"},
                                "cwe": {"type": "string"},
                                "cvss_score": {"type": "number"},
                                "description": {"type": "string"},
                                "evidence": {"type": "string"},
                                "remediation": {"type": "string"},
                                "references": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["title", "severity", "description", "evidence", "remediation"],
                        },
                        "description": "All confirmed findings",
                    },
                    "summary": {"type": "string", "description": "Executive summary of the assessment"},
                    "recommendations": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "High-level remediation recommendations",
                    },
                },
                "required": ["findings", "summary", "recommendations"],
            },
        }

    def _handle_common_tools(self, name: str, inputs: dict) -> Any | None:
        """Handle tools shared across all domains. Returns None if not handled."""
        if name == "run_command":
            allowed_prefixes = [
                "nmap", "nikto", "gobuster", "ffuf", "nuclei", "sqlmap",
                "wfuzz", "curl", "wget", "whois", "dig", "nslookup", "host",
                "openssl", "amass", "subfinder", "whatweb", "wafw00f",
                "dnsrecon", "fierce", "theHarvester", "sslscan",
            ]
            cmd = inputs.get("command", [])
            if not cmd:
                return {"error": "Empty command"}
            if cmd[0] not in allowed_prefixes:
                return {"error": f"Tool '{cmd[0]}' is not in the allowed list for security testing."}
            return self._run_command(cmd, timeout=inputs.get("timeout", 120))

        if name == "http_request":
            return self._http_request(inputs)

        if name in ("save_finding", "finish_assessment"):
            # These are handled by the agent loop directly
            return {"status": "recorded", "data": inputs}

        return None

    def _http_request(self, inputs: dict) -> dict:
        import httpx
        url = inputs["url"]
        method = inputs.get("method", "GET").upper()
        headers = inputs.get("headers", {})
        body = inputs.get("body")
        follow = inputs.get("follow_redirects", True)

        default_ua = self.config.get("scan", "user_agent",
                                     default="ASO-Scanner/1.0 (Authorized Security Assessment)")
        headers.setdefault("User-Agent", default_ua)

        proxy = self.config.get("scan", "proxy")
        proxies = {"http://": proxy, "https://": proxy} if proxy else None
        verify = self.config.get("scan", "verify_ssl", default=False)

        try:
            with httpx.Client(verify=verify, proxies=proxies,
                              follow_redirects=follow, timeout=30) as client:
                resp = client.request(method, url, headers=headers,
                                      content=body.encode() if body else None)
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:8000],
                "url": str(resp.url),
            }
        except Exception as exc:
            return {"error": str(exc)}
