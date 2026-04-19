"""
ASO MCP Server — exposes pentest tools to Claude Code CLI via Model Context Protocol.

Usage (Claude Code CLI):
  Add to your .mcp.json:
  {
    "mcpServers": {
      "aso": { "url": "http://localhost:8002/sse" }
    }
  }
  Then run: claude  (Claude Code CLI will connect automatically)

  Or for stdio mode (local dev):
  claude --mcp-server "python mcp_server/server.py"
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

TESTER_URL   = os.getenv("TOOL_RUNNER_URL", "http://tester:8001")
BACKEND_URL  = os.getenv("BACKEND_URL",     "http://backend:8000")
MCP_HOST     = os.getenv("MCP_HOST",        "0.0.0.0")
MCP_PORT     = int(os.getenv("MCP_PORT",    "8002"))
CAIDO_URL    = os.getenv("CAIDO_URL",       "http://caido:8080")
CAIDO_API_KEY = os.getenv("CAIDO_API_KEY",  "")

mcp = FastMCP(
    name="ASO — Automated Security Operator",
    instructions=(
        "You are ASO, an expert penetration tester. "
        "Use the provided tools to conduct authorized security assessments. "
        "Always call save_finding() when you discover a vulnerability. "
        "Call finish_session() when the assessment is complete."
    ),
)


# ──────────────────────────────────────────────────
# Tool execution — runs in isolated tester container
# ──────────────────────────────────────────────────

@mcp.tool()
async def run_command(command: list[str], timeout: int = 120) -> dict:
    """
    Execute a penetration testing tool in the isolated security container.
    Allowed tools: nmap, nikto, gobuster, ffuf, nuclei, sqlmap, subfinder,
    wfuzz, curl, wget, whois, dig, nslookup, host, openssl, amass, whatweb.

    Args:
        command: Command and arguments as a list, e.g. ["nmap", "-sV", "10.0.0.1"]
        timeout: Max execution time in seconds (default 120)

    Returns:
        dict with stdout, stderr, returncode (and optional error key)
    """
    async with httpx.AsyncClient(timeout=timeout + 15) as client:
        try:
            resp = await client.post(
                f"{TESTER_URL}/exec",
                json={"command": command, "timeout": timeout},
            )
            return resp.json()
        except Exception as exc:
            return {"error": str(exc), "stdout": "", "stderr": "", "returncode": -1}


@mcp.tool()
async def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    follow_redirects: bool = True,
    via_caido: bool = False,
) -> dict:
    """
    Make an HTTP request to a target URL for security testing.

    Args:
        url:              Target URL
        method:           HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
        headers:          Request headers as key-value pairs
        body:             Request body string
        follow_redirects: Whether to follow HTTP redirects
        via_caido:        Route through Caido proxy so the request appears in Caido history

    Returns:
        dict with status_code, headers, body (truncated to 8000 chars), url
    """
    hdrs = headers or {}
    hdrs.setdefault("User-Agent", "ASO-Scanner/1.0 (Authorized Security Assessment)")
    proxy_url = CAIDO_URL if via_caido else None
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=follow_redirects,
            timeout=30,
            proxy=proxy_url,
        ) as client:
            resp = await client.request(
                method.upper(), url, headers=hdrs,
                content=body.encode() if body else None,
            )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:8000],
            "url": str(resp.url),
            "proxied_via_caido": via_caido,
        }
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
async def save_finding(
    title: str,
    severity: str,
    description: str,
    evidence: str,
    remediation: str,
    cwe: str | None = None,
    cvss_score: float | None = None,
    references: list[str] | None = None,
    session_id: str | None = None,
) -> dict:
    """
    Save a confirmed security finding to the database.

    Args:
        title:       Short finding title (e.g. "Reflected XSS in search param")
        severity:    critical | high | medium | low | info
        description: Detailed description of the vulnerability
        evidence:    Proof of exploitability / reproduction steps
        remediation: How to fix the issue
        cwe:         CWE identifier (e.g. "CWE-79")
        cvss_score:  CVSS 3.1 base score 0.0–10.0
        references:  List of URLs / CVEs / OWASP references
        session_id:  Current assessment session ID (from create_session)

    Returns:
        dict with finding_id and status
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                f"{BACKEND_URL}/api/findings",
                json={
                    "title": title,
                    "severity": severity.lower(),
                    "description": description,
                    "evidence": evidence,
                    "remediation": remediation,
                    "cwe": cwe,
                    "cvss_score": cvss_score,
                    "references": references or [],
                    "session_id": session_id,
                },
            )
            return resp.json()
        except Exception as exc:
            return {"error": str(exc), "status": "failed"}


@mcp.tool()
async def get_findings(session_id: str | None = None) -> list[dict]:
    """
    Retrieve saved findings from the database.

    Args:
        session_id: Filter by session ID. If None, returns all findings.

    Returns:
        List of finding objects
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            url = f"{BACKEND_URL}/api/findings"
            if session_id:
                url += f"?session_id={session_id}"
            resp = await client.get(url)
            return resp.json()
        except Exception as exc:
            return [{"error": str(exc)}]


@mcp.tool()
async def create_session(
    target: str,
    domain: str = "web",
    depth: str = "standard",
    scope: list[str] | None = None,
) -> dict:
    """
    Create a new assessment session. Call this at the start of every pentest.

    Args:
        target: Target URL, IP, or domain being assessed
        domain: web | api | web3 | llm | thick | mobile | infra
        depth:  quick | standard | deep
        scope:  List of in-scope targets (defaults to [target])

    Returns:
        dict with session_id to use in subsequent tool calls
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                f"{BACKEND_URL}/api/sessions",
                json={
                    "target": target,
                    "domain": domain,
                    "depth": depth,
                    "scope": scope or [target],
                },
            )
            return resp.json()
        except Exception as exc:
            return {"error": str(exc)}


@mcp.tool()
async def get_session(session_id: str) -> dict:
    """
    Get details and all findings for an existing session.

    Args:
        session_id: Session ID returned by create_session

    Returns:
        Session details including status and findings list
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{BACKEND_URL}/api/sessions/{session_id}")
            return resp.json()
        except Exception as exc:
            return {"error": str(exc)}


@mcp.tool()
async def finish_session(
    session_id: str,
    summary: str,
    recommendations: list[str],
) -> dict:
    """
    Mark an assessment session as complete and generate reports.

    Args:
        session_id:      Session ID from create_session
        summary:         Executive summary of the assessment
        recommendations: High-level remediation recommendations

    Returns:
        dict with report download links
    """
    async with httpx.AsyncClient(timeout=30) as client:
        try:
            resp = await client.post(
                f"{BACKEND_URL}/api/sessions/{session_id}/finish",
                json={"summary": summary, "recommendations": recommendations},
            )
            return resp.json()
        except Exception as exc:
            return {"error": str(exc)}


@mcp.tool()
async def list_available_tools() -> dict:
    """
    List all security tools available in the pentest container.

    Returns:
        dict with available tools and their paths
    """
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(f"{TESTER_URL}/tools")
            return resp.json()
        except Exception as exc:
            return {"error": str(exc), "tools": []}


@mcp.tool()
async def check_security_headers(url: str) -> dict:
    """
    Check HTTP security headers for a URL.
    Tests: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc.

    Args:
        url: Target URL to check

    Returns:
        dict mapping header names to their values or 'MISSING'
    """
    result = await http_request(url, method="HEAD")
    if "error" in result:
        result = await http_request(url)
    if "error" in result:
        return result

    headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
    checks = {
        "Strict-Transport-Security": "strict-transport-security",
        "Content-Security-Policy":   "content-security-policy",
        "X-Frame-Options":           "x-frame-options",
        "X-Content-Type-Options":    "x-content-type-options",
        "Referrer-Policy":           "referrer-policy",
        "Permissions-Policy":        "permissions-policy",
    }
    security_headers = {name: headers.get(key, "MISSING") for name, key in checks.items()}
    return {
        "url": url,
        "security_headers": security_headers,
        "server": headers.get("server", ""),
        "x_powered_by": headers.get("x-powered-by", ""),
        "cors": headers.get("access-control-allow-origin", "not set"),
    }


@mcp.tool()
async def check_cors(url: str, origin: str = "https://evil.com") -> dict:
    """
    Test for CORS misconfiguration.

    Args:
        url:    Target URL
        origin: Origin to test with (default: https://evil.com)

    Returns:
        dict with CORS headers and whether the config is vulnerable
    """
    result = await http_request(url, headers={"Origin": origin})
    if "error" in result:
        return result
    headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    return {
        "url": url,
        "tested_origin": origin,
        "access_control_allow_origin": acao,
        "access_control_allow_credentials": acac,
        "vulnerable": (acao == origin or acao == "*") and acac.lower() == "true",
    }


@mcp.tool()
async def analyze_jwt(token: str, test_url: str | None = None) -> dict:
    """
    Analyze a JWT token for security weaknesses.
    Checks: algorithm, expiration, alg:none bypass.

    Args:
        token:    JWT token string
        test_url: Optional endpoint to test alg:none bypass against

    Returns:
        dict with decoded header/payload and list of issues found
    """
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT — expected 3 parts"}

    def _decode(s: str) -> dict:
        s += "=" * (4 - len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s))
        except Exception:
            return {}

    header  = _decode(parts[0])
    payload = _decode(parts[1])
    issues  = []

    alg = header.get("alg", "")
    if alg.lower() == "none":
        issues.append("CRITICAL: alg=none — no signature verification")
    if alg.upper() in ("HS256", "HS384", "HS512"):
        issues.append("HMAC secret — susceptible to brute force if weak")
    if "exp" not in payload:
        issues.append("No expiration claim — tokens never expire")
    if "aud" not in payload:
        issues.append("No audience claim — may be usable across services")

    result = {"header": header, "payload": payload, "algorithm": alg, "issues": issues}

    if test_url:
        none_token = parts[0].replace(
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("="),
            base64.urlsafe_b64encode(json.dumps({**header, "alg": "none"}).encode()).decode().rstrip("="),
        ) + "." + parts[1] + "."
        resp = await http_request(test_url, headers={"Authorization": f"Bearer {none_token}"})
        result["alg_none_bypass"] = {
            "status_code": resp.get("status_code"),
            "potentially_vulnerable": resp.get("status_code", 401) not in (401, 403),
        }

    return result


def _caido_headers() -> dict:
    hdrs = {"Content-Type": "application/json"}
    if CAIDO_API_KEY:
        hdrs["X-Caido-Api-Key"] = CAIDO_API_KEY
    return hdrs


@mcp.tool()
async def get_caido_requests(
    filter_host: str | None = None,
    limit: int = 50,
) -> dict:
    """
    Fetch HTTP requests captured by the Caido proxy from its history.

    Args:
        filter_host: Optional hostname filter (e.g. "example.com")
        limit:       Max number of requests to return (default 50)

    Returns:
        dict with a list of request/response summaries from Caido history
    """
    query = """
    query GetRequests($first: Int) {
      requests(first: $first) {
        edges {
          node {
            id
            request {
              host
              port
              path
              query
              method
              httpVersion
            }
            response {
              statusCode
              roundtripTime
              length
            }
          }
        }
      }
    }
    """
    variables: dict = {"first": limit}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{CAIDO_URL}/graphql",
                headers=_caido_headers(),
                json={"query": query, "variables": variables},
            )
            data = resp.json()
        edges = data.get("data", {}).get("requests", {}).get("edges", [])
        rows = [e["node"] for e in edges if e.get("node")]
        if filter_host:
            rows = [
                r for r in rows
                if filter_host.lower() in (r.get("request", {}).get("host", "") or "").lower()
            ]
        return {"count": len(rows), "requests": rows}
    except Exception as exc:
        return {"error": str(exc), "requests": []}


@mcp.tool()
async def get_caido_request(request_id: str) -> dict:
    """
    Retrieve the full raw request and response for a specific Caido history entry.

    Args:
        request_id: ID from get_caido_requests

    Returns:
        dict with raw request bytes (base64) and raw response bytes (base64)
    """
    query = """
    query GetRequest($id: ID!) {
      request(id: $id) {
        id
        request {
          host port path query method httpVersion
          headers { name value }
          body { text }
        }
        response {
          statusCode httpVersion
          headers { name value }
          body { text }
          roundtripTime length
        }
      }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{CAIDO_URL}/graphql",
                headers=_caido_headers(),
                json={"query": query, "variables": {"id": request_id}},
            )
            return resp.json().get("data", {}).get("request", {})
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
async def replay_caido_request(
    request_id: str,
    edits: dict | None = None,
) -> dict:
    """
    Replay a Caido history request, optionally with modifications.
    Uses the Caido Replay API to send the request and capture the response.

    Args:
        request_id: ID of the request to replay (from get_caido_requests)
        edits:      Optional dict of fields to override before replaying,
                    e.g. {"path": "/admin", "body": {"text": "id=1 OR 1=1"}}

    Returns:
        dict with the replay response or an error
    """
    mutation = """
    mutation ReplayRequest($id: ID!, $input: ReplayRequestInput) {
      replayRequest(id: $id, input: $input) {
        response {
          statusCode
          headers { name value }
          body { text }
          roundtripTime
          length
        }
      }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{CAIDO_URL}/graphql",
                headers=_caido_headers(),
                json={
                    "query": mutation,
                    "variables": {"id": request_id, "input": edits or {}},
                },
            )
            return resp.json().get("data", {}).get("replayRequest", {})
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool()
async def get_caido_sitemap(host: str | None = None) -> dict:
    """
    Retrieve the site map discovered by Caido (all paths seen by the proxy).

    Args:
        host: Optional hostname to filter (e.g. "api.example.com")

    Returns:
        dict with discovered paths grouped by host
    """
    query = """
    query GetSitemap {
      sitemap {
        children {
          host
          paths
        }
      }
    }
    """
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{CAIDO_URL}/graphql",
                headers=_caido_headers(),
                json={"query": query},
            )
            children = (
                resp.json().get("data", {}).get("sitemap", {}).get("children", [])
            )
        if host:
            children = [c for c in children if host.lower() in c.get("host", "").lower()]
        return {"sitemap": children}
    except Exception as exc:
        return {"error": str(exc)}


if __name__ == "__main__":
    import sys
    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="sse", host=MCP_HOST, port=MCP_PORT)
