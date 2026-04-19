"""Web Application domain — OWASP Top 10 and beyond."""

from __future__ import annotations
from typing import Any
from .base import BaseDomain


_SYSTEM = """You are ASO (Automated Security Operator), an expert web application penetration tester conducting an authorized bug bounty assessment.

## Methodology
Follow this structured approach:
1. **Reconnaissance** — subdomain enumeration, technology fingerprinting, open ports, SSL/TLS review
2. **Discovery** — directory/file bruteforce, parameter discovery, JS analysis, API endpoint mapping
3. **Vulnerability Testing** — systematically test every OWASP Top 10 category:
   - A01 Broken Access Control (IDOR, path traversal, privilege escalation)
   - A02 Cryptographic Failures (weak TLS, cleartext secrets, weak hashing)
   - A03 Injection (SQLi, XSS, SSTI, command injection, XXE, LDAP injection)
   - A04 Insecure Design (business logic flaws, rate limiting, abuse cases)
   - A05 Security Misconfiguration (default creds, exposed admin, CORS, headers)
   - A06 Vulnerable Components (outdated libs/frameworks with known CVEs)
   - A07 Auth & Session Management (brute force, session fixation, JWT flaws)
   - A08 Software Integrity Failures (insecure deserialization, supply chain)
   - A09 Logging Failures (no audit logs, verbose errors)
   - A10 SSRF (server-side request forgery to internal services)
4. **Exploitation** — confirm findings with minimal PoC evidence
5. **Reporting** — record every finding with severity, CWE, evidence, and remediation

## Rules
- Stay within declared scope
- Do not cause DoS or data destruction
- Use save_finding() immediately when a vulnerability is confirmed
- Call finish_assessment() when done with all findings and a summary
- Emit findings as structured JSON via finish_assessment()

## Severity Guide (CVSS 3.1)
- Critical 9.0–10.0: RCE, auth bypass, massive data breach
- High 7.0–8.9: SQLi, stored XSS, IDOR exposing sensitive data
- Medium 4.0–6.9: Reflected XSS, CSRF, open redirect, info disclosure
- Low 0.1–3.9: Missing headers, version disclosure, weak TLS config
- Info: Observations without direct security impact
"""


class WebDomain(BaseDomain):

    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        scope_str = ", ".join(scope)
        depth_note = {
            "quick":    "Focus on high-impact quick wins: open ports, headers, obvious vulns. Skip exhaustive bruteforce.",
            "standard": "Full OWASP Top 10 assessment with directory enumeration and parameter testing.",
            "deep":     "Exhaustive assessment: full bruteforce, JS analysis, parameter mining, chained exploits.",
        }[depth]
        return (
            _SYSTEM
            + f"\n\n## Target\n{target}\n\n## Scope\n{scope_str}\n\n## Depth\n{depth_note}"
        )

    def initial_message(self, target: str, depth: str) -> str:
        return (
            f"Begin a comprehensive web application security assessment of: {target}\n\n"
            f"Scan depth: {depth}\n\n"
            "Start with reconnaissance (technology fingerprinting, subdomain enumeration, "
            "port scanning, SSL check), then move to discovery (directory enumeration, "
            "JS analysis), and finally systematic vulnerability testing. "
            "Use the available tools, confirm every finding, and call finish_assessment() "
            "with all results when done."
        )

    def tools(self) -> list[dict]:
        return [
            self._schema_run_command(),
            self._schema_http_request(),
            self._schema_save_finding(),
            self._schema_finish_assessment(),
            {
                "name": "check_security_headers",
                "description": "Analyze HTTP security headers for a URL.",
                "input_schema": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
            {
                "name": "test_xss",
                "description": "Test a URL/parameter for Cross-Site Scripting.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "parameter": {"type": "string", "description": "Parameter name to test"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    },
                    "required": ["url", "parameter"],
                },
            },
            {
                "name": "test_sqli",
                "description": "Test a URL/parameter for SQL injection.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "parameter": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
                    },
                    "required": ["url", "parameter"],
                },
            },
            {
                "name": "check_cors",
                "description": "Test for CORS misconfiguration on a URL.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "origin": {"type": "string", "default": "https://evil.com"},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "check_ssl",
                "description": "Analyze SSL/TLS configuration for a host.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "default": 443},
                    },
                    "required": ["host"],
                },
            },
        ]

    def execute_tool(self, name: str, inputs: dict) -> Any:
        result = self._handle_common_tools(name, inputs)
        if result is not None:
            return result

        if name == "check_security_headers":
            return self._check_security_headers(inputs["url"])
        if name == "test_xss":
            return self._test_xss(inputs)
        if name == "test_sqli":
            return self._test_sqli(inputs)
        if name == "check_cors":
            return self._check_cors(inputs)
        if name == "check_ssl":
            return self._check_ssl(inputs)

        return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------
    # Web-specific tool implementations
    # ------------------------------------------------------------------

    def _check_security_headers(self, url: str) -> dict:
        result = self._http_request({"url": url, "method": "HEAD"})
        if "error" in result:
            result = self._http_request({"url": url})
        if "error" in result:
            return result

        headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
        checks = {
            "Strict-Transport-Security": "strict-transport-security",
            "Content-Security-Policy": "content-security-policy",
            "X-Frame-Options": "x-frame-options",
            "X-Content-Type-Options": "x-content-type-options",
            "Referrer-Policy": "referrer-policy",
            "Permissions-Policy": "permissions-policy",
            "X-XSS-Protection": "x-xss-protection",
        }
        findings = {}
        for display, key in checks.items():
            findings[display] = headers.get(key, "MISSING")

        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        return {
            "url": url,
            "security_headers": findings,
            "server_disclosure": server,
            "x_powered_by": x_powered,
            "cors_header": headers.get("access-control-allow-origin", "not set"),
        }

    def _test_xss(self, inputs: dict) -> dict:
        url = inputs["url"]
        param = inputs["parameter"]
        method = inputs.get("method", "GET")
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1)//",
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
        ]
        results = []
        for payload in payloads:
            if method == "GET":
                test_url = f"{url}?{param}={payload}" if "?" not in url else f"{url}&{param}={payload}"
                resp = self._http_request({"url": test_url})
            else:
                resp = self._http_request({
                    "url": url, "method": "POST",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": f"{param}={payload}",
                })
            if "error" not in resp:
                body = resp.get("body", "")
                reflected = payload in body or payload.replace('"', '&quot;') in body
                results.append({
                    "payload": payload,
                    "reflected": reflected,
                    "status_code": resp.get("status_code"),
                })
        return {"url": url, "parameter": param, "xss_tests": results}

    def _test_sqli(self, inputs: dict) -> dict:
        url = inputs["url"]
        param = inputs["parameter"]
        method = inputs.get("method", "GET")
        payloads = ["'", "''", "' OR '1'='1", "' OR 1=1--", '" OR "1"="1']
        error_patterns = [
            "sql syntax", "mysql_fetch", "ora-0", "microsoft ole db",
            "odbc drivers", "sqlite", "postgresql", "syntax error",
            "unclosed quotation", "you have an error in your sql",
        ]
        results = []
        for payload in payloads:
            if method == "GET":
                test_url = f"{url}?{param}={payload}" if "?" not in url else f"{url}&{param}={payload}"
                resp = self._http_request({"url": test_url})
            else:
                resp = self._http_request({
                    "url": url, "method": "POST",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": f"{param}={payload}",
                })
            if "error" not in resp:
                body = resp.get("body", "").lower()
                error_found = any(p in body for p in error_patterns)
                results.append({
                    "payload": payload,
                    "sql_error_detected": error_found,
                    "status_code": resp.get("status_code"),
                })
        return {"url": url, "parameter": param, "sqli_tests": results}

    def _check_cors(self, inputs: dict) -> dict:
        url = inputs["url"]
        origin = inputs.get("origin", "https://evil.com")
        resp = self._http_request({
            "url": url,
            "headers": {"Origin": origin},
        })
        if "error" in resp:
            return resp
        headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        return {
            "url": url,
            "tested_origin": origin,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "vulnerable": (acao == origin or acao == "*") and acac.lower() == "true",
        }

    def _check_ssl(self, inputs: dict) -> dict:
        host = inputs["host"]
        port = inputs.get("port", 443)
        result = self._run_command(["openssl", "s_client", "-connect", f"{host}:{port}",
                                    "-showcerts", "<", "/dev/null"], timeout=15)
        sslscan = self._run_command(["sslscan", "--no-colour", f"{host}:{port}"], timeout=30)
        return {
            "host": host,
            "port": port,
            "openssl_output": result.get("stdout", result.get("error", "")),
            "sslscan_output": sslscan.get("stdout", sslscan.get("error", "")),
        }
