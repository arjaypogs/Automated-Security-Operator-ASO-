"""Web Service / API domain — OWASP API Security Top 10."""

from __future__ import annotations
import json
from typing import Any
from .base import BaseDomain


_SYSTEM = """You are ASO, an expert API/Web-Service penetration tester conducting an authorized bug bounty assessment.

## Methodology — OWASP API Security Top 10
1. **Reconnaissance** — discover API documentation (Swagger/OpenAPI/Postman), endpoints, auth scheme
2. **API Mapping** — enumerate all endpoints, HTTP methods, parameters, and data models
3. **Vulnerability Testing**:
   - API1:2023 Broken Object Level Authorization (BOLA/IDOR) — access other users' resources
   - API2:2023 Broken Authentication — weak tokens, JWT flaws, missing rate limiting
   - API3:2023 Broken Object Property Level Authorization — over-posting, mass assignment
   - API4:2023 Unrestricted Resource Consumption — no rate limits, large payloads
   - API5:2023 Broken Function Level Authorization — unprivileged access to admin functions
   - API6:2023 Unrestricted Access to Sensitive Business Flows — abuse of business logic
   - API7:2023 Server-Side Request Forgery (SSRF)
   - API8:2023 Security Misconfiguration — CORS, verbose errors, default creds
   - API9:2023 Improper Inventory Management — shadow/deprecated APIs
   - API10:2023 Unsafe Consumption of APIs — third-party injection
4. **Auth Testing** — JWT tampering, token prediction, OAuth flaws, API key exposure
5. **Injection Testing** — SQLi, NoSQLi, SSTI, command injection via API parameters
6. **Rate Limiting & DoS** — test for missing rate limits (safely)
7. **Reporting** — record findings with CVSS scores and remediation steps

## Rules
- Stay within declared scope
- Do not cause service disruption
- Confirm every finding before saving it
- Call finish_assessment() with all findings and executive summary when done
"""


class APIDomain(BaseDomain):

    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        depth_note = {
            "quick":    "Focus on auth, BOLA, and obvious misconfigs. Skip exhaustive endpoint bruteforce.",
            "standard": "Full OWASP API Top 10 assessment with endpoint enumeration.",
            "deep":     "Exhaustive: full endpoint/parameter fuzzing, auth bypass chains, business logic abuse.",
        }[depth]
        return (
            _SYSTEM
            + f"\n\n## Target\n{target}\n\n## Scope\n{', '.join(scope)}\n\n## Depth\n{depth_note}"
        )

    def initial_message(self, target: str, depth: str) -> str:
        return (
            f"Begin a comprehensive API security assessment of: {target}\n\n"
            f"Depth: {depth}\n\n"
            "Start by discovering the API structure (check /swagger.json, /openapi.json, /api-docs, "
            "/graphql, /v1/, /v2/ etc). Then map all endpoints, test authentication, "
            "check for BOLA/IDOR, test authorization, look for injection vulnerabilities, "
            "and test rate limiting. Call finish_assessment() with all findings when done."
        )

    def tools(self) -> list[dict]:
        return [
            self._schema_run_command(),
            self._schema_http_request(),
            self._schema_save_finding(),
            self._schema_finish_assessment(),
            {
                "name": "test_jwt",
                "description": "Analyze and test a JWT token for security weaknesses.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string", "description": "JWT token string"},
                        "url": {"type": "string", "description": "Endpoint to test against"},
                    },
                    "required": ["token"],
                },
            },
            {
                "name": "fuzz_api_endpoint",
                "description": "Fuzz an API endpoint with common parameter names and values.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                        "base_headers": {"type": "object", "description": "Auth headers etc."},
                        "fuzz_type": {
                            "type": "string",
                            "enum": ["idor", "params", "methods", "content_types"],
                            "default": "idor",
                        },
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "test_graphql",
                "description": "Test a GraphQL endpoint for introspection, injection, and auth issues.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "headers": {"type": "object"},
                    },
                    "required": ["url"],
                },
            },
            {
                "name": "check_api_auth",
                "description": "Test API authentication mechanisms.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "auth_type": {
                            "type": "string",
                            "enum": ["bearer", "basic", "api_key", "oauth"],
                        },
                        "token": {"type": "string"},
                    },
                    "required": ["url"],
                },
            },
        ]

    def execute_tool(self, name: str, inputs: dict) -> Any:
        result = self._handle_common_tools(name, inputs)
        if result is not None:
            return result

        if name == "test_jwt":
            return self._test_jwt(inputs)
        if name == "fuzz_api_endpoint":
            return self._fuzz_api_endpoint(inputs)
        if name == "test_graphql":
            return self._test_graphql(inputs)
        if name == "check_api_auth":
            return self._check_api_auth(inputs)

        return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------

    def _test_jwt(self, inputs: dict) -> dict:
        token = inputs["token"]
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Not a valid JWT (expected 3 parts)"}

        def _decode(s: str) -> dict:
            padding = 4 - len(s) % 4
            s += "=" * padding
            try:
                return json.loads(base64.urlsafe_b64decode(s))
            except Exception:
                return {}

        header = _decode(parts[0])
        payload = _decode(parts[1])

        issues = []
        alg = header.get("alg", "")
        if alg.lower() == "none":
            issues.append("CRITICAL: Algorithm is 'none' — signature verification disabled")
        if alg.upper() in ("HS256", "HS384", "HS512"):
            issues.append("Algorithm uses shared secret (HMAC) — susceptible to brute force if weak secret")
        if "exp" not in payload:
            issues.append("Token has no expiration (exp) claim — tokens never expire")

        result = {
            "header": header,
            "payload": payload,
            "algorithm": alg,
            "issues": issues,
        }

        # Test alg:none bypass if URL provided
        url = inputs.get("url")
        if url:
            none_token = parts[0].replace(
                base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("="),
                base64.urlsafe_b64encode(json.dumps({**header, "alg": "none"}).encode()).decode().rstrip("=")
            ) + "." + parts[1] + "."
            resp = self._http_request({"url": url, "headers": {"Authorization": f"Bearer {none_token}"}})
            result["alg_none_bypass_test"] = {
                "status_code": resp.get("status_code"),
                "potentially_vulnerable": resp.get("status_code", 401) not in (401, 403),
            }

        return result

    def _fuzz_api_endpoint(self, inputs: dict) -> dict:
        url = inputs["url"]
        method = inputs.get("method", "GET")
        headers = inputs.get("base_headers", {})
        fuzz_type = inputs.get("fuzz_type", "idor")

        results = []

        if fuzz_type == "idor":
            # Test numeric ID manipulation
            for id_val in [0, 1, 2, 99, 100, -1, 999999]:
                test_url = url.rstrip("/") + f"/{id_val}"
                resp = self._http_request({"url": test_url, "method": method, "headers": headers})
                results.append({
                    "url": test_url,
                    "status_code": resp.get("status_code"),
                    "body_length": len(resp.get("body", "")),
                })

        elif fuzz_type == "methods":
            for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]:
                resp = self._http_request({"url": url, "method": m, "headers": headers})
                results.append({"method": m, "status_code": resp.get("status_code")})

        elif fuzz_type == "content_types":
            for ct in ["application/json", "application/xml", "text/plain",
                       "application/x-www-form-urlencoded", "multipart/form-data"]:
                h = {**headers, "Content-Type": ct}
                resp = self._http_request({"url": url, "method": "POST", "headers": h, "body": "{}"})
                results.append({"content_type": ct, "status_code": resp.get("status_code")})

        return {"url": url, "fuzz_type": fuzz_type, "results": results}

    def _test_graphql(self, inputs: dict) -> dict:
        url = inputs["url"]
        headers = {**inputs.get("headers", {}), "Content-Type": "application/json"}

        # Introspection query
        intro_query = '{"query":"{__schema{types{name}}}"}'
        resp_intro = self._http_request({"url": url, "method": "POST",
                                          "headers": headers, "body": intro_query})
        introspection_enabled = (resp_intro.get("status_code") == 200 and
                                  "__schema" in resp_intro.get("body", ""))

        # Batch query attack
        batch = '[{"query":"{__typename}"},{"query":"{__typename}"}]'
        resp_batch = self._http_request({"url": url, "method": "POST",
                                          "headers": headers, "body": batch})

        return {
            "url": url,
            "introspection_enabled": introspection_enabled,
            "introspection_response": resp_intro.get("body", "")[:2000],
            "batch_query_supported": resp_batch.get("status_code") == 200,
        }

    def _check_api_auth(self, inputs: dict) -> dict:
        url = inputs["url"]
        results = {}

        # Test unauthenticated access
        resp_unauth = self._http_request({"url": url})
        results["unauthenticated_access"] = {
            "status_code": resp_unauth.get("status_code"),
            "accessible": resp_unauth.get("status_code", 401) not in (401, 403),
        }

        # Test with empty/invalid auth
        resp_empty = self._http_request({"url": url, "headers": {"Authorization": "Bearer "}})
        results["empty_bearer"] = {
            "status_code": resp_empty.get("status_code"),
            "accessible": resp_empty.get("status_code", 401) not in (401, 403),
        }

        resp_invalid = self._http_request({"url": url, "headers": {"Authorization": "Bearer invalid_token_12345"}})
        results["invalid_bearer"] = {
            "status_code": resp_invalid.get("status_code"),
            "accessible": resp_invalid.get("status_code", 401) not in (401, 403),
        }

        return {"url": url, "auth_tests": results}
