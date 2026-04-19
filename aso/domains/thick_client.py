"""Thick Client domain — desktop application security testing."""

from __future__ import annotations
from typing import Any
from .base import BaseDomain


_SYSTEM = """You are ASO, an expert thick client / desktop application penetration tester.

## Methodology — Thick Client Security Testing
1. **Reconnaissance** — identify application framework, language, architecture (1-tier/2-tier/3-tier)
2. **Binary Analysis**:
   - Check for debugging symbols, obfuscation
   - Identify hardcoded credentials, API keys, URLs
   - Decompile/disassemble binaries (Ghidra, IDA, dnSpy, jadx)
3. **Network Traffic Analysis**:
   - Intercept traffic with Caido proxy
   - Check for unencrypted traffic, certificate pinning
   - Test custom protocols
4. **Local Storage Analysis**:
   - Registry keys, config files, temp files, log files
   - Credential storage (Windows Credential Store, keychain)
   - SQLite/local databases
5. **Memory Analysis**:
   - Sensitive data in memory (passwords, keys, PII)
   - Heap spray protection
6. **Authentication & Authorization**:
   - Client-side authentication bypass
   - Role/privilege enforcement
7. **Input Validation**:
   - Injection through UI components
   - File format vulnerabilities
8. **DLL Hijacking / Privilege Escalation**:
   - Missing DLLs, writable paths in PATH
   - Auto-update mechanisms
9. **Reporting** — findings with reproduction steps

## Rules
- Only analyze applications you are authorized to test
- Do not attempt to bypass license protection
- Call finish_assessment() with all findings when done
"""


class ThickClientDomain(BaseDomain):

    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        depth_note = {
            "quick":    "Focus on network traffic, hardcoded creds, and obvious client-side bypasses.",
            "standard": "Full assessment: binary analysis, network, local storage, auth.",
            "deep":     "Exhaustive: reverse engineering, memory analysis, DLL hijacking, privilege escalation.",
        }[depth]
        return (
            _SYSTEM
            + f"\n\n## Target\n{target}\n\n## Scope\n{', '.join(scope)}\n\n## Depth\n{depth_note}"
        )

    def initial_message(self, target: str, depth: str) -> str:
        return (
            f"Begin a thick client security assessment of: {target}\n\n"
            f"Depth: {depth}\n\n"
            "The target may be an executable path, installer, or application name. "
            "Start with reconnaissance (framework, language, architecture), then analyze "
            "network traffic, local storage, authentication, and binary for hardcoded secrets. "
            "Call finish_assessment() with all findings when done."
        )

    def tools(self) -> list[dict]:
        return [
            self._schema_run_command(),
            self._schema_http_request(),
            self._schema_save_finding(),
            self._schema_finish_assessment(),
            {
                "name": "analyze_binary",
                "description": "Analyze a binary/executable file for security issues.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to binary file"},
                        "analysis_type": {
                            "type": "string",
                            "enum": ["strings", "imports", "protections", "hardcoded_secrets"],
                            "default": "strings",
                        },
                    },
                    "required": ["file_path"],
                },
            },
            {
                "name": "scan_local_storage",
                "description": "Scan local storage locations for sensitive data.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Directory or file path to scan"},
                        "patterns": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Regex patterns to search for",
                        },
                    },
                    "required": ["path"],
                },
            },
            {
                "name": "check_dll_hijacking",
                "description": "Check for DLL hijacking opportunities in an application directory.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "app_path": {"type": "string", "description": "Application directory"},
                    },
                    "required": ["app_path"],
                },
            },
            {
                "name": "capture_network_traffic",
                "description": "Instructions for capturing and analyzing thick client network traffic.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "app_name": {"type": "string"},
                        "protocol": {"type": "string", "enum": ["http", "https", "custom", "all"], "default": "all"},
                    },
                    "required": ["app_name"],
                },
            },
        ]

    def execute_tool(self, name: str, inputs: dict) -> Any:
        result = self._handle_common_tools(name, inputs)
        if result is not None:
            return result

        if name == "analyze_binary":
            return self._analyze_binary(inputs)
        if name == "scan_local_storage":
            return self._scan_local_storage(inputs)
        if name == "check_dll_hijacking":
            return self._check_dll_hijacking(inputs)
        if name == "capture_network_traffic":
            return self._capture_network_traffic(inputs)

        return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------

    def _analyze_binary(self, inputs: dict) -> dict:
        path = inputs["file_path"]
        analysis_type = inputs.get("analysis_type", "strings")

        if analysis_type == "strings":
            result = self._run_command(["strings", "-n", "8", path], timeout=30)
            # Filter for interesting strings
            output = result.get("stdout", "")
            interesting = []
            patterns = ["password", "passwd", "secret", "api_key", "apikey", "token",
                        "http://", "https://", "jdbc:", "mongodb://", "mysql://",
                        "username", "admin", "private", "BEGIN RSA"]
            for line in output.splitlines():
                ll = line.lower()
                if any(p in ll for p in patterns):
                    interesting.append(line)
            return {"path": path, "interesting_strings": interesting[:100], "total_lines": len(output.splitlines())}

        elif analysis_type == "protections":
            checksec = self._run_command(["checksec", "--file", path], timeout=15)
            return {"path": path, "checksec": checksec.get("stdout", checksec.get("error", ""))}

        elif analysis_type == "imports":
            result = self._run_command(["objdump", "-d", "--no-show-raw-insn", path], timeout=30)
            return {"path": path, "imports": result.get("stdout", "")[:5000]}

        return {"error": f"Unknown analysis_type: {analysis_type}"}

    def _scan_local_storage(self, inputs: dict) -> dict:
        import os, re
        path = inputs["path"]
        patterns = inputs.get("patterns", [
            r"password\s*[=:]\s*\S+",
            r"api[_-]?key\s*[=:]\s*\S+",
            r"secret\s*[=:]\s*\S+",
            r"token\s*[=:]\s*\S+",
        ])

        findings = []
        try:
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__"}]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            content = f.read(50000)
                        for pat in patterns:
                            matches = re.findall(pat, content, re.IGNORECASE)
                            if matches:
                                findings.append({"file": fpath, "pattern": pat, "matches": matches[:5]})
                    except Exception:
                        continue
        except Exception as exc:
            return {"error": str(exc)}

        return {"path": path, "findings": findings[:50]}

    def _check_dll_hijacking(self, inputs: dict) -> dict:
        app_path = inputs["app_path"]
        result = self._run_command(["ls", "-la", app_path], timeout=10)
        # On Windows this would check for writable dirs in PATH and missing DLLs
        # On Linux we check for writable shared lib paths
        ldconfig = self._run_command(["ldconfig", "-p"], timeout=10)
        return {
            "app_path": app_path,
            "directory_listing": result.get("stdout", ""),
            "shared_libs": ldconfig.get("stdout", "")[:3000],
            "note": "Check for writable directories in PATH, missing DLLs via Procmon on Windows",
        }

    def _capture_network_traffic(self, inputs: dict) -> dict:
        return {
            "app_name": inputs["app_name"],
            "instructions": {
                "http_https": [
                    "Configure Caido as system proxy (127.0.0.1:7080)",
                    "Install Caido CA certificate: open http://127.0.0.1:7080 → Settings → CA Certificate",
                    "Launch application and observe traffic in Caido Intercept / HTTP History",
                    "Look for unencrypted credentials, session tokens, API keys",
                    "Use get_caido_requests() to pull captured traffic into ASO for automated analysis",
                ],
                "certificate_pinning_bypass": [
                    "Use Frida to hook SSL certificate validation",
                    "Use objection for mobile/Java apps: objection -g <app> explore",
                    "Patch binary to skip pinning check if static patching is needed",
                ],
                "custom_protocols": [
                    "Use Wireshark to capture raw traffic",
                    "Analyze with 'tcpdump -i any -w capture.pcap'",
                    "Decode protocol with custom Wireshark dissector or Scapy",
                ],
            },
        }
