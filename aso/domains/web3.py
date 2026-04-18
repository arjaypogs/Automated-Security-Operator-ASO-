"""Web3 / Blockchain domain — smart contract and DeFi security."""

from __future__ import annotations
import re
from typing import Any
from .base import BaseDomain


_SYSTEM = """You are ASO, an expert Web3 and smart contract security researcher conducting an authorized bug bounty assessment.

## Methodology — Smart Contract & DeFi Security
1. **Reconnaissance** — identify blockchain, contract addresses, deployed bytecode, source code (Etherscan/BSCScan)
2. **Static Analysis** — analyze Solidity source for known vulnerability patterns
3. **Vulnerability Testing** (SWC Registry + DeFi-specific):
   - SWC-107 Reentrancy (single/cross-function, cross-contract)
   - SWC-101 Integer Overflow/Underflow
   - SWC-115 Authorization via tx.origin
   - SWC-104 Unchecked Return Values
   - SWC-116 Timestamp Dependence
   - SWC-120 Weak Sources of Randomness
   - SWC-105 Unprotected Ether Withdrawal
   - SWC-106 Unprotected SELFDESTRUCT
   - SWC-100 Function Default Visibility
   - Access Control Flaws — missing onlyOwner, wrong role checks
   - Flash Loan Attacks — price manipulation, oracle manipulation
   - Front-Running — MEV, sandwich attacks
   - Delegate Call Vulnerabilities
   - Proxy/Upgrade Pattern Flaws
   - Token Standard Deviations (ERC20/721/1155 issues)
   - Price Oracle Manipulation
   - Logic Errors / Business Logic Flaws
4. **DeFi-Specific Testing** — liquidity pool manipulation, yield farming exploits, governance attacks
5. **Reporting** — CVSS-equivalent severity, exploit scenario, mitigation

## Rules
- Analysis only — do not deploy exploit contracts on mainnet
- Testnet PoC acceptable for critical findings
- Use save_finding() for each confirmed vulnerability
- Call finish_assessment() with complete findings when done
"""


class Web3Domain(BaseDomain):

    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        depth_note = {
            "quick":    "Focus on common patterns: reentrancy, access control, integer overflow.",
            "standard": "Full smart contract audit covering SWC registry and DeFi-specific issues.",
            "deep":     "Exhaustive: formal analysis hints, cross-contract interactions, economic attack vectors.",
        }[depth]
        return (
            _SYSTEM
            + f"\n\n## Target\n{target}\n\n## Scope\n{', '.join(scope)}\n\n## Depth\n{depth_note}"
        )

    def initial_message(self, target: str, depth: str) -> str:
        return (
            f"Begin a smart contract / Web3 security assessment of: {target}\n\n"
            f"Depth: {depth}\n\n"
            "If the target is a contract address, fetch the source from Etherscan/BSCScan. "
            "Analyze for reentrancy, access control issues, integer bugs, oracle manipulation, "
            "flash loan vectors, and logic errors. Run static analysis tools if available. "
            "Call finish_assessment() with all findings when done."
        )

    def tools(self) -> list[dict]:
        return [
            self._schema_run_command(),
            self._schema_http_request(),
            self._schema_save_finding(),
            self._schema_finish_assessment(),
            {
                "name": "analyze_solidity",
                "description": "Analyze Solidity source code for common vulnerability patterns.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "source_code": {"type": "string", "description": "Solidity source code"},
                        "contract_name": {"type": "string"},
                    },
                    "required": ["source_code"],
                },
            },
            {
                "name": "fetch_contract_source",
                "description": "Fetch verified contract source code from a block explorer.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Contract address (0x...)"},
                        "network": {
                            "type": "string",
                            "enum": ["ethereum", "bsc", "polygon", "arbitrum", "optimism", "avalanche"],
                            "default": "ethereum",
                        },
                    },
                    "required": ["address"],
                },
            },
            {
                "name": "check_abi",
                "description": "Analyze a contract ABI for dangerous or exposed functions.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "abi": {"type": "string", "description": "ABI JSON string"},
                        "address": {"type": "string"},
                    },
                    "required": ["abi"],
                },
            },
        ]

    def execute_tool(self, name: str, inputs: dict) -> Any:
        result = self._handle_common_tools(name, inputs)
        if result is not None:
            return result

        if name == "analyze_solidity":
            return self._analyze_solidity(inputs["source_code"], inputs.get("contract_name", "Unknown"))
        if name == "fetch_contract_source":
            return self._fetch_contract_source(inputs["address"], inputs.get("network", "ethereum"))
        if name == "check_abi":
            return self._check_abi(inputs["abi"], inputs.get("address", ""))

        return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------

    def _analyze_solidity(self, source: str, name: str) -> dict:
        findings = []

        checks = [
            (r"\.call\{value:", "Potential reentrancy: uses low-level .call — check for CEI pattern", "high"),
            (r"tx\.origin", "Use of tx.origin for authorization — susceptible to phishing (SWC-115)", "high"),
            (r"block\.(timestamp|number)", "Timestamp/block number dependence for randomness or timing (SWC-116)", "medium"),
            (r"selfdestruct\s*\(", "SELFDESTRUCT present — high risk if unprotected (SWC-106)", "high"),
            (r"delegatecall\s*\(", "DELEGATECALL present — storage collision risk", "high"),
            (r"assembly\s*\{", "Inline assembly — requires manual review", "medium"),
            (r"function\s+\w+\s*\([^)]*\)\s*(public|external)\s*(?!view|pure)", "Public/external state-changing function", "info"),
            (r"pragma solidity\s+\^?0\.[0-6]\.", "Outdated Solidity version — use >=0.8.0 for overflow protection", "medium"),
            (r"uint\s+\w+\s*=.*-", "Potential integer underflow (pre-0.8 style)", "medium"),
            (r"\.transfer\s*\(", "Use of .transfer — may fail with proxied contracts, consider .call", "low"),
            (r"ecrecover\s*\(", "ecrecover — verify against address(0) and handle signature malleability", "medium"),
            (r"msg\.sender\s*==\s*owner", "Owner check — ensure owner cannot be address(0)", "low"),
        ]

        for pattern, description, severity in checks:
            matches = re.findall(pattern, source, re.MULTILINE | re.IGNORECASE)
            if matches:
                findings.append({
                    "pattern": pattern,
                    "description": description,
                    "severity": severity,
                    "occurrences": len(matches),
                })

        # Try running slither if available
        slither = self._run_command(["slither", "--detect", "all", "--json", "-", "--solc-disable-warnings"], timeout=60)

        return {
            "contract": name,
            "static_analysis": findings,
            "slither": slither.get("stdout", slither.get("error", "slither not available")),
            "lines": len(source.splitlines()),
        }

    def _fetch_contract_source(self, address: str, network: str) -> dict:
        explorers = {
            "ethereum": "https://api.etherscan.io/api",
            "bsc": "https://api.bscscan.com/api",
            "polygon": "https://api.polygonscan.com/api",
            "arbitrum": "https://api.arbiscan.io/api",
            "optimism": "https://api-optimistic.etherscan.io/api",
            "avalanche": "https://api.snowtrace.io/api",
        }
        base = explorers.get(network, explorers["ethereum"])
        url = f"{base}?module=contract&action=getsourcecode&address={address}&apikey=YourApiKeyToken"
        resp = self._http_request({"url": url})
        return {
            "address": address,
            "network": network,
            "response": resp.get("body", "")[:8000],
            "note": "Add ETHERSCAN_API_KEY env var for authenticated requests",
        }

    def _check_abi(self, abi_str: str, address: str) -> dict:
        import json as _json
        try:
            abi = _json.loads(abi_str)
        except Exception:
            return {"error": "Invalid ABI JSON"}

        dangerous = []
        for item in abi:
            if item.get("type") != "function":
                continue
            name = item.get("name", "")
            state = item.get("stateMutability", "")
            visibility = item.get("visibility", "public")

            if name.lower() in ("withdraw", "selfdestruct", "kill", "drain",
                                 "transferownership", "renounceownership", "upgrade",
                                 "initialize", "setowner", "setimplementation"):
                dangerous.append({
                    "function": name,
                    "stateMutability": state,
                    "concern": "Privileged or destructive function — verify access control",
                })

        return {
            "address": address,
            "total_functions": sum(1 for i in abi if i.get("type") == "function"),
            "dangerous_functions": dangerous,
        }
