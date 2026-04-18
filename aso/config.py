"""Configuration management for ASO."""

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

load_dotenv()

_DEFAULTS = {
    "aso": {
        "model": "claude-opus-4-7",
        "max_tokens": 8192,
        "max_iterations": 50,
        "timeout": 300,
    },
    "output": {
        "directory": "results",
        "formats": ["html", "json"],
        "verbose": False,
    },
    "scan": {
        "default_depth": "standard",
        "rate_limit": 10,
        "user_agent": "ASO-Scanner/1.0 (Authorized Security Assessment)",
        "follow_redirects": True,
        "verify_ssl": False,
        "proxy": None,
    },
    "tools": {
        "nmap": {"enabled": True, "path": "nmap", "default_args": "-sV -sC --open"},
        "nikto": {"enabled": True, "path": "nikto"},
        "gobuster": {"enabled": True, "path": "gobuster", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
        "ffuf": {"enabled": True, "path": "ffuf", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
        "sqlmap": {"enabled": False, "path": "sqlmap", "safe_mode": True},
        "nuclei": {"enabled": True, "path": "nuclei", "templates": ""},
        "amass": {"enabled": True, "path": "amass"},
        "subfinder": {"enabled": True, "path": "subfinder"},
    },
}


class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self._data = dict(_DEFAULTS)
        self._load_file(config_path)
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")

    def _load_file(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        with open(p) as f:
            file_data = yaml.safe_load(f) or {}
        self._deep_merge(self._data, file_data)

    def _deep_merge(self, base: dict, override: dict) -> None:
        for key, val in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(val, dict):
                self._deep_merge(base[key], val)
            else:
                base[key] = val

    def get(self, *keys: str, default: Any = None) -> Any:
        node = self._data
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)
        return node

    @property
    def model(self) -> str:
        return self.get("aso", "model", default="claude-opus-4-7")

    @property
    def max_tokens(self) -> int:
        return self.get("aso", "max_tokens", default=8192)

    @property
    def max_iterations(self) -> int:
        return self.get("aso", "max_iterations", default=50)

    @property
    def tool_config(self, name: str = "") -> dict:
        return self.get("tools", default={})

    def tool(self, name: str) -> dict:
        return self.get("tools", name, default={})

    @property
    def scan_config(self) -> dict:
        return self.get("scan", default={})

    @property
    def domain_checks(self) -> dict:
        return self.get("domains", default={})
