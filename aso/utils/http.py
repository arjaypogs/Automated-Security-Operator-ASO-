"""HTTP utility functions for ASO."""

from __future__ import annotations
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_domain(url: str) -> str:
    return urlparse(normalize_url(url)).netloc


def is_in_scope(url: str, scope: list[str]) -> bool:
    target = extract_domain(url)
    for s in scope:
        s_domain = extract_domain(s) if "://" in s else s
        if target == s_domain or target.endswith("." + s_domain):
            return True
    return False


def build_url(base: str, path: str = "", params: dict | None = None) -> str:
    url = urljoin(normalize_url(base), path)
    if params:
        url += "?" + urlencode(params)
    return url


def extract_links(html: str, base_url: str) -> list[str]:
    links = re.findall(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    result = []
    for link in links:
        if link.startswith(("http://", "https://")):
            result.append(link)
        elif link.startswith("/"):
            result.append(urljoin(base_url, link))
    return list(set(result))


def extract_forms(html: str) -> list[dict]:
    forms = []
    for form_match in re.finditer(
        r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE
    ):
        form_html = form_match.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        inputs = re.findall(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']*)["\'])?[^>]*>',
            form_html, re.IGNORECASE
        )
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "inputs": [{"name": n, "type": t or "text"} for n, t in inputs],
        })
    return forms


def parse_cookies(set_cookie_header: str) -> dict:
    flags = {}
    parts = set_cookie_header.split(";")
    for part in parts[1:]:
        part = part.strip().lower()
        if part == "httponly":
            flags["HttpOnly"] = True
        elif part == "secure":
            flags["Secure"] = True
        elif part.startswith("samesite"):
            flags["SameSite"] = part.split("=")[-1].strip()
    return flags


def check_cookie_security(set_cookie_header: str) -> list[str]:
    issues = []
    flags = parse_cookies(set_cookie_header)
    if not flags.get("HttpOnly"):
        issues.append("Missing HttpOnly flag — cookie accessible via JavaScript")
    if not flags.get("Secure"):
        issues.append("Missing Secure flag — cookie transmitted over HTTP")
    samesite = flags.get("SameSite", "")
    if samesite.lower() not in ("strict", "lax"):
        issues.append(f"SameSite={samesite or 'not set'} — CSRF risk")
    return issues
