"""Infrastructure domain — network, cloud, and server security."""

from __future__ import annotations
from typing import Any
from .base import BaseDomain


_SYSTEM = """You are ASO, an expert infrastructure and network penetration tester.

## Methodology — Infrastructure Security Assessment (PTES + NIST)
1. **Discovery & Reconnaissance**:
   - Port scanning (nmap), service version detection
   - OS fingerprinting
   - Banner grabbing
   - DNS enumeration, zone transfers
   - WHOIS, ASN, netblock discovery
2. **Vulnerability Scanning**:
   - Run Nuclei templates against discovered services
   - Check for known CVEs in identified software versions
   - Default credentials on services (FTP, SSH, Telnet, SNMP, web admin)
   - Exposed management interfaces (Kubernetes dashboard, Elasticsearch, MongoDB, Redis)
3. **Service-Specific Tests**:
   - SSH: weak ciphers, key auth only, root login
   - FTP: anonymous login, writable directories
   - SMTP: open relay, user enumeration
   - SNMP: default community strings (public/private)
   - SMB: null sessions, EternalBlue, signing
   - RDP: BlueKeep, NLA, weak auth
   - Web services: admin panels, API endpoints
   - Database ports: unauthenticated access (3306, 5432, 27017, 6379, 9200)
4. **Cloud Security** (AWS/GCP/Azure):
   - S3/GCS/Azure Blob public access
   - Metadata service (SSRF → IMDS)
   - IAM misconfigurations
   - Exposed cloud dashboards
   - Secrets in cloud storage
5. **Network Segmentation** — inter-VLAN access, DMZ bypass
6. **Privilege Escalation Paths** — identify weak sudo, SUID binaries, writable cron
7. **Reporting** — CVE references, CVSS scores, remediation

## Rules
- Only scan authorized IP ranges/domains
- No destructive exploits — document findings with PoC only
- Avoid service disruption (no aggressive DoS scans)
- Call finish_assessment() with all findings when done
"""


class InfraDomain(BaseDomain):

    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        depth_note = {
            "quick":    "Top ports scan, service detection, quick vuln scan with Nuclei.",
            "standard": "Full port scan, service enumeration, default creds, known CVE check.",
            "deep":     "Exhaustive: all ports, brute force, lateral movement paths, cloud misconfigs.",
        }[depth]
        return (
            _SYSTEM
            + f"\n\n## Target\n{target}\n\n## Scope\n{', '.join(scope)}\n\n## Depth\n{depth_note}"
        )

    def initial_message(self, target: str, depth: str) -> str:
        return (
            f"Begin an infrastructure security assessment of: {target}\n\n"
            f"Depth: {depth}\n\n"
            "Start with port scanning (nmap), identify running services, check for "
            "known vulnerabilities, default credentials, exposed admin interfaces, "
            "and misconfigurations. For cloud targets, check for public storage, "
            "IMDS exposure, and IAM issues. Call finish_assessment() with all findings when done."
        )

    def tools(self) -> list[dict]:
        return [
            self._schema_run_command(),
            self._schema_http_request(),
            self._schema_save_finding(),
            self._schema_finish_assessment(),
            {
                "name": "port_scan",
                "description": "Run an nmap port scan against a target.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "IP, hostname, or CIDR"},
                        "scan_type": {
                            "type": "string",
                            "enum": ["quick", "full", "udp", "version", "vuln"],
                            "default": "version",
                        },
                        "ports": {"type": "string", "description": "Port range e.g. '1-1000' or 'top100'"},
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "check_default_creds",
                "description": "Check a service for default/common credentials.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "service": {
                            "type": "string",
                            "enum": ["ssh", "ftp", "telnet", "snmp", "http", "mysql", "postgres",
                                     "mongodb", "redis", "elasticsearch", "smb", "rdp"],
                        },
                    },
                    "required": ["host", "service"],
                },
            },
            {
                "name": "check_cloud_storage",
                "description": "Check for publicly accessible cloud storage buckets.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "provider": {
                            "type": "string",
                            "enum": ["aws", "gcp", "azure"],
                            "default": "aws",
                        },
                        "bucket_name": {"type": "string", "description": "Bucket/container name to test"},
                    },
                    "required": ["provider", "bucket_name"],
                },
            },
            {
                "name": "check_exposed_service",
                "description": "Check if a specific service is exposed and misconfigured.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "service_type": {
                            "type": "string",
                            "enum": ["elasticsearch", "mongodb", "redis", "kubernetes",
                                     "docker", "consul", "etcd", "memcached", "cassandra"],
                        },
                    },
                    "required": ["host", "port", "service_type"],
                },
            },
            {
                "name": "dns_enum",
                "description": "Perform DNS enumeration on a domain.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string"},
                        "enum_type": {
                            "type": "string",
                            "enum": ["records", "zone_transfer", "subdomain_bruteforce", "all"],
                            "default": "records",
                        },
                    },
                    "required": ["domain"],
                },
            },
        ]

    def execute_tool(self, name: str, inputs: dict) -> Any:
        result = self._handle_common_tools(name, inputs)
        if result is not None:
            return result

        if name == "port_scan":
            return self._port_scan(inputs)
        if name == "check_default_creds":
            return self._check_default_creds(inputs)
        if name == "check_cloud_storage":
            return self._check_cloud_storage(inputs)
        if name == "check_exposed_service":
            return self._check_exposed_service(inputs)
        if name == "dns_enum":
            return self._dns_enum(inputs)

        return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------

    def _port_scan(self, inputs: dict) -> dict:
        target = inputs["target"]
        scan_type = inputs.get("scan_type", "version")
        ports = inputs.get("ports", "")

        nmap_flags = {
            "quick":   ["-F", "--open"],
            "full":    ["-p-", "--open"],
            "udp":     ["-sU", "--open", "-F"],
            "version": ["-sV", "-sC", "--open"],
            "vuln":    ["-sV", "--script=vuln", "--open"],
        }

        cmd = [self._tool_path("nmap")]
        cmd.extend(nmap_flags.get(scan_type, ["-sV", "--open"]))
        if ports:
            cmd.extend(["-p", ports])
        cmd.extend(["-oN", "-", target])

        result = self._run_command(cmd, timeout=300)
        return {
            "target": target,
            "scan_type": scan_type,
            "output": result.get("stdout", result.get("error", "")),
        }

    def _check_default_creds(self, inputs: dict) -> dict:
        host = inputs["host"]
        port = inputs.get("port")
        service = inputs["service"]

        default_ports = {
            "ssh": 22, "ftp": 21, "telnet": 23, "snmp": 161,
            "http": 80, "mysql": 3306, "postgres": 5432,
            "mongodb": 27017, "redis": 6379, "elasticsearch": 9200,
            "smb": 445, "rdp": 3389,
        }
        port = port or default_ports.get(service, 80)

        common_creds = {
            "ssh":  [("root", "root"), ("admin", "admin"), ("admin", "password"), ("root", "toor")],
            "ftp":  [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
            "mysql": [("root", ""), ("root", "root"), ("root", "password")],
            "redis": [("", ""), ("", "redis"), ("", "password")],
            "mongodb": [("", ""), ("admin", "admin")],
        }

        if service == "redis":
            result = self._run_command(["redis-cli", "-h", host, "-p", str(port), "INFO"], timeout=10)
            return {
                "host": host, "port": port, "service": service,
                "unauthenticated_access": "redis_version" in result.get("stdout", "").lower(),
                "output": result.get("stdout", result.get("error", ""))[:500],
            }

        if service == "elasticsearch":
            resp = self._http_request({"url": f"http://{host}:{port}/_cluster/health"})
            return {
                "host": host, "port": port, "service": service,
                "unauthenticated_access": resp.get("status_code") == 200,
                "response": resp.get("body", "")[:500],
            }

        if service == "mongodb":
            result = self._run_command(
                ["mongosh", "--host", host, "--port", str(port), "--eval", "db.adminCommand({listDatabases:1})"],
                timeout=10
            )
            return {
                "host": host, "port": port, "service": service,
                "unauthenticated_access": "databases" in result.get("stdout", "").lower(),
                "output": result.get("stdout", result.get("error", ""))[:500],
            }

        return {
            "host": host, "port": port, "service": service,
            "default_creds_to_test": common_creds.get(service, []),
            "note": f"Use Hydra or Medusa for automated brute-force: hydra -L users.txt -P pass.txt {service}://{host}",
        }

    def _check_cloud_storage(self, inputs: dict) -> dict:
        provider = inputs["provider"]
        bucket = inputs["bucket_name"]

        urls = {
            "aws":   [f"https://{bucket}.s3.amazonaws.com/", f"https://s3.amazonaws.com/{bucket}/"],
            "gcp":   [f"https://storage.googleapis.com/{bucket}/"],
            "azure": [f"https://{bucket}.blob.core.windows.net/"],
        }

        results = []
        for url in urls.get(provider, []):
            resp = self._http_request({"url": url})
            results.append({
                "url": url,
                "status_code": resp.get("status_code"),
                "publicly_accessible": resp.get("status_code") in (200, 206),
                "body_excerpt": resp.get("body", "")[:500],
            })

        return {"provider": provider, "bucket": bucket, "results": results}

    def _check_exposed_service(self, inputs: dict) -> dict:
        host = inputs["host"]
        port = inputs["port"]
        service = inputs["service_type"]

        endpoints = {
            "elasticsearch": [f"http://{host}:{port}/_cat/indices", f"http://{host}:{port}/_cluster/health"],
            "mongodb":       [f"mongodb://{host}:{port}/"],
            "redis":         ["redis-cli"],
            "kubernetes":    [f"https://{host}:{port}/api/v1/namespaces", f"http://{host}:8080/api/v1/"],
            "docker":        [f"http://{host}:{port}/v1.41/containers/json"],
            "consul":        [f"http://{host}:{port}/v1/agent/members"],
            "etcd":          [f"http://{host}:{port}/v2/keys/", f"https://{host}:{port}/v3/keys"],
            "memcached":     [],
        }

        results = []
        for url in endpoints.get(service, []):
            if url.startswith("http"):
                resp = self._http_request({"url": url, "follow_redirects": False})
                results.append({
                    "url": url,
                    "status_code": resp.get("status_code"),
                    "accessible": resp.get("status_code") not in (401, 403, None),
                    "response_excerpt": resp.get("body", "")[:300],
                })

        return {"host": host, "port": port, "service": service, "tests": results}

    def _dns_enum(self, inputs: dict) -> dict:
        domain = inputs["domain"]
        etype = inputs.get("enum_type", "records")

        results = {}

        if etype in ("records", "all"):
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
                r = self._run_command(["dig", "+short", rtype, domain], timeout=10)
                if r.get("stdout", "").strip():
                    results[rtype] = r["stdout"].strip().splitlines()

        if etype in ("zone_transfer", "all"):
            ns_result = self._run_command(["dig", "+short", "NS", domain], timeout=10)
            nameservers = ns_result.get("stdout", "").strip().splitlines()
            zt_results = []
            for ns in nameservers[:3]:
                zt = self._run_command(["dig", "AXFR", domain, f"@{ns.rstrip('.')}"], timeout=15)
                zt_results.append({
                    "nameserver": ns,
                    "output": zt.get("stdout", "")[:2000],
                    "transfer_possible": "XFR size" in zt.get("stdout", ""),
                })
            results["zone_transfer"] = zt_results

        if etype in ("subdomain_bruteforce", "all"):
            subfinder = self._run_command(["subfinder", "-d", domain, "-silent"], timeout=60)
            amass = self._run_command(["amass", "enum", "-passive", "-d", domain], timeout=120)
            results["subdomains_subfinder"] = subfinder.get("stdout", "").splitlines()[:100]
            results["subdomains_amass"] = amass.get("stdout", "").splitlines()[:100]

        return {"domain": domain, "enum_type": etype, "results": results}
