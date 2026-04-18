"""Mobile Application domain — Android and iOS security (OWASP MASVS)."""

from __future__ import annotations
from typing import Any
from .base import BaseDomain


_SYSTEM = """You are ASO, an expert mobile application penetration tester following OWASP MASVS.

## Methodology — OWASP Mobile Application Security Verification Standard
1. **Reconnaissance** — identify platform (Android/iOS), app version, third-party SDKs
2. **Static Analysis**:
   - Android: decompile APK with jadx/apktool, review AndroidManifest.xml
   - iOS: analyze IPA, Info.plist, binary protections
   - Hardcoded secrets, API keys, credentials in source
   - Insecure permissions and exported components
3. **Dynamic Analysis**:
   - Intercept network traffic (Burp + certificate pinning bypass)
   - Hook runtime with Frida/objection
   - File system monitoring during runtime
4. **MASVS Testing**:
   - MSTG-STORAGE: Insecure data storage (SharedPreferences, SQLite, logs, clipboard)
   - MSTG-CRYPTO: Weak cryptography, hardcoded keys, insecure random
   - MSTG-AUTH: Insecure authentication, biometric bypass, session management
   - MSTG-NETWORK: Certificate validation, certificate pinning, clear-text traffic
   - MSTG-PLATFORM: WebView issues, IPC abuse, exported components
   - MSTG-CODE: Debugging, anti-tampering, obfuscation bypass
   - MSTG-RESILIENCE: Root/jailbreak detection bypass
5. **Backend API Testing** — test the APIs the mobile app consumes
6. **Reporting** — CVSS scores, MASVS reference, PoC steps

## Rules
- Only test authorized applications
- Do not submit to app stores or modify production apps
- Use Frida/objection for dynamic analysis
- Call finish_assessment() with all findings when done
"""


class MobileDomain(BaseDomain):

    def system_prompt(self, target: str, scope: list[str], depth: str) -> str:
        depth_note = {
            "quick":    "Focus on network traffic, hardcoded secrets, and exported components.",
            "standard": "Full MASVS assessment: static + dynamic analysis.",
            "deep":     "Exhaustive: binary analysis, runtime hooks, backend API testing, all MASVS controls.",
        }[depth]
        return (
            _SYSTEM
            + f"\n\n## Target\n{target}\n\n## Scope\n{', '.join(scope)}\n\n## Depth\n{depth_note}"
        )

    def initial_message(self, target: str, depth: str) -> str:
        return (
            f"Begin a mobile application security assessment of: {target}\n\n"
            f"Depth: {depth}\n\n"
            "The target may be an APK file path, IPA file path, or bundle ID. "
            "Start with static analysis (decompile, manifest review, string search), "
            "then guide through dynamic testing setup and MASVS controls. "
            "Call finish_assessment() with all findings when done."
        )

    def tools(self) -> list[dict]:
        return [
            self._schema_run_command(),
            self._schema_http_request(),
            self._schema_save_finding(),
            self._schema_finish_assessment(),
            {
                "name": "analyze_apk",
                "description": "Analyze an Android APK file for security issues.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "apk_path": {"type": "string", "description": "Path to APK file"},
                        "analysis_type": {
                            "type": "string",
                            "enum": ["manifest", "strings", "permissions", "components", "full"],
                            "default": "manifest",
                        },
                    },
                    "required": ["apk_path"],
                },
            },
            {
                "name": "analyze_ipa",
                "description": "Analyze an iOS IPA file for security issues.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ipa_path": {"type": "string", "description": "Path to IPA file"},
                        "analysis_type": {
                            "type": "string",
                            "enum": ["info_plist", "strings", "binary_protections", "full"],
                            "default": "info_plist",
                        },
                    },
                    "required": ["ipa_path"],
                },
            },
            {
                "name": "frida_script",
                "description": "Generate a Frida script for mobile app hooking/analysis.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "script_type": {
                            "type": "string",
                            "enum": [
                                "ssl_pinning_bypass",
                                "root_detection_bypass",
                                "hook_crypto",
                                "dump_strings",
                                "trace_calls",
                            ],
                        },
                        "app_package": {"type": "string", "description": "App package/bundle ID"},
                    },
                    "required": ["script_type"],
                },
            },
            {
                "name": "check_network_security_config",
                "description": "Analyze Android network_security_config.xml or iOS ATS settings.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "config_content": {"type": "string", "description": "XML/plist content"},
                        "platform": {"type": "string", "enum": ["android", "ios"], "default": "android"},
                    },
                    "required": ["config_content"],
                },
            },
        ]

    def execute_tool(self, name: str, inputs: dict) -> Any:
        result = self._handle_common_tools(name, inputs)
        if result is not None:
            return result

        if name == "analyze_apk":
            return self._analyze_apk(inputs)
        if name == "analyze_ipa":
            return self._analyze_ipa(inputs)
        if name == "frida_script":
            return self._frida_script(inputs)
        if name == "check_network_security_config":
            return self._check_nsc(inputs)

        return {"error": f"Unknown tool: {name}"}

    # ------------------------------------------------------------------

    def _analyze_apk(self, inputs: dict) -> dict:
        apk = inputs["apk_path"]
        atype = inputs.get("analysis_type", "manifest")

        if atype in ("manifest", "full"):
            # Try apktool first
            decompile = self._run_command(["apktool", "d", "-f", apk, "-o", "/tmp/apk_out"], timeout=60)
            if decompile.get("returncode", 1) == 0:
                manifest = self._run_command(["cat", "/tmp/apk_out/AndroidManifest.xml"], timeout=10)
                manifest_content = manifest.get("stdout", "")
            else:
                manifest_content = decompile.get("error", "apktool not available")

            # Parse dangerous items
            issues = []
            if "android:allowBackup=\"true\"" in manifest_content:
                issues.append("allowBackup=true: app data can be extracted via ADB backup")
            if "android:debuggable=\"true\"" in manifest_content:
                issues.append("debuggable=true: app is debuggable in production build")
            if "android:exported=\"true\"" in manifest_content:
                issues.append("Exported components found: may allow unauthorized access")
            if "android:usesCleartextTraffic=\"true\"" in manifest_content:
                issues.append("usesCleartextTraffic=true: clear-text HTTP allowed")

            return {
                "apk": apk,
                "manifest_excerpt": manifest_content[:3000],
                "issues": issues,
            }

        if atype == "strings":
            result = self._run_command(["strings", apk], timeout=30)
            output = result.get("stdout", "")
            sensitive = [l for l in output.splitlines()
                         if any(p in l.lower() for p in
                                ["password", "secret", "api_key", "token", "http://", "private"])]
            return {"apk": apk, "sensitive_strings": sensitive[:100]}

        if atype == "permissions":
            aapt = self._run_command(["aapt", "dump", "permissions", apk], timeout=15)
            return {"apk": apk, "permissions": aapt.get("stdout", aapt.get("error", ""))}

        return {"error": f"Unknown analysis_type: {atype}"}

    def _analyze_ipa(self, inputs: dict) -> dict:
        ipa = inputs["ipa_path"]
        atype = inputs.get("analysis_type", "info_plist")

        # Extract IPA (it's a zip)
        extract = self._run_command(["unzip", "-o", ipa, "-d", "/tmp/ipa_out"], timeout=30)

        if atype == "info_plist":
            plist = self._run_command(["find", "/tmp/ipa_out", "-name", "Info.plist"], timeout=10)
            plist_path = plist.get("stdout", "").strip().split("\n")[0] if plist.get("stdout") else ""
            if plist_path:
                content = self._run_command(["plutil", "-p", plist_path], timeout=10)
                return {"ipa": ipa, "info_plist": content.get("stdout", "")[:3000]}
            return {"ipa": ipa, "error": "Info.plist not found"}

        if atype == "binary_protections":
            binary = self._run_command(["find", "/tmp/ipa_out", "-type", "f",
                                         "-perm", "+111", "!", "-name", "*.dylib"], timeout=10)
            bin_path = binary.get("stdout", "").strip().split("\n")[0] if binary.get("stdout") else ""
            if bin_path:
                checksec = self._run_command(["checksec", "--file", bin_path], timeout=15)
                otool = self._run_command(["otool", "-l", bin_path], timeout=15)
                return {
                    "ipa": ipa,
                    "binary": bin_path,
                    "checksec": checksec.get("stdout", ""),
                    "otool_excerpt": otool.get("stdout", "")[:2000],
                }
            return {"ipa": ipa, "error": "Binary not found"}

        return {"error": f"Unknown analysis_type: {atype}"}

    def _frida_script(self, inputs: dict) -> dict:
        script_type = inputs["script_type"]
        pkg = inputs.get("app_package", "com.target.app")

        scripts = {
            "ssl_pinning_bypass": f"""// SSL Pinning Bypass for {pkg}
// Usage: frida -U -f {pkg} -l ssl_bypass.js --no-pause
Java.perform(function() {{
    var CertificateFactory = Java.use('java.security.cert.CertificateFactory');
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // Bypass OkHttp CertificatePinner
    try {{
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {{
            console.log('[SSL Bypass] Bypassing OkHttp pinning for: ' + a);
        }};
    }} catch(e) {{ console.log('OkHttp not found: ' + e); }}

    // Bypass TrustManager
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(a, b, c, d, e, f) {{
        console.log('[SSL Bypass] TrustManagerImpl bypassed');
        return a;
    }};
}});""",

            "root_detection_bypass": f"""// Root Detection Bypass for {pkg}
Java.perform(function() {{
    // Bypass RootBeer
    try {{
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {{
            console.log('[Root Bypass] isRooted() hooked -> false');
            return false;
        }};
    }} catch(e) {{}}

    // Bypass file checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {{
        var path = this.getAbsolutePath();
        var rootPaths = ['/su', '/system/bin/su', '/sbin/su', '/system/xbin/su',
                         '/data/local/xbin/su', '/data/local/bin/su'];
        if (rootPaths.indexOf(path) >= 0) {{
            console.log('[Root Bypass] File.exists() returning false for: ' + path);
            return false;
        }}
        return this.exists();
    }};
}});""",

            "hook_crypto": f"""// Crypto Hook for {pkg} — dumps keys and plaintext
Java.perform(function() {{
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(data) {{
        console.log('[Crypto] doFinal input: ' + bytes2hex(data));
        var result = this.doFinal(data);
        console.log('[Crypto] doFinal output: ' + bytes2hex(result));
        return result;
    }};

    function bytes2hex(arr) {{
        return Array.from(arr).map(b => ('0' + (b & 0xFF).toString(16)).slice(-2)).join('');
    }}
}});""",

            "dump_strings": f"""// String Dumper for {pkg}
Java.perform(function() {{
    var String = Java.use('java.lang.String');
    String.$init.overload('[B').implementation = function(bytes) {{
        var str = this.$init(bytes);
        if (this.length() > 10 && this.length() < 500) {{
            console.log('[String] ' + this.toString());
        }}
        return str;
    }};
}});""",

            "trace_calls": f"""// Method Tracer for {pkg}
// Usage: frida-trace -U -f {pkg} -j '*!*'
// Or use this to trace a specific class:
Java.perform(function() {{
    Java.enumerateLoadedClasses({{
        onMatch: function(name) {{
            if (name.includes('{pkg}')) {{
                console.log('[Class] ' + name);
            }}
        }},
        onComplete: function() {{ console.log('[Tracer] Done'); }}
    }});
}});""",
        }

        return {
            "script_type": script_type,
            "app_package": pkg,
            "script": scripts.get(script_type, "# Script not found"),
            "usage": f"frida -U -f {pkg} -l script.js --no-pause",
        }

    def _check_nsc(self, inputs: dict) -> dict:
        content = inputs["config_content"]
        platform = inputs.get("platform", "android")
        issues = []

        if platform == "android":
            if "cleartextTrafficPermitted=\"true\"" in content:
                issues.append("clearTextTrafficPermitted=true globally — plaintext HTTP allowed")
            if "<domain-config" in content and "cleartextTrafficPermitted=\"true\"" in content:
                issues.append("Some domains allow cleartext traffic")
            if "<trust-anchors>" not in content:
                issues.append("No explicit trust anchors — trusts system CAs by default")
            if "user" in content and "certificates" in content:
                issues.append("User-installed certificates are trusted — insecure in production")

        elif platform == "ios":
            if "NSAllowsArbitraryLoads" in content:
                issues.append("NSAllowsArbitraryLoads=YES — ATS disabled, all HTTP allowed")
            if "NSExceptionAllowsInsecureHTTPLoads" in content:
                issues.append("Domain-specific ATS exception for insecure HTTP")

        return {
            "platform": platform,
            "issues": issues,
            "config_excerpt": content[:2000],
        }
