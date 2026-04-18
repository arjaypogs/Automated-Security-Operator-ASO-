"""
ASO Tester Service — isolated tool execution API.
The backend forwards tool commands here instead of running them locally.
This container has all security tools (nmap, nikto, ffuf, nuclei, etc.) installed.
"""

import asyncio
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="ASO Tester", description="Isolated security tool execution service")

ALLOWED_TOOLS = {
    "nmap", "nikto", "gobuster", "ffuf", "nuclei", "wfuzz", "curl", "wget",
    "whois", "dig", "nslookup", "host", "openssl", "subfinder", "amass",
    "whatweb", "wafw00f", "dnsrecon", "fierce", "sslscan", "ping", "nc",
}


class ExecRequest(BaseModel):
    command: list[str]
    timeout: int = 120
    stdin: str | None = None


class ExecResponse(BaseModel):
    stdout: str
    stderr: str
    returncode: int
    error: str | None = None


@app.get("/health")
def health():
    return {"status": "ok", "service": "ASO Tester"}


@app.get("/tools")
def list_tools():
    """List available security tools."""
    available = []
    for tool in sorted(ALLOWED_TOOLS):
        result = subprocess.run(["which", tool], capture_output=True, text=True)
        if result.returncode == 0:
            available.append({"name": tool, "path": result.stdout.strip()})
    return {"tools": available}


@app.post("/exec", response_model=ExecResponse)
async def execute(req: ExecRequest):
    if not req.command:
        raise HTTPException(400, "Empty command")

    tool = req.command[0]
    if tool not in ALLOWED_TOOLS:
        raise HTTPException(403, f"Tool '{tool}' is not in the allowed list")

    try:
        proc = await asyncio.create_subprocess_exec(
            *req.command,
            stdin=asyncio.subprocess.PIPE if req.stdin else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdin_bytes = req.stdin.encode() if req.stdin else None
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=req.timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ExecResponse(
                stdout="", stderr="",
                returncode=-1,
                error=f"Command timed out after {req.timeout}s",
            )

        return ExecResponse(
            stdout=stdout.decode("utf-8", errors="replace")[:32000],
            stderr=stderr.decode("utf-8", errors="replace")[:8000],
            returncode=proc.returncode,
        )

    except FileNotFoundError:
        return ExecResponse(
            stdout="", stderr="",
            returncode=127,
            error=f"Tool not found: {tool}",
        )
    except Exception as exc:
        return ExecResponse(
            stdout="", stderr="",
            returncode=-1,
            error=str(exc),
        )
