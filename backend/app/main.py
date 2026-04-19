"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .routers import findings, reports, scans, sessions


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="ASO — Automated Security Operator",
    description="AI Pentest Agent API — pairs with Claude Code CLI via MCP",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(sessions.router)
app.include_router(findings.router)
app.include_router(reports.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ASO Backend"}
