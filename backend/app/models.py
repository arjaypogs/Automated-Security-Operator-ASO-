"""SQLAlchemy ORM models."""

from __future__ import annotations
import json
from datetime import datetime
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target: Mapped[str] = mapped_column(String, nullable=False)
    domain: Mapped[str] = mapped_column(String, nullable=False)
    depth: Mapped[str] = mapped_column(String, default="standard")
    scope: Mapped[str] = mapped_column(Text, default="[]")          # JSON list
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|running|completed|failed
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    elapsed_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_counts: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    report_html_path: Mapped[str | None] = mapped_column(String, nullable=True)
    report_json_path: Mapped[str | None] = mapped_column(String, nullable=True)
    report_md_path: Mapped[str | None] = mapped_column(String, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="scan",
                                                    cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    cwe: Mapped[str | None] = mapped_column(String, nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="[]")  # JSON list

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")

    @property
    def references_list(self) -> list[str]:
        try:
            return json.loads(self.references)
        except Exception:
            return []
