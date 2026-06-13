# src/skill_auditor/models.py
"""Structured outputs: typed findings and the audit report (not free text)."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Source(str, Enum):
    STATIC = "static"
    LLM = "llm"


class Finding(BaseModel):
    rule_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1)
    file: str
    line: int | None = None
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    source: Source = Source.STATIC
    confidence: float = 1.0


class AuditReport(BaseModel):
    skill_name: str
    skill_path: str
    verdict: str  # block | warn | pass
    findings: list[Finding]
    counts: dict[str, int]
    llm_used: bool
    notes: list[str] = Field(default_factory=list)
