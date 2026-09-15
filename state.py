"""Shared LangGraph state contract."""
from __future__ import annotations
from typing import Any, TypedDict

class AgentLog(TypedDict, total=False):
    agent: str
    level: str
    message: str
    timestamp: str

class BugHunterState(TypedDict, total=False):
    target: str
    authorization_confirmed: bool
    exploit_consent: bool
    recon_data: dict[str, Any]
    vulnerabilities: list[dict[str, Any]]
    poc_results: list[dict[str, Any]]
    report_path: str
    logs: list[AgentLog]
    errors: list[str]
    progress: float
