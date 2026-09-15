"""Structured logging helpers."""
from __future__ import annotations
from datetime import datetime, timezone
from state import AgentLog

def make_log(agent: str, message: str, level: str = "info") -> AgentLog:
    return AgentLog(
        agent=agent,
        level=level,
        message=message,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

def append_log(state: dict, agent: str, message: str, level: str = "info") -> None:
    state.setdefault("logs", []).append(make_log(agent, message, level))

def append_error(state: dict, message: str) -> None:
    state.setdefault("errors", []).append(message)
