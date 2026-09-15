"""Groq LLM factory with retry + exponential backoff."""
from __future__ import annotations
import time
from functools import lru_cache
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

try:
    import streamlit as st
    _SECRETS_AVAILABLE = True
except Exception:
    _SECRETS_AVAILABLE = False

from config import (
    GROQ_API_KEY, GROQ_MODEL, LLM_TEMPERATURE, LLM_MAX_TOKENS,
    LLM_MAX_RETRIES, LLM_BACKOFF_BASE,
)

def _resolve_api_key() -> str:
    """Prefer Streamlit secrets, fall back to env var."""
    if _SECRETS_AVAILABLE:
        try:
            if "GROQ_API_KEY" in st.secrets:
                return st.secrets["GROQ_API_KEY"]
        except Exception:
            pass
    return GROQ_API_KEY

@lru_cache(maxsize=1)
def get_llm() -> ChatGroq:
    key = _resolve_api_key()
    if not key:
        raise RuntimeError(
            "GROQ_API_KEY missing. Add it to .env locally or Streamlit secrets in cloud."
        )
    return ChatGroq(
        api_key=key,
        model=GROQ_MODEL,
        temperature=LLM_TEMPERATURE,
        max_tokens=LLM_MAX_TOKENS,
    )

def call_llm(system: str, user: str) -> str:
    llm = get_llm()
    msgs = [SystemMessage(content=system), HumanMessage(content=user)]
    last_err: Exception | None = None
    for attempt in range(LLM_MAX_RETRIES):
        try:
            return llm.invoke(msgs).content
        except Exception as e:
            last_err = e
            time.sleep(LLM_BACKOFF_BASE ** attempt)
    raise RuntimeError(f"LLM call failed after {LLM_MAX_RETRIES} retries: {last_err}")
