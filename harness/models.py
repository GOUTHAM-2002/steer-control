"""Thin chat client with retry/backoff, routing to OpenRouter or OpenAI.

Most roles (P/gate/judge, and S when not via Claude Code) go through OpenRouter.
A model id prefixed ``oai/`` is routed to the OpenAI API directly (using
OPENAI_API_KEY); this is used for the saboteur P = ``oai/gpt-6-astra``. OpenAI
reasoning models require ``max_completion_tokens`` (not ``max_tokens``) and reject
a non-default temperature, so those are handled per-provider.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

_ENV = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(_ENV)

_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
_OPENAI_BASE = "https://api.openai.com/v1"
_OAI_PREFIX = "oai/"


def _resolve(model: str) -> tuple[str, str]:
    """Return (provider, model_id). ``oai/<m>`` -> OpenAI direct."""
    if model.startswith(_OAI_PREFIX):
        return "openai", model[len(_OAI_PREFIX):]
    return "openrouter", model


def _client(provider: str) -> OpenAI:
    if provider == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise RuntimeError(f"OPENAI_API_KEY not found (looked in {_ENV})")
        return OpenAI(base_url=_OPENAI_BASE, api_key=key)
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key:
        raise RuntimeError(f"OPENROUTER_API_KEY not found (looked in {_ENV})")
    return OpenAI(base_url=_OPENROUTER_BASE, api_key=key)


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    calls: int = 0

    def add(self, other: "Usage") -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.cost_usd += other.cost_usd
        self.calls += other.calls


@dataclass
class ChatResult:
    text: str
    usage: Usage = field(default_factory=Usage)
    raw: dict | None = None
    refused: bool = False
    finish_reason: str | None = None


def chat(
    model: str,
    messages: list[dict],
    *,
    max_tokens: int = 2048,
    temperature: float = 1.0,
    reasoning_effort: str | None = None,
    retries: int = 4,
) -> ChatResult:
    """One chat completion with exponential backoff on transient errors.

    `reasoning_effort` (low|medium|high) is forwarded to OpenRouter's unified
    reasoning control; use "low" for judge/gate/saboteur so reasoning tokens
    don't starve the visible completion (and to cut cost/latency).
    """
    provider, model_id = _resolve(model)
    client = _client(provider)
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            kwargs: dict = {"model": model_id, "messages": messages}
            if provider == "openai":
                # OpenAI reasoning models: max_completion_tokens, default temperature only
                kwargs["max_completion_tokens"] = max_tokens
                if reasoning_effort:
                    kwargs["reasoning_effort"] = reasoning_effort
            else:
                kwargs["max_tokens"] = max_tokens
                kwargs["temperature"] = temperature
                if reasoning_effort:
                    kwargs["extra_body"] = {"reasoning": {"effort": reasoning_effort}}
                kwargs["extra_headers"] = {
                    "HTTP-Referer": "https://alignment-eval.local/steer-control",
                    "X-Title": "steer-control-eval",
                }
            resp = client.chat.completions.create(**kwargs)
            choices = resp.choices or []
            if not choices:
                return ChatResult(text="", refused=True, finish_reason="no_choices",
                                  raw=resp.model_dump())
            choice = choices[0]
            msg = choice.message
            text = (getattr(msg, "content", None) or "") if msg else ""
            refusal = getattr(msg, "refusal", None) if msg else None
            fr = getattr(choice, "finish_reason", None)
            u = resp.usage
            usage = Usage(
                prompt_tokens=getattr(u, "prompt_tokens", 0) or 0 if u else 0,
                completion_tokens=getattr(u, "completion_tokens", 0) or 0 if u else 0,
                cost_usd=float(getattr(u, "cost", 0.0) or 0.0) if u else 0.0,
                calls=1,
            )
            return ChatResult(
                text=text, usage=usage, raw=resp.model_dump(),
                refused=bool(refusal) or fr == "content_filter",
                finish_reason=fr,
            )
        except Exception as e:  # noqa: BLE001 - broad retry is intentional
            last_err = e
            if attempt == retries - 1:
                break
            time.sleep(2.0 * (2**attempt))
    raise RuntimeError(f"chat failed for {model}: {last_err}")
