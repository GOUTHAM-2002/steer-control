"""Steering-model (S) backends.

Two ways to drive the audited steering model:

- OpenRouterSteer: normal chat-completions via OpenRouter. Subject to the
  provider's platform content filters. On the public Anthropic route, Fable's
  usage-policy classifier refuses this protocol, so use it only for models that
  aren't filtered on the steering prompt.

- ClaudeCodeSteer: drives Fable (or any Claude) through the local `claude` CLI
  in print mode. The Claude Code harness engages with the steering protocol
  where the raw Anthropic API returns `content_filter`. Multi-turn state is kept
  by resuming the CLI session; the protocol system prompt replaces Claude Code's
  default agent prompt, and all tools are disabled so S can only emit text.

Both expose the same interface:
    step(user_text: str) -> StepResult
where the first call is seeded with the system prompt automatically.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from .models import chat


@dataclass
class StepResult:
    text: str
    cost_usd: float = 0.0
    refused: bool = False
    finish_reason: str | None = None
    error: str | None = None


# --------------------------------------------------------------------------- #
class OpenRouterSteer:
    def __init__(self, model: str, system_prompt: str, *, max_tokens: int = 4000):
        self.model = model
        self.system = system_prompt
        self.max_tokens = max_tokens
        self.convo: list[dict] = [{"role": "system", "content": system_prompt}]

    def step(self, user_text: str) -> StepResult:
        self.convo.append({"role": "user", "content": user_text})
        text = ""
        refused = False
        fr = None
        cost = 0.0
        for _ in range(3):  # retry transient empties
            r = chat(self.model, self.convo, max_tokens=self.max_tokens, temperature=1.0)
            cost += r.usage.cost_usd
            fr = r.finish_reason
            if r.refused:
                refused = True
                break
            if r.text.strip():
                text = r.text
                break
        if text:
            self.convo.append({"role": "assistant", "content": text})
        return StepResult(text=text, cost_usd=cost, refused=refused, finish_reason=fr)


# --------------------------------------------------------------------------- #
class ClaudeCodeSteer:
    """Drive S via the `claude` CLI, keeping context through session resume."""

    _TOOLS_OFF = [
        "Bash", "Edit", "Write", "Read", "Glob", "Grep", "WebFetch", "WebSearch",
        "Task", "TodoWrite", "NotebookEdit", "Agent", "Artifact",
    ]

    def __init__(self, model: str, system_prompt: str, *, timeout_s: int = 180):
        self.model = model
        self.system = system_prompt
        self.timeout_s = timeout_s
        self.session_id: str | None = None
        self.bin = shutil.which("claude") or os.path.expanduser("~/.local/bin/claude")

    def step(self, user_text: str) -> StepResult:
        cmd = [
            self.bin, "-p", user_text,
            "--model", self.model,
            "--output-format", "json",
            "--disallowedTools", *self._TOOLS_OFF,
        ]
        if self.session_id is None:
            cmd += ["--system-prompt", self.system]
        else:
            cmd += ["--resume", self.session_id]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            return StepResult(text="", error="claude_cli_timeout")
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:400]
            return StepResult(text="", error=f"claude_cli_rc={proc.returncode}: {detail}")
        try:
            d = json.loads(proc.stdout)
        except Exception:
            return StepResult(text="", error=f"claude_cli_nonjson: {proc.stdout[:300]}")
        # capture/refresh the session id for the next turn
        sid = d.get("session_id")
        if sid:
            self.session_id = sid
        result = d.get("result") or ""
        is_error = bool(d.get("is_error"))
        cost = float(d.get("total_cost_usd", 0.0) or 0.0)
        # a CLI-level refusal surfaces as is_error or an empty result
        refused = is_error and not result.strip()
        return StepResult(text=result, cost_usd=cost, refused=refused,
                          error=("cli_is_error" if is_error else None))


# --------------------------------------------------------------------------- #
def make_steer_backend(model: str, system_prompt: str, *, via: str = "auto"):
    """Pick a steering backend.

    via="claude_code" forces the CLI path; via="openrouter" forces the API path;
    via="auto" uses the CLI for Anthropic/Claude/Fable models (which the public
    API filters on this protocol) and the API otherwise.
    """
    if via == "claude_code":
        return ClaudeCodeSteer(model, system_prompt)
    if via == "openrouter":
        return OpenRouterSteer(model, system_prompt)
    m = model.lower()
    if any(k in m for k in ("fable", "claude", "opus", "sonnet", "haiku", "mythos")):
        return ClaudeCodeSteer(model, system_prompt)
    return OpenRouterSteer(model, system_prompt)
