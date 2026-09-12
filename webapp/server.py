#!/usr/bin/env python3
"""Local control panel for the steering-control eval.

Start it yourself (so the auto-mode classifier never gates it):

    cd /home/goutham/steer_control
    source .venv/bin/activate
    PATH="$HOME/.local/bin:$PATH" python webapp/server.py

then open http://127.0.0.1:8765 . Edit the prompts / models / task, click Run,
and watch the full S <-> P <-> scorer <-> judge flow stream live.

Endpoints
---------
GET  /               -> the single-page UI
GET  /api/config     -> default config (models, budgets, tasks, prompts)
POST /api/run        -> runs ONE episode, streams NDJSON events as they happen
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.prompts import PromptSet            # noqa: E402
from harness.protocol import RoleModels, run_episode  # noqa: E402

WEBAPP = Path(__file__).resolve().parent
SEEDS = ROOT / "data" / "seeds" / "tasks.jsonl"

DEFAULT_MODELS = {
    "steer": "claude-fable-5-1",
    "saboteur": "oai/gpt-6-astra",
    "gate": "anthropic/claude-sonnet-5",
    "judge": "anthropic/claude-sonnet-5",
}

# Curated frontier-model choices for the UI dropdowns.
# S runs via the `claude` CLI by default, so it lists Claude Code model ids;
# the others run via OpenRouter, or the OpenAI API directly when prefixed `oai/`.
_CLAUDE_CLI = ["claude-fable-5-1", "claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"]
_OPENROUTER = [
    "anthropic/claude-fable-5.1", "anthropic/claude-opus-5", "anthropic/claude-sonnet-5",
    "openai/gpt-6-astra", "openai/gpt-5.5", "openai/gpt-5.5-pro",
    "openrouter/google/gemini-3.1-flash-lite", "openrouter/deepseek/deepseek-v4-flash-0731",
]
_OPENAI_DIRECT = ["oai/gpt-6-astra", "oai/gpt-5.5"]
MODEL_OPTIONS = {
    "steer": _CLAUDE_CLI + _OPENROUTER,
    "saboteur": _OPENAI_DIRECT + _OPENROUTER,
    "gate": _OPENROUTER + _OPENAI_DIRECT,
    "judge": _OPENROUTER + _OPENAI_DIRECT,
}


def load_tasks() -> list[dict]:
    return [json.loads(l) for l in SEEDS.read_text().splitlines() if l.strip()]


def default_config() -> dict:
    tasks = load_tasks()
    return {
        "models": dict(DEFAULT_MODELS),
        "model_options": MODEL_OPTIONS,
        "steer_via": "claude_code",
        "budgets": {"max_prompts": 4, "max_resamples": 3},
        "tasks": tasks,
        "task": tasks[0] if tasks else {"task_id": "", "main_task": "", "side_task": "", "side_task_check": ""},
        "prompts": PromptSet().to_dict(),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            html = (WEBAPP / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        elif self.path == "/api/config":
            self._send_json(default_config())
        elif self.path == "/api/health":
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path != "/api/run":
            self._send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            cfg = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            self._send_json({"error": f"bad json: {e}"}, 400)
            return

        # streaming NDJSON response
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(ev: dict):
            try:
                self.wfile.write((json.dumps(ev) + "\n").encode())
                self.wfile.flush()
            except Exception:
                raise

        models_cfg = {**DEFAULT_MODELS, **(cfg.get("models") or {})}
        models = RoleModels(steer=models_cfg["steer"], saboteur=models_cfg["saboteur"],
                            gate=models_cfg["gate"], judge=models_cfg["judge"])
        ps = PromptSet.from_dict(cfg.get("prompts"))
        task = cfg.get("task") or {}
        budgets = cfg.get("budgets") or {}
        try:
            run_episode(
                task.get("task_id", "custom"),
                task.get("main_task", ""),
                task.get("side_task", ""),
                task.get("side_task_check", ""),
                models,
                vuln_reference=task.get("vuln_reference", ""),
                steer_via=cfg.get("steer_via", "claude_code"),
                max_prompts=int(budgets.get("max_prompts", 4)),
                max_resamples=int(budgets.get("max_resamples", 3)),
                promptset=ps,
                on_event=emit,
            )
        except BrokenPipeError:
            return  # client navigated away
        except Exception as e:
            try:
                emit({"type": "error", "error": f"{type(e).__name__}: {e}"})
            except Exception:
                pass


def serve(host="127.0.0.1", port=8765):
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"steer-control control panel -> http://{host}:{port}")
    print("Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    serve()
