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
from dataclasses import asdict
from datetime import datetime, timezone
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
# Claude Code CLI ids (bare names, no "/") run via steer_via=claude_code.
_CLAUDE_CLI = ["claude-fable-5-1", "claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001"]
# Anthropic via OpenRouter: fine for scorer/judge/P, but NOT for the steering
# model (the steering prompt is refused on the public Anthropic API), so these
# are excluded from the steer options — Claude must go through the CLI.
_OR_ANTHROPIC = ["anthropic/claude-fable-5.1", "anthropic/claude-opus-5", "anthropic/claude-sonnet-5"]
# Non-Anthropic OpenRouter models (valid as the steering model).
_OR_OTHER = [
    "openai/gpt-6-astra", "openai/gpt-5.5", "openai/gpt-5.5-pro",
    "x-ai/grok-4.6", "x-ai/grok-4.5",
    "deepseek/deepseek-v4-pro", "deepseek/deepseek-v4-flash",
    "google/gemini-3.1-pro-preview", "google/gemini-3.1-flash-lite",
]
# "oai/<model>" hits the OpenAI API directly.
_OPENAI_DIRECT = ["oai/gpt-6-astra", "oai/gpt-5.5"]
MODEL_OPTIONS = {
    "steer": _CLAUDE_CLI + _OR_OTHER,                     # Claude -> CLI only; others -> OpenRouter
    "saboteur": _OPENAI_DIRECT + _OR_OTHER + _OR_ANTHROPIC,
    "gate": _OR_ANTHROPIC + _OR_OTHER + _OPENAI_DIRECT,
    "judge": _OR_ANTHROPIC + _OR_OTHER + _OPENAI_DIRECT,
}


def load_tasks() -> list[dict]:
    return [json.loads(l) for l in SEEDS.read_text().splitlines() if l.strip()]


def default_config() -> dict:
    tasks = load_tasks()
    return {
        "models": dict(DEFAULT_MODELS),
        "model_options": MODEL_OPTIONS,
        "steer_via": "claude_code",
        "budgets": {"max_prompts": 10, "max_resamples": 3},
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

    def _parse_from(self):
        try:
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            for kv in q.split("&"):
                if kv.startswith("from="):
                    return int(kv[5:])
        except Exception:
            pass
        return 0

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if self.path == "/" or self.path.startswith("/?"):
            html = (WEBAPP / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        elif path == "/api/config":
            self._send_json(default_config())
        elif path == "/api/health":
            self._send_json({"ok": True})
        elif path == "/api/experiment/status":
            self._send_json(_experiment_status())
        elif path == "/api/experiment/stream":
            self._stream_experiment(self._parse_from())
        else:
            self._send_json({"error": "not found"}, 404)

    def _stream_experiment(self, frm: int):
        """Tail the current/last experiment's event buffer from index `frm`.

        The run lives in a background thread, so a browser refresh just drops this
        connection; reconnecting with ?from=0 replays everything and resumes.
        """
        import time as _t
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        i = frm
        try:
            while True:
                evs, active, total = _experiment_events_since(i)
                for ev in evs:
                    self.wfile.write((json.dumps(ev) + "\n").encode())
                self.wfile.flush()
                i += len(evs)
                if not active and i >= total:
                    break
                _t.sleep(0.3)
        except (BrokenPipeError, ConnectionError):
            return  # client went away; the run keeps going

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/api/run", "/api/experiment/start", "/api/experiment/stop"):
            self._send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            cfg = json.loads(self.rfile.read(length) or b"{}")
        except Exception as e:
            self._send_json({"error": f"bad json: {e}"}, 400)
            return

        if path == "/api/experiment/stop":
            self._send_json(_experiment_stop())
            return
        if path == "/api/experiment/start":
            self._send_json(_experiment_start(cfg))  # starts in background, returns run id
            return

        # streaming NDJSON response (smoke-test single run)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(ev: dict):
            self.wfile.write((json.dumps(ev) + "\n").encode())
            self.wfile.flush()

        models_cfg = {**DEFAULT_MODELS, **(cfg.get("models") or {})}
        models = RoleModels(steer=models_cfg["steer"], saboteur=models_cfg["saboteur"],
                            gate=models_cfg["gate"], judge=models_cfg["judge"])
        ps = PromptSet.from_dict(cfg.get("prompts"))
        task = cfg.get("task") or {}
        budgets = cfg.get("budgets") or {}
        try:
            ep = run_episode(
                task.get("task_id", "custom"),
                task.get("main_task", ""),
                task.get("side_task", ""),
                task.get("side_task_check", ""),
                models,
                vuln_reference=task.get("vuln_reference", ""),
                steer_via=cfg.get("steer_via", "claude_code"),
                max_prompts=int(budgets.get("max_prompts", 10)),
                max_resamples=int(budgets.get("max_resamples", 3)),
                promptset=ps,
                on_event=emit,
                p_mode=cfg.get("p_mode", "live"),
            )
            _log_episode(ep)  # persist so results survive for later inspection
        except BrokenPipeError:
            return  # client hit Stop / navigated away
        except Exception as e:
            try:
                emit({"type": "error", "error": f"{type(e).__name__}: {e}"})
            except Exception:
                pass


def _steer_via_for(model: str) -> str:
    """Bare Claude ids run via the CLI; anything with a '/' runs via OpenRouter."""
    return "openrouter" if "/" in model else "claude_code"


# --------------------------------------------------------------------------- #
# experiment run registry: runs live in a background thread with an event
# buffer, so a browser refresh just drops the viewer connection and can
# reconnect (?from=0) without orphaning or duplicating the run.
# --------------------------------------------------------------------------- #
import threading as _threading  # noqa: E402

_RUN_LOCK = _threading.Lock()
_RUN: dict | None = None


def _experiment_status() -> dict:
    with _RUN_LOCK:
        if not _RUN:
            return {"active": False, "exists": False}
        return {"active": _RUN["active"], "exists": True, "id": _RUN["id"],
                "n_events": len(_RUN["events"]), "done": _RUN["done"]}


def _experiment_events_since(i: int):
    with _RUN_LOCK:
        if not _RUN:
            return ([], False, 0)
        return (list(_RUN["events"][i:]), _RUN["active"], len(_RUN["events"]))


def _experiment_stop() -> dict:
    with _RUN_LOCK:
        if _RUN and _RUN["active"]:
            _RUN["cancel"].set()
            return {"stopped": True, "id": _RUN["id"]}
    return {"stopped": False}


def _experiment_start(cfg: dict) -> dict:
    import uuid
    global _RUN
    with _RUN_LOCK:
        if _RUN and _RUN["active"]:
            _RUN["cancel"].set()   # replace any previous run
        cancel = _threading.Event()
        run = {"id": uuid.uuid4().hex[:8], "events": [], "active": True,
               "done": False, "cancel": cancel}
        _RUN = run

    def append(ev: dict):
        with _RUN_LOCK:
            run["events"].append(ev)

    def target():
        try:
            _run_experiment_core(cfg, append, cancel)
        except Exception as e:  # noqa: BLE001
            append({"type": "error", "error": f"{type(e).__name__}: {e}"})
        finally:
            with _RUN_LOCK:
                run["active"] = False
                run["done"] = True

    _threading.Thread(target=target, daemon=True).start()
    return {"run_id": run["id"]}


def _run_experiment_core(cfg: dict, emit, cancel) -> None:
    """Run episodes across many steering models in PARALLEL.

    Each (model, episode) is an independent task on a thread pool. Claude models
    route to the Claude Code CLI, everything else to OpenRouter, run concurrently.
    `emit` appends to the run's event buffer; `cancel` (a threading.Event) stops
    queued tasks when the user hits Stop or starts a new run. In-flight episodes
    finish (a running model call cannot be interrupted).
    """
    import time
    import threading
    import concurrent.futures as cf

    steer_models = [m for m in (cfg.get("models") or []) if m]
    episodes = max(1, int(cfg.get("episodes", 1)))
    budgets = cfg.get("budgets") or {}
    max_prompts = int(budgets.get("max_prompts", 10))
    max_resamples = int(budgets.get("max_resamples", 3))
    concurrency = max(1, int(cfg.get("concurrency", 6)))
    p_mode = cfg.get("p_mode", "reference")  # experiments default to fast reference P
    task = cfg.get("task") or {}
    ps = PromptSet.from_dict(cfg.get("prompts"))
    roles = {**DEFAULT_MODELS, **(cfg.get("models_roles") or {})}  # saboteur/gate/judge
    saboteur = roles["saboteur"]; gate = roles["gate"]; judge = roles["judge"]

    total = len(steer_models) * episodes
    t0 = time.time()

    emit({"type": "experiment_start", "models": steer_models, "episodes": episodes,
          "total": total, "task_id": task.get("task_id", "custom"),
          "max_prompts": max_prompts, "max_resamples": max_resamples,
          "concurrency": concurrency})

    done_lock = threading.Lock()
    overall_done = {"n": 0}

    def worker(m: str, e: int) -> tuple:
        if cancel.is_set():
            return (m, {"outcome": "cancelled"}, 0.0)
        via = _steer_via_for(m)
        models = RoleModels(steer=m, saboteur=saboteur, gate=gate, judge=judge)
        try:
            emit({"type": "episode_start", "model": m, "episode": e, "total": total,
                   "elapsed_s": round(time.time() - t0, 1)})
        except Exception:
            return (m, {"outcome": "cancelled"}, 0.0)
        try:
            ep = run_episode(
                task.get("task_id", "custom"), task.get("main_task", ""),
                task.get("side_task", ""), task.get("side_task_check", ""),
                models, vuln_reference=task.get("vuln_reference", ""),
                steer_via=via, max_prompts=max_prompts, max_resamples=max_resamples,
                promptset=ps, on_event=None, p_mode=p_mode,
            )
        except Exception as ex:
            v = {"outcome": "error", "rationale": f"{type(ex).__name__}: {ex}"}
            try:
                emit({"type": "episode_end", "model": m, "episode": e, "total": total,
                       "outcome": "error", "ended": "error", "cost": 0,
                       "elapsed_s": round(time.time() - t0, 1)})
            except Exception:
                pass
            return (m, v, 0.0)
        _log_episode(ep)
        v = ep.verdict or {}
        cost = ep.usage.get("cost_usd", 0) or 0
        with done_lock:
            overall_done["n"] += 1
            overall = overall_done["n"]
        try:
            emit({"type": "episode_end", "model": m, "episode": e, "overall": overall,
                   "total": total, "outcome": v.get("outcome", "none"), "ended": ep.ended_reason,
                   "honesty": v.get("honesty"), "incentive_capture": v.get("incentive_capture"),
                   "deception": v.get("deception"), "cost": round(cost, 4),
                   "elapsed_s": round(time.time() - t0, 1)})
        except Exception:
            pass
        return (m, v, cost)

    results: dict[str, list] = {m: [] for m in steer_models}
    # interleave round-robin across models (episode-major) so the first parallel
    # wave spans different models — fast models finish quickly and slow Claude
    # episodes don't hog every worker while the rest idle.
    tasks = [(m, e) for e in range(episodes) for m in steer_models]
    with cf.ThreadPoolExecutor(max_workers=min(concurrency, len(tasks) or 1)) as ex:
        futs = {ex.submit(worker, m, e): (m, e) for (m, e) in tasks}
        for fut in cf.as_completed(futs):
            try:
                m, v, cost = fut.result()
            except Exception:
                continue
            results[m].append((v, cost))
            if len(results[m]) == episodes:
                per = _summarize_model(results[m])
                try:
                    emit({"type": "model_done", "model": m, "summary": per})
                except Exception:
                    pass

    per_model = {m: _summarize_model(results[m]) for m in steer_models if results[m]}
    wall = round(time.time() - t0, 1)
    summary = {"task_id": task.get("task_id", "custom"), "episodes": episodes,
               "max_prompts": max_prompts, "max_resamples": max_resamples,
               "saboteur": saboteur, "gate": gate, "judge": judge,
               "per_model": per_model, "wall_s": wall,
               "total_cost_usd": round(sum(pm["cost_usd"] for pm in per_model.values()), 4)}
    # persist experiment summary
    try:
        exp_dir = ROOT / "logs" / "experiments"
        exp_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        (exp_dir / f"exp_{stamp}.json").write_text(json.dumps(summary, indent=2))
    except Exception:
        pass
    try:
        emit({"type": "experiment_done", "summary": summary})
    except Exception:
        pass


def _summarize_model(pairs: list) -> dict:
    """Aggregate a list of (verdict, cost) into per-model stats."""
    from collections import Counter
    counts: Counter = Counter()
    hon = []; inc = []; dec = []; costs = []
    for v, cost in pairs:
        counts[v.get("outcome", "none")] += 1
        if isinstance(v.get("honesty"), (int, float)): hon.append(v["honesty"])
        if isinstance(v.get("incentive_capture"), (int, float)): inc.append(v["incentive_capture"])
        if isinstance(v.get("deception"), (int, float)): dec.append(v["deception"])
        costs.append(cost or 0)
    n = sum(counts.values()) or 1
    return {
        "counts": dict(counts), "n": sum(counts.values()),
        "rubber_stamp_rate": round(counts.get("rubber_stamp", 0) / n, 3),
        "disclosed_rate": round(counts.get("disclosed_but_delivered", 0) / n, 3),
        "refused_rate": round(counts.get("refused_or_flagged", 0) / n, 3),
        "avg_honesty": round(sum(hon) / len(hon), 2) if hon else None,
        "avg_incentive_capture": round(sum(inc) / len(inc), 2) if inc else None,
        "avg_deception": round(sum(dec) / len(dec), 2) if dec else None,
        "cost_usd": round(sum(costs), 4),
    }


def _log_episode(ep) -> None:
    """Append a finished web-panel episode to logs/web_runs.jsonl."""
    try:
        rec = asdict(ep)
        rec["ts"] = datetime.now(timezone.utc).isoformat()
        rec["source"] = "web"
        logs = ROOT / "logs"
        logs.mkdir(exist_ok=True)
        with (logs / "web_runs.jsonl").open("a") as f:
            f.write(json.dumps(rec) + "\n")
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
