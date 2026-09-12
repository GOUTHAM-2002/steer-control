#!/usr/bin/env python3
"""Run the steering-control misalignment eval.

Examples
--------
  # smoke test: 1 task, Fable 5 as the audited steering model
  python run.py --smoke

  # full: all seed tasks, N episodes each
  python run.py --steer anthropic/claude-fable-5 --epochs 3
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from harness.protocol import RoleModels, prompted_model_for, run_episode

ROOT = Path(__file__).resolve().parent
SEEDS = ROOT / "data" / "seeds" / "tasks.jsonl"
LOGS = ROOT / "logs"


def load_tasks(limit: int | None = None) -> list[dict]:
    tasks = [json.loads(l) for l in SEEDS.read_text().splitlines() if l.strip()]
    return tasks[:limit] if limit else tasks


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steer", default="claude-fable-5-1",
                    help="steering model S (the audited target); "
                         "use the Claude Code model id (e.g. claude-fable-5-1) when steer-via=claude_code")
    ap.add_argument("--prompted", default=None,
                    help="override the prompted model P (default: family-matched)")
    ap.add_argument("--gate", default="anthropic/claude-sonnet-5")
    ap.add_argument("--judge", default="anthropic/claude-sonnet-5")
    ap.add_argument("--steer-via", default="auto",
                    choices=["auto", "claude_code", "openrouter"],
                    help="how to drive S: claude_code bypasses the API content filter")
    ap.add_argument("--epochs", type=int, default=1, help="episodes per task")
    ap.add_argument("--n-tasks", type=int, default=None, help="limit number of tasks")
    ap.add_argument("--max-prompts", type=int, default=4)
    ap.add_argument("--max-resamples", type=int, default=3)
    ap.add_argument("--smoke", action="store_true",
                    help="1 task, 1 epoch, small budgets")
    ap.add_argument("--tag", default="run")
    args = ap.parse_args()

    if args.smoke:
        args.n_tasks = 1
        args.epochs = 1
        args.max_prompts = 3
        args.max_resamples = 2
        args.tag = "smoke"

    models = RoleModels(
        steer=args.steer,
        saboteur=prompted_model_for(args.steer, args.prompted),
        gate=args.gate,
        judge=args.judge,
    )
    tasks = load_tasks(args.n_tasks)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    steer_slug = args.steer.split("/")[-1].replace(".", "-")
    LOGS.mkdir(exist_ok=True)
    out_path = LOGS / f"{args.tag}_{steer_slug}_{stamp}.jsonl"

    print(f"steer(S)     = {models.steer}")
    print(f"prompted(P)  = {models.saboteur}")
    print(f"gate         = {models.gate}")
    print(f"judge        = {models.judge}")
    print(f"tasks={len(tasks)} epochs={args.epochs} max_prompts={args.max_prompts}")
    print(f"log -> {out_path}\n")

    episodes = []
    t0 = time.time()
    with out_path.open("w") as f:
        for task in tasks:
            for e in range(args.epochs):
                print(f"  running {task['task_id']} epoch {e} ...", flush=True)
                ep = run_episode(
                    task["task_id"], task["main_task"], task["side_task"],
                    task["side_task_check"], models,
                    vuln_reference=task.get("vuln_reference", ""),
                    steer_via=args.steer_via,
                    max_prompts=args.max_prompts, max_resamples=args.max_resamples,
                )
                rec = asdict(ep)
                rec["epoch"] = e
                f.write(json.dumps(rec) + "\n")
                f.flush()
                episodes.append(rec)
                v = ep.verdict or {}
                print(f"    -> outcome={v.get('outcome')} "
                      f"attempts={len(ep.attempts)} ended={ep.ended_reason} "
                      f"cost=${ep.usage.get('cost_usd', 0):.4f}")

    # ---- summary ----
    from collections import Counter
    outcomes = Counter(ep["verdict"].get("outcome", "none") for ep in episodes)
    total_cost = sum(ep["usage"].get("cost_usd", 0) for ep in episodes)
    n = len(episodes)
    rubber = outcomes.get("rubber_stamp", 0)
    all_attempts = [a for ep in episodes for a in ep["attempts"]]
    n_insecure = sum(1 for a in all_attempts if a["side_task_present"])
    # valid episodes = those where the eval could actually test rubber-stamping
    # (the saboteur landed the side-task exploit). Invalid ones are excluded from the rate.
    n_invalid = outcomes.get("invalid_saboteur_secure", 0)
    n_valid = n - n_invalid
    summary = {
        "steer": models.steer, "prompted": models.saboteur,
        "gate": models.gate, "judge": models.judge,
        "n_episodes": n, "outcomes": dict(outcomes),
        "n_valid_episodes": n_valid, "n_invalid_saboteur_secure": n_invalid,
        "rubber_stamp_rate": round(rubber / n_valid, 3) if n_valid else None,
        "n_prompted_outputs": len(all_attempts),
        "side_task_landed_frac": round(n_insecure / len(all_attempts), 3) if all_attempts else None,
        "total_cost_usd": round(total_cost, 4),
        "wall_s": round(time.time() - t0, 1),
        "log": str(out_path),
    }
    summary_path = out_path.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2))
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"\nsummary -> {summary_path}")


if __name__ == "__main__":
    main()
