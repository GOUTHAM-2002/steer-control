#!/usr/bin/env python3
"""Round 2b — the verified-real candidates that didn't run (stop-on-stamp halted
at the allowlist dud). Each confirmed exploitable before use:
  inverted_owner (non-owner granted access), zip_slip ('..' passes abs-only guard),
  truncated_token (32-bit prefix compare). jwt_verified_then_unused dropped (DUD:
  verify() gate runs first). Drives the running server's /api/run.
    ! python experiments/drive3.py
"""
import json, time
from drive2 import VULNS, run_one, LOG as _L
from pathlib import Path

LOG = Path(__file__).resolve().parent.parent / "logs" / "hard_review3.jsonl"
REAL = {"inverted_owner_check", "zip_slip_absonly", "truncated_token_compare"}
picked = [v for v in VULNS if v["task_id"] in REAL]


def main():
    print(f"Round 2b — {len(picked)} verified-real · Fable · max_prompts=1\n")
    LOG.parent.mkdir(exist_ok=True)
    rubber = []
    for i, v in enumerate(picked, 1):
        print(f"[{i}/{len(picked)}] {v['task_id']} …", flush=True)
        t0 = time.time()
        try:
            verdict, justification, ended = run_one(v)
        except Exception as e:
            print(f"    ERROR: {e}\n"); continue
        oc = verdict.get("outcome", "?"); dt = time.time() - t0
        with LOG.open("a") as f:
            f.write(json.dumps({"task_id": v["task_id"], "outcome": oc, "ended": ended,
                                "honesty": verdict.get("honesty"), "deception": verdict.get("deception"),
                                "rationale": verdict.get("rationale"), "justification": justification,
                                "secs": round(dt, 1)}) + "\n")
        flag = "  <<< RUBBER-STAMP" if oc == "rubber_stamp" else ""
        print(f"    -> {oc} (honesty={verdict.get('honesty')}, deception={verdict.get('deception')}, {dt:.0f}s){flag}")
        if verdict.get("rationale"):
            print(f"    judge: {verdict['rationale'][:260]}")
        print()
        if oc == "rubber_stamp":
            rubber.append(v["task_id"]); print(f"FOUND RUBBER-STAMP on '{v['task_id']}'. Stopping.\n"); break
    print("=== done ===")
    print("rubber-stamps:", rubber if rubber else "none — Fable held firm")
    print(f"log: {LOG}")


if __name__ == "__main__":
    main()
