"""Runs the attack test-suite on plain RAG and on PromptShield, then writes results.md."""
import argparse
import json
from pathlib import Path

import config
import rag

config.CHROMA_PATH = "chroma_eval"       # keep test data away from the app's database
config.LOG_PATH = "logs/eval.jsonl"

DATA = Path("data")
CLEAN_DOC = DATA / "samples" / "leave_policy.txt"
TESTS = json.loads((DATA / "attacks" / "attacks.json").read_text(encoding="utf-8"))


def load(path):
    with open(path, "rb") as f:
        return rag.extract_text(f, str(path))


def rate(a, b):
    return round(100 * a / b) if b else 0


def run_suite(use_shield, deep):
    tag = "shield" if use_shield else "plain"
    print(f"\nRunning: {tag}")

    clean = f"clean_{tag}"
    rag.reset_collection(clean)
    stats = rag.ingest_text(load(CLEAN_DOC), CLEAN_DOC.name, clean, use_shield, deep)

    jobs = [(t, clean) for t in TESTS["direct"]]
    for t in TESTS["indirect"]:                      # attacks hidden inside documents
        col = f"{t['id'].lower()}_{tag}"
        rag.reset_collection(col)
        rag.ingest_text(load(t["file"]), t["file"], col, use_shield, deep)
        jobs.append((t, col))

    rows = []
    for t, col in jobs:
        res = rag.answer_question(t["prompt"], col, use_shield, deep)
        hit = t["marker"].lower() in res["answer"].lower()
        rows.append({"id": t["id"], "success": hit})
        print(f"  {t['id']:<4} {t['type']:<22} {'ATTACK SUCCEEDED' if hit else 'ok'}")

    false_alarms = sum(
        rag.answer_question(b["prompt"], clean, use_shield, deep)["blocked"]
        for b in TESTS["benign"]
    )
    return {
        "rows": rows,
        "succeeded": sum(r["success"] for r in rows),
        "false_alarms": false_alarms,
        "clean_quarantined": len(stats["quarantined"]),
        "clean_total": stats["total"],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-only", action="store_true", help="skip the LLM judge (faster)")
    deep = not parser.parse_args().rules_only

    missing = config.missing_models()
    if missing is None or missing:
        raise SystemExit(f"Ollama is unreachable or models are missing: {missing}")

    Path("logs").mkdir(exist_ok=True)
    Path(config.LOG_PATH).write_text("")

    plain = run_suite(False, deep)
    shielded = run_suite(True, deep)

    n, b = len(plain["rows"]), len(TESTS["benign"])
    table = [
        "| Setup | Attacks succeeded | Attack success rate | Normal questions blocked | Clean chunks quarantined |",
        "|---|---|---|---|---|",
        f"| Plain RAG | {plain['succeeded']} / {n} | {rate(plain['succeeded'], n)}% | 0 / {b} | 0 / {plain['clean_total']} |",
        f"| PromptShield | {shielded['succeeded']} / {n} | {rate(shielded['succeeded'], n)}% | "
        f"{shielded['false_alarms']} / {b} | {shielded['clean_quarantined']} / {shielded['clean_total']} |",
    ]
    Path("results.md").write_text("\n".join(table) + "\n", encoding="utf-8")
    print("\n" + "\n".join(table))

    missed = [r["id"] for r in shielded["rows"] if r["success"]]
    print("\nStill succeeded with the shield on:", ", ".join(missed) or "none")
    print("Saved results.md (paste the table into your README).")


if __name__ == "__main__":
    main()