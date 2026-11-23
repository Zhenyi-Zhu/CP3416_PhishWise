"""Evaluate message-level cue category sets; Python standard library only."""
from __future__ import annotations

import csv
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
CATEGORY_KEYS = ("urgency", "authority", "threat", "reward")


def source_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def divide(top: int, bottom: int):
    return top / bottom if bottom else None


def metrics(rows: list[dict]) -> dict:
    per_category = {}
    for category in CATEGORY_KEYS:
        tp = fp = fn = tn = 0
        for row in rows:
            expected = category in row["expected"]
            predicted = category in row["predicted"]
            if expected and predicted:
                tp += 1
            elif predicted:
                fp += 1
            elif expected:
                fn += 1
            else:
                tn += 1
        per_category[category] = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                                  "precision": divide(tp, tp + fp), "recall": divide(tp, tp + fn),
                                  "f1": divide(2 * tp, 2 * tp + fp + fn)}
    micro = {key: sum(item[key] for item in per_category.values()) for key in ("tp", "fp", "fn", "tn")}
    tp, fp, fn = micro["tp"], micro["fp"], micro["fn"]
    micro.update(precision=divide(tp, tp + fp), recall=divide(tp, tp + fn), f1=divide(2 * tp, 2 * tp + fp + fn))
    exact = sum(set(row["expected"]) == set(row["predicted"]) for row in rows)
    return {"messages": len(rows), "category_decisions": len(rows) * 4,
            "exact_sets": exact, "exact_set_agreement": divide(exact, len(rows)),
            "per_category": per_category, "micro": micro}


def validate_dataset(dataset: dict):
    cases = dataset["cases"]
    if not cases:
        raise ValueError("The dataset has no cases.")
    ids = set()
    for case in cases:
        if case["id"] in ids:
            raise ValueError("Duplicate case ID: " + case["id"])
        ids.add(case["id"])
        labels = case["expected"]
        if len(labels) != len(set(labels)) or not set(labels).issubset(CATEGORY_KEYS):
            raise ValueError("Invalid reference labels: " + case["id"])
        if not isinstance(case["text"], str) or not case["text"].strip():
            raise ValueError("Empty message: " + case["id"])
        if set(case["evidence"]) != set(labels):
            raise ValueError("Reference evidence and labels differ: " + case["id"])
        for excerpt in case["evidence"].values():
            if excerpt not in case["text"]:
                raise ValueError("Reference excerpt missing from message: " + case["id"])
        if not case["rationale"].strip():
            raise ValueError("Missing rationale: " + case["id"])


def fmt(value) -> str:
    return "N/A" if value is None else f"{value:.1%}"


def summary_text(report: dict) -> str:
    score = report["metrics"]
    lines = ["PhishWise additional cue evaluation", "",
             f"Run time (UTC): {report['run_time_utc']}", f"Platform: {report['platform']}",
             f"Python: {report['python']}", f"Analyzer version: {report['analyzer_version']}",
             f"Dataset: {report['dataset_id']}", "",
             "Task: message-level cue category coverage (not phishing classification)",
             f"Messages: {score['messages']} | Category decisions: {score['category_decisions']}",
             f"Exact category sets: {score['exact_sets']}/{score['messages']} ({fmt(score['exact_set_agreement'])})",
             f"Micro precision: {fmt(score['micro']['precision'])}",
             f"Micro recall: {fmt(score['micro']['recall'])}",
             f"Micro F1: {fmt(score['micro']['f1'])}", "",
             "Category       TP  FP  FN  TN    Precision   Recall      F1"]
    for key, m in score["per_category"].items():
        lines.append(f"{key:<14} {m['tp']:>2}  {m['fp']:>2}  {m['fn']:>2}  {m['tn']:>2}    {fmt(m['precision']):>8} {fmt(m['recall']):>8} {fmt(m['f1']):>8}")
    lines.extend(["", "Exact category sets by group:"])
    for key, m in report["groups"].items():
        lines.append(f"  {key}: {m['exact_sets']}/{m['messages']}")
    lines.extend(["", "Mismatches:"])
    mismatches = [r for r in report["rows"] if r["missing"] or r["extra"]]
    for row in mismatches:
        lines.append(f"  {row['id']}: missing={','.join(row['missing']) or '-'}; extra={','.join(row['extra']) or '-'}")
    if not mismatches:
        lines.append("  None in this sample set.")
    lines.extend(["", f"Sample origin: {report['provenance']}",
                  f"Reference labels: {report['reference_status']}",
                  "These scores describe this selected set only; they are not real-world accuracy estimates.",
                  "Analyzer SHA-256 (normalized newlines): " + report["analyzer_sha256"],
                  "Dataset SHA-256: " + report["dataset_sha256"],
                  "Runner SHA-256: " + report["runner_sha256"]])
    return "\n".join(lines) + "\n"


def main() -> int:
    dataset_path = BASE / "evaluation" / "cases.json"
    analyzer_path = BASE / "analyzer.py"
    try:
        raw = dataset_path.read_bytes()
        dataset = json.loads(raw.decode("utf-8-sig"))
        validate_dataset(dataset)
        actual_hash = source_hash(analyzer_path)
        if actual_hash != dataset["baseline_analyzer_sha256"]:
            raise ValueError("analyzer.py differs from the frozen v0.1.0 baseline. Keep this run separate; do not change the stored hash to hide a rule change.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Evaluation could not start:", error, file=sys.stderr)
        return 1

    import analyzer
    if Path(analyzer.__file__).resolve() != analyzer_path.resolve():
        print("Wrong analyzer module was imported.", file=sys.stderr)
        return 1
    rows = []
    for case in dataset["cases"]:
        result = analyzer.analyze(case["text"])
        expected = set(case["expected"])
        predicted = {key for key in CATEGORY_KEYS if result["counts"][key] > 0}
        rows.append({**case, "predicted": sorted(predicted), "missing": sorted(expected - predicted),
                     "extra": sorted(predicted - expected), "exact_set": expected == predicted,
                     "counts": result["counts"], "findings": result["findings"]})
    report = {
        "run_time_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
        "python": sys.version, "analyzer_version": analyzer.VERSION,
        "analyzer_sha256": actual_hash, "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "runner_sha256": source_hash(Path(__file__)), "dataset_id": dataset["dataset_id"],
        "provenance": dataset["provenance"], "reference_status": dataset["reference_status"],
        "metrics": metrics(rows), "groups": {group: metrics([r for r in rows if r["group"] == group])
                                              for group in dict.fromkeys(r["group"] for r in rows)},
        "rows": rows,
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = BASE / "evidence" / f"evaluation_{platform.system().lower()}_{stamp}"
    try:
        output.mkdir(parents=True, exist_ok=False)
        (output / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        with (output / "results.csv").open("w", newline="", encoding="utf-8-sig") as file:
            fields = ["id", "group", "expected", "predicted", "missing", "extra", "exact_set", "text", "rationale"]
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                flat = {key: row[key] for key in fields}
                for key in ("expected", "predicted", "missing", "extra"):
                    flat[key] = ";".join(sorted(flat[key]))
                writer.writerow(flat)
        summary = summary_text(report)
        (output / "summary.txt").write_text(summary, encoding="utf-8")
    except OSError as error:
        print("Could not save all evaluation files:", error, file=sys.stderr)
        return 1
    print(summary)
    print("Saved results:", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
