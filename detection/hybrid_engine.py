
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_time(value):
    if not value:
        return None

    try:
        text = str(value)

        if "." in text:
            prefix, rest = text.split(".", 1)
            digits = "".join(
                c for c in rest if c.isdigit()
            )
            text = prefix + "." + digits[:6] + "+00:00"
        elif text.endswith("Z"):
            text = text[:-1] + "+00:00"

        return datetime.fromisoformat(text).astimezone(
            timezone.utc
        )
    except ValueError:
        return None


def load_rules(path):
    alerts = []

    with path.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            item = json.loads(line)

            if item.get("status") != "ALERT":
                continue

            timestamp = parse_time(item.get("time"))
            if timestamp is None:
                continue

            alerts.append({
                "timestamp": timestamp,
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity", "MEDIUM"),
                "reason": item.get("reason", ""),
                "details": item
            })

    return alerts


def load_predictions(path):
    predictions = []

    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            timestamp = parse_time(row.get("window_start"))

            if timestamp is None:
                continue

            predictions.append({
                "window_start": timestamp,
                "score": float(row["anomaly_score"]),
                "prediction": row["prediction"]
            })

    return predictions


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()

    rules = load_rules(args.rules)
    predictions = load_predictions(args.predictions)

    output = []

    for rule in rules:
        matching = None

        for pred in predictions:
            start = pred["window_start"]
            end = start.timestamp() + 30

            if start.timestamp() <= rule["timestamp"].timestamp() < end:
                matching = pred
                break

        severity = rule["severity"]
        ai_prediction = matching["prediction"] if matching else None
        ai_score = matching["score"] if matching else None

        if ai_prediction == "ANOMALY":
            priority = "CRITICAL"
        else:
            priority = severity

        output.append({
            "timestamp": rule["timestamp"].isoformat(),
            "rule_id": rule["rule_id"],
            "rule_severity": severity,
            "ai_prediction": ai_prediction,
            "ai_score": ai_score,
            "priority": priority,
            "reason": rule["reason"],
            "source": "HYBRID" if matching else "RULE_ONLY"
        })

    for pred in predictions:
        if pred["prediction"] != "ANOMALY":
            continue

        has_rule = any(
            pred["window_start"].timestamp()
            <= rule["timestamp"].timestamp()
            < pred["window_start"].timestamp() + 30
            for rule in rules
        )

        if not has_rule:
            output.append({
                "timestamp": pred["window_start"].isoformat(),
                "rule_id": None,
                "rule_severity": None,
                "ai_prediction": "ANOMALY",
                "ai_score": pred["score"],
                "priority": "MEDIUM",
                "reason": "Anomalie statistique detectee",
                "source": "AI_ONLY"
            })

    output.sort(key=lambda x: x["timestamp"])

    args.output.parent.mkdir(
        parents=True, exist_ok=True
    )

    with args.output.open("w", encoding="utf-8") as file:
        for alert in output:
            file.write(json.dumps(alert) + "\n")

    print("Alertes créées :", len(output))
    print("Résultat :", args.output)


if __name__ == "__main__":
    main()
