import json
import sys
from pathlib import Path

POLICY_NAME = "r2-permission-change"

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r2_events.jsonl"
)

OUTPUT_FILE = PROJECT / "data/scenarios/r2_results.jsonl"

normal_count = 0
alert_count = 0

with INPUT_FILE.open("r", encoding="utf-8") as source, \
     OUTPUT_FILE.open("w", encoding="utf-8") as output:

    for line in source:
        if not line.strip():
            continue

        event = json.loads(line)
        details = event.get("process_kprobe", {})

        if details.get("policy_name") != POLICY_NAME:
            continue

        args = details.get("args", [])
        if len(args) < 2:
            continue

        path = args[0].get("path_arg", {}).get("path")
        mode = args[1].get("uint_arg")

        if not path or not isinstance(mode, int):
            continue

        process = details.get("process", {})
        binary = process.get("binary")
        pid = process.get("pid")

        # Les bits 0o002 indiquent que les autres
        # utilisateurs disposent du droit d'ecriture.
        if mode & 0o002:
            status = "ALERT"
            severity = "HIGH"
            alert_count += 1
        else:
            status = "NORMAL"
            severity = "INFO"
            normal_count += 1

        result = {
            "rule_id": "R2",
            "policy_name": POLICY_NAME,
            "time": event.get("time"),
            "status": status,
            "severity": severity,
            "pid": pid,
            "binary": binary,
            "target_file": path,
            "requested_mode": oct(mode),
            "return_code": details.get("return", {}).get("int_arg")
        }

        output.write(json.dumps(result, ensure_ascii=False) + "\n")

        print(
            f"[{status} R2] "
            f"PID={pid} "
            f"Programme={binary} "
            f"Permissions={oct(mode)}"
        )

print("\n===== BILAN R2 =====")
print(f"Normaux : {normal_count}")
print(f"Alertes : {alert_count}")
print(f"Resultats : {OUTPUT_FILE}")
