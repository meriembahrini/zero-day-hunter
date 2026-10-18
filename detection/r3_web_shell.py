import json
import sys
from pathlib import Path

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r4_raw.jsonl"
)

OUTPUT_FILE = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else Path.home() / "zero-day-hunter/data/scenarios/r3_results.jsonl"
)

SHELLS = {"sh", "bash", "dash"}
SERVER_SCRIPT = "r4_web_server.py"

normal_count = 0
alert_count = 0
seen = set()

with INPUT_FILE.open(encoding="utf-8") as source, \
     OUTPUT_FILE.open("w", encoding="utf-8") as output:

    for line in source:
        if not line.strip():
            continue

        event = json.loads(line)
        details = event.get("process_exec")

        if not details:
            continue

        process = details.get("process") or {}
        parent = details.get("parent") or {}

        binary = process.get("binary", "")
        parent_binary = parent.get("binary", "")
        parent_args = parent.get("arguments", "")

        # Identifier notre serveur Python de laboratoire
        if (
            Path(parent_binary).name not in {"python3", "python3.12"}
            or SERVER_SCRIPT not in parent_args
        ):
            continue

        exec_id = process.get("exec_id")
        if exec_id and exec_id in seen:
            continue
        if exec_id:
            seen.add(exec_id)

        if Path(binary).name in SHELLS:
            status = "ALERT"
            severity = "HIGH"
            reason = "Shell lance par le serveur web"
            alert_count += 1
        else:
            status = "NORMAL"
            severity = "INFO"
            reason = "Processus enfant non shell"
            normal_count += 1

        result = {
            "rule_id": "R3",
            "time": event.get("time"),
            "status": status,
            "severity": severity,
            "reason": reason,
            "pid": process.get("pid"),
            "exec_id": exec_id,
            "binary": binary,
            "parent_binary": parent_binary,
            "parent_arguments": parent_args
        }

        output.write(json.dumps(result, ensure_ascii=False) + "\n")

        print(
            f"[{status} R3] "
            f"Programme={binary} "
            f"Parent={parent_binary}"
        )

print("\n===== BILAN R3 =====")
print(f"Normaux : {normal_count}")
print(f"Alertes : {alert_count}")
print(f"Resultats : {OUTPUT_FILE}")
