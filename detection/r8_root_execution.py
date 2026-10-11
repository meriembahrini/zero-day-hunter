import json
import sys
from pathlib import Path

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r8_raw.jsonl"
)

OUTPUT_FILE = PROJECT / "data/scenarios/r8_results.jsonl"

ALLOWED_ROOT_BINARIES = {
    "/usr/bin/id",
    "/usr/bin/whoami"
}

seen = set()
normal_count = 0
alert_count = 0

with INPUT_FILE.open("r", encoding="utf-8") as source, \
     OUTPUT_FILE.open("w", encoding="utf-8") as output:

    for line in source:
        if not line.strip():
            continue

        event = json.loads(line)
        details = event.get("process_exec")

        if not details:
            continue

        process = details.get("process", {})

        uid = process.get("uid")
        if uid != 0:
            continue

        binary = process.get("binary", "")
        pid = process.get("pid")
        exec_id = process.get("exec_id")

        if exec_id and exec_id in seen:
            continue

        if exec_id:
            seen.add(exec_id)

        # Politique de laboratoire
        if binary in ALLOWED_ROOT_BINARIES:
            status = "NORMAL"
            severity = "INFO"
            reason = "Programme root autorise"
            normal_count += 1
        else:
            status = "ALERT"
            severity = "MEDIUM"
            reason = "Programme root non autorise"
            alert_count += 1

        result = {
            "rule_id": "R8",
            "time": event.get("time"),
            "status": status,
            "severity": severity,
            "reason": reason,
            "pid": pid,
            "uid": uid,
            "exec_id": exec_id,
            "binary": binary,
            "arguments": process.get("arguments", ""),
            "parent_binary": details.get("parent", {}).get("binary", "")
        }

        output.write(json.dumps(result, ensure_ascii=False) + "\n")

        print(
            f"[{status} R8] "
            f"PID={pid} UID={uid} "
            f"Programme={binary}"
        )

print("\n===== BILAN R8 =====")
print(f"Normaux : {normal_count}")
print(f"Alertes : {alert_count}")
print(f"Resultats : {OUTPUT_FILE}")
