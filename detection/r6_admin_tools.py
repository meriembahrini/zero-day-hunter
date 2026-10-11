import json
import sys
from pathlib import Path

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r6_raw.jsonl"
)

OUTPUT_FILE = PROJECT / "data/scenarios/r6_results.jsonl"

ADMIN_TOOLS = {
    "sudo", "su", "chmod", "chown",
    "useradd", "usermod", "passwd"
}

LAB_DIR = str(PROJECT / "lab") + "/"

# Mémoriser les exécutions déjà traitées
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
        binary = process.get("binary", "")
        tool = Path(binary).name

        if tool not in ADMIN_TOOLS:
            continue

        exec_id = process.get("exec_id")
        if exec_id and exec_id in seen:
            continue
        if exec_id:
            seen.add(exec_id)

        pid = process.get("pid")
        uid = process.get("uid")
        arguments = process.get("arguments", "")
        parent = details.get("parent", {})
        parent_binary = parent.get("binary", "")

        # Politique de laboratoire :
        # chmod et chown sont autorisés uniquement
        # lorsque le chemin lab/ apparaît dans les arguments.
        lab_operation = (
            tool in {"chmod", "chown"}
            and LAB_DIR in arguments
        )

        if lab_operation:
            status = "NORMAL"
            severity = "INFO"
            reason = "Operation administrative dans le laboratoire"
            normal_count += 1
        else:
            status = "ALERT"
            severity = "MEDIUM"
            reason = "Outil administratif hors contexte autorise"
            alert_count += 1

        result = {
            "rule_id": "R6",
            "time": event.get("time"),
            "status": status,
            "severity": severity,
            "reason": reason,
            "pid": pid,
            "uid": uid,
            "exec_id": exec_id,
            "binary": binary,
            "arguments": arguments,
            "parent_binary": parent_binary
        }

        output.write(json.dumps(result, ensure_ascii=False) + "\n")

        print(
            f"[{status} R6] "
            f"PID={pid} UID={uid} "
            f"Outil={tool} "
            f"Raison={reason}"
        )

print("\n===== BILAN R6 =====")
print(f"Normaux : {normal_count}")
print(f"Alertes : {alert_count}")
print(f"Resultats : {OUTPUT_FILE}")
