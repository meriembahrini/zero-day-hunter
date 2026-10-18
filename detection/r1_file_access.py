import json
import sys
from pathlib import Path

# Configuration de R1
POLICY_NAME = "r1-sensitive-file-access"
SENSITIVE_FILE = str(Path.home() / "zero-day-hunter/lab/secrets.txt")

AUTHORIZED_PROGRAMS = {
    "/usr/bin/python3"
}

# Fichier d'entree : celui indique dans la commande,
# sinon notre capture initiale
EVENTS_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path.home() / "zero-day-hunter/data/scenarios/r1_file_access_filtered.jsonl"
)

# Fichier de sortie
OUTPUT_FILE = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else Path.home() / "zero-day-hunter/data/scenarios/r1_results.jsonl"
)

already_seen = set()
alerts_count = 0
normal_count = 0

with EVENTS_FILE.open("r", encoding="utf-8") as source:
    with OUTPUT_FILE.open("w", encoding="utf-8") as output:

        for line in source:
            if not line.strip():
                continue

            event = json.loads(line)

            details = event.get("process_kprobe")
            if not details:
                continue

            if details.get("policy_name") != POLICY_NAME:
                continue

            args = details.get("args", [])
            if not args:
                continue

            target_file = args[0].get("file_arg", {}).get("path")
            if target_file != SENSITIVE_FILE:
                continue

            process = details.get("process", {})
            binary = process.get("binary", "unknown")
            pid = process.get("pid")
            exec_id = process.get("exec_id")

            # Eviter les doublons pour une meme execution
            if exec_id and exec_id in already_seen:
                continue

            if exec_id:
                already_seen.add(exec_id)

            # Decision de notre moteur
            if binary in AUTHORIZED_PROGRAMS:
                status = "NORMAL"
                severity = "INFO"
                normal_count += 1
            else:
                status = "ALERT"
                severity = "HIGH"
                alerts_count += 1

            # Construire une decision structuree
            result = {
                "rule_id": "R1",
                "policy_name": POLICY_NAME,
                "time": event.get("time"),
                "status": status,
                "severity": severity,
                "pid": pid,
                "exec_id": exec_id,
                "binary": binary,
                "target_file": target_file
            }

            # Affichage dans le terminal
            print(
                f"[{status} R1] PID={pid} "
                f"Programme={binary}"
            )

            # Enregistrement JSONL
            output.write(json.dumps(result, ensure_ascii=False) + "\n")

print("\n===== BILAN R1 =====")
print(f"Acces normaux : {normal_count}")
print(f"Alertes : {alerts_count}")
print(f"Resultats enregistres dans : {OUTPUT_FILE}")
