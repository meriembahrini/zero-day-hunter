import json
import sys
from pathlib import Path

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r9_raw.jsonl"
)

OUTPUT_FILE = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else Path.home() / "zero-day-hunter/data/scenarios/r6_results.jsonl"
)

POLICY_NAME = "r6-tcp-connect"
TARGET_IP = "127.0.0.1"
ALLOWED_PORT = 8081
TEST_PORTS = {8081, 9090}

normal_count = 0
alert_count = 0
seen = set()

with INPUT_FILE.open(encoding="utf-8") as source, \
     OUTPUT_FILE.open("w", encoding="utf-8") as output:

    for line in source:
        if not line.strip():
            continue

        event = json.loads(line)
        details = event.get("process_kprobe", {})

        if details.get("policy_name") != POLICY_NAME:
            continue

        if details.get("function_name") != "tcp_connect":
            continue

        process = details.get("process", {})
        args = details.get("args", [])

        if not args:
            continue

        sock = args[0].get("sock_arg", {})

        if not sock:
            continue

        destination = sock.get("daddr")
        port = sock.get("dport")

        try:
            port = int(port)
        except (ValueError, TypeError):
            continue

        # Conserver uniquement nos connexions de laboratoire
        if destination != TARGET_IP or port not in TEST_PORTS:
            continue

        exec_id = process.get("exec_id")
        key = (exec_id, destination, port)

        if key in seen:
            continue
        seen.add(key)

        if port == ALLOWED_PORT:
            status = "NORMAL"
            severity = "INFO"
            normal_count += 1
        else:
            status = "ALERT"
            severity = "HIGH"
            alert_count += 1

        result = {
            "rule_id": "R6",
            "time": event.get("time"),
            "status": status,
            "severity": severity,
            "pid": process.get("pid"),
            "exec_id": exec_id,
            "binary": process.get("binary"),
            "destination_ip": destination,
            "destination_port": port,
            "reason": "Destination TCP inattendue" if status == "ALERT"
                      else "Destination TCP autorisee"
        }

        output.write(json.dumps(result, ensure_ascii=False) + "\n")

        print(
            f"[{status} R6] "
            f"Programme={process.get('binary')} "
            f"Destination={destination}:{port}"
        )

print("\n===== BILAN R6 =====")
print(f"Normaux : {normal_count}")
print(f"Alertes : {alert_count}")
print(f"Resultats : {OUTPUT_FILE}")
