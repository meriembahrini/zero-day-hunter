import json
import sys
from pathlib import Path
from datetime import datetime

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r14_raw.jsonl"
)

OUTPUT_FILE = PROJECT / "data/scenarios/r14_results.jsonl"

SECRET = str(PROJECT / "lab/secrets.txt")
WINDOW_SECONDS = 30

processes = {}
shells = []
file_accesses = []
network_connections = []


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def has_ancestor(exec_id, ancestor_id):
    """Verifie si un processus descend du shell suspect."""
    visited = set()

    while exec_id and exec_id not in visited:
        if exec_id == ancestor_id:
            return True

        visited.add(exec_id)

        process = processes.get(exec_id, {})
        exec_id = process.get("parent_exec_id")

    return False


# 1. Lire les evenements Tetragon
with INPUT_FILE.open(encoding="utf-8") as f:
    events = [
        json.loads(line)
        for line in f
        if line.strip()
    ]


# 2. Reconstruire les relations entre processus
for event in events:
    details = event.get("process_exec")

    if not details:
        continue

    process = details.get("process", {})
    exec_id = process.get("exec_id")

    if not exec_id:
        continue

    processes[exec_id] = {
        "parent_exec_id": process.get("parent_exec_id"),
        "binary": process.get("binary", ""),
        "pid": process.get("pid")
    }

    parent = details.get("parent", {})

    if (
        Path(process.get("binary", "")).name in {"sh", "bash", "dash"}
        and "r4_web_server.py" in parent.get("arguments", "")
    ):
        shells.append({
            "exec_id": exec_id,
            "pid": process.get("pid"),
            "time": event.get("time")
        })


# 3. Identifier les observations R1 et R9
for event in events:
    details = event.get("process_kprobe")

    if not details:
        continue

    process = details.get("process", {})
    exec_id = process.get("exec_id")
    args = details.get("args", [])
    policy = details.get("policy_name")

    if not exec_id or not args:
        continue

    if policy == "r1-sensitive-file-access":
        path = args[0].get("file_arg", {}).get("path")

        if path == SECRET:
            file_accesses.append({
                "exec_id": exec_id,
                "time": event.get("time"),
                "binary": process.get("binary"),
                "pid": process.get("pid")
            })

    elif policy == "r9-tcp-connect":
        sock = args[0].get("sock_arg", {})
        destination = sock.get("daddr")

        try:
            port = int(sock.get("dport"))
        except (TypeError, ValueError):
            continue

        if destination == "127.0.0.1" and port == 9090:
            network_connections.append({
                "exec_id": exec_id,
                "time": event.get("time"),
                "binary": process.get("binary"),
                "pid": process.get("pid")
            })


# 4. Chercher la sequence R4 -> R1 -> R9
alerts = []

for shell in shells:
    t_shell = parse_time(shell["time"])

    for access in file_accesses:
        if not has_ancestor(access["exec_id"], shell["exec_id"]):
            continue

        t_access = parse_time(access["time"])

        for connection in network_connections:
            if not has_ancestor(connection["exec_id"], shell["exec_id"]):
                continue

            t_network = parse_time(connection["time"])

            duration = (t_network - t_shell).total_seconds()

            if (
                t_shell <= t_access <= t_network
                and 0 <= duration <= WINDOW_SECONDS
            ):
                alerts.append({
                    "rule_id": "R14",
                    "status": "ALERT",
                    "severity": "CRITICAL",
                    "time": connection["time"],
                    "matched_rules": ["R4", "R1", "R9"],
                    "shell_exec_id": shell["exec_id"],
                    "shell_pid": shell["pid"],
                    "file_process_pid": access["pid"],
                    "network_process_pid": connection["pid"],
                    "duration_seconds": round(duration, 3),
                    "reason": (
                        "Shell lance par serveur web, "
                        "suivi d'un acces sensible et "
                        "d'une connexion TCP inhabituelle"
                    )
                })

                break

        if any(
            alert["shell_exec_id"] == shell["exec_id"]
            for alert in alerts
        ):
            break


# 5. Supprimer les alertes repetees pour un meme shell
unique_alerts = {
    alert["shell_exec_id"]: alert
    for alert in alerts
}

with OUTPUT_FILE.open("w", encoding="utf-8") as output:
    for alert in unique_alerts.values():
        output.write(json.dumps(alert, ensure_ascii=False) + "\n")

        print(
            f"[ALERT R14] CRITICAL "
            f"| Shell PID={alert['shell_pid']} "
            f"| Sequence=R4 -> R1 -> R9 "
            f"| Duree={alert['duration_seconds']}s"
        )

print("\n===== BILAN R14 =====")
print(f"Shells surveilles : {len(shells)}")
print(f"Acces sensibles observes : {len(file_accesses)}")
print(f"Connexions inhabituelles observees : {len(network_connections)}")
print(f"Chaines correlees : {len(unique_alerts)}")
print(f"Resultats : {OUTPUT_FILE}")
