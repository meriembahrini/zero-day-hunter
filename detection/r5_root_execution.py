
import json
import sys
from pathlib import Path

PROJECT = Path.home() / "zero-day-hunter"

INPUT_FILE = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else PROJECT / "data/scenarios/r8_raw.jsonl"
)

OUTPUT_FILE = (
    Path(sys.argv[2])
    if len(sys.argv) > 2
    else PROJECT / "data/scenarios/r5_results.jsonl"
)

# Programmes root connus dans notre laboratoire
ALLOWED_ROOT_BINARIES = {
    "/usr/bin/id",
    "/usr/bin/whoami"
}

# Scripts Ubuntu utilisés lors de la connexion SSH
MOTD_DIRECTORY = "/etc/update-motd.d/"

# Script web de notre laboratoire
WEB_SERVER_SCRIPT = "r4_web_server.py"

seen = set()
normal_count = 0
review_count = 0
alert_count = 0


def classify_process(binary, arguments, parent_binary, parent_arguments):
    """
    Classe un processus root selon son contexte observable.
    """

    # 1. Shell root lancé par notre serveur web de laboratoire
    shell_names = {"sh", "bash", "dash"}

    if (
        Path(binary).name in shell_names
        and WEB_SERVER_SCRIPT in parent_arguments
        and Path(parent_binary).name.startswith("python")
    ):
        return (
            "ALERT",
            "HIGH",
            "Shell root lance par le serveur web du laboratoire"
        )

    # 2. Programmes explicitement autorisés
    if binary in ALLOWED_ROOT_BINARIES:
        return (
            "NORMAL",
            "INFO",
            "Programme root autorise dans le laboratoire"
        )

    # 3. Scripts du message de bienvenue Ubuntu
    if binary.startswith(MOTD_DIRECTORY):
        return (
            "NORMAL",
            "INFO",
            "Script du message de bienvenue Ubuntu"
        )

    # 4. Service SSH
    if binary == "/usr/sbin/sshd":
        return (
            "NORMAL",
            "INFO",
            "Service SSH systeme"
        )

    # 5. Autres programmes root : investigation
    return (
        "REVIEW",
        "LOW",
        "Execution root a examiner"
    )


OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

with INPUT_FILE.open("r", encoding="utf-8") as source, \
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

        if process.get("uid") != 0:
            continue

        binary = process.get("binary") or ""
        arguments = process.get("arguments") or ""
        parent_binary = parent.get("binary") or ""
        parent_arguments = parent.get("arguments") or ""

        pid = process.get("pid")
        exec_id = process.get("exec_id")

        if exec_id and exec_id in seen:
            continue

        if exec_id:
            seen.add(exec_id)

        status, severity, reason = classify_process(
            binary,
            arguments,
            parent_binary,
            parent_arguments
        )

        if status == "NORMAL":
            normal_count += 1
        elif status == "REVIEW":
            review_count += 1
        else:
            alert_count += 1

        result = {
            "rule_id": "R5",
            "time": event.get("time"),
            "status": status,
            "severity": severity,
            "reason": reason,
            "pid": pid,
            "uid": 0,
            "exec_id": exec_id,
            "binary": binary,
            "arguments": arguments,
            "parent_binary": parent_binary,
            "parent_arguments": parent_arguments
        }

        output.write(
            json.dumps(result, ensure_ascii=False) + "\n"
        )

        print(
            f"[{status} R5] "
            f"PID={pid} Programme={binary}"
        )


print("\n===== BILAN R5 =====")
print(f"Normaux : {normal_count}")
print(f"A examiner : {review_count}")
print(f"Alertes : {alert_count}")
print(f"Resultats : {OUTPUT_FILE}")
