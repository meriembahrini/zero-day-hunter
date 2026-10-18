
import subprocess
import time
from datetime import datetime, timezone

COMMANDS = [
    ["uname", "-a"],
    ["id"],
    ["whoami"],
    ["hostname"],
    ["uptime"],
    ["ls", "/usr/bin"],
    ["ls", "/etc"],
    ["df", "-h"],
    ["free", "-h"],
    ["ps", "-ef"],
    ["ip", "address"],
    ["ip", "route"],
    ["ss", "-tuln"],
    ["find", "/usr/bin", "-maxdepth", "1", "-type", "f"],
    ["stat", "/etc/os-release"],
    ["cat", "/etc/os-release"],
    ["date"],
    ["env"],
]

print("===== SCENARIO S3 : RECONNAISSANCE SIMULEE =====")
print("Debut :", datetime.now(timezone.utc).isoformat())

for index, command in enumerate(COMMANDS, start=1):
    print(f"[{index}/{len(COMMANDS)}] {' '.join(command)}", flush=True)

    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5
    )

    print("  Code de retour :", result.returncode)

    time.sleep(0.2)

print("Fin :", datetime.now(timezone.utc).isoformat())
print("Simulation terminee.")
