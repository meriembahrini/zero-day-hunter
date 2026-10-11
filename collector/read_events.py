import json
from pathlib import Path

file_path = Path.home() / "zero-day-hunter/data/events.jsonl"

with file_path.open("r", encoding="utf-8") as file:
    for number, line in enumerate(file, start=1):
        if not line.strip():
            continue

        event = json.loads(line)

        if "process_exec" in event:
            event_type = "EXECUTION"
            data = event["process_exec"]

        elif "process_exit" in event:
            event_type = "TERMINAISON"
            data = event["process_exit"]

        else:
            event_type = "AUTRE"
            data = {}

        process = data.get("process") or {}

        print(
            f"Événement {number} | "
            f"{event_type} | "
            f"Programme : {process.get('binary', 'inconnu')} | "
            f"PID : {process.get('pid', 'inconnu')}"
        )
