
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def capture(output_file, duration):
    output_file.parent.mkdir(parents=True, exist_ok=True)

    metadata_file = output_file.with_suffix(".meta.json")

    command = [
        "sudo", "-n",
        "timeout", str(duration),
        "tetra", "getevents", "-o", "json"
    ]

    print(f"Début de la collecte : {utc_now()}", flush=True)
    print(f"Durée demandée : {duration} secondes", flush=True)

    with output_file.open("w", encoding="utf-8") as destination:
        start_time = utc_now()

        try:
            result = subprocess.run(
                command,
                stdout=destination,
                check=False
            )
        finally:
            end_time = utc_now()

            metadata = {
                "start_time": start_time,
                "end_time": end_time,
                "duration_requested_seconds": duration
            }

            metadata_file.write_text(
                json.dumps(metadata, indent=4),
                encoding="utf-8"
            )

    print(f"Code de sortie : {result.returncode}")
    print(f"Fin de la collecte : {end_time}")
    print(f"Événements : {output_file}")
    print(f"Métadonnées : {metadata_file}")

    if result.returncode not in (0, 124):
        raise RuntimeError(
            f"Échec de la collecte : code {result.returncode}"
        )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--duration",
        type=int,
        default=600
    )

    args = parser.parse_args()

    if args.duration <= 0:
        parser.error("La durée doit être positive")

    capture(args.output, args.duration)


if __name__ == "__main__":
    main()
