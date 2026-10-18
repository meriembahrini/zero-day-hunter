
import argparse
import json
from pathlib import Path


EVENT_TYPES = ("process_exec", "process_exit", "process_kprobe")


def normalize_process(process):
    """Organise les informations d'un processus Linux."""
    process = process or {}

    return {
        "pid": process.get("pid"),
        "tid": process.get("tid"),
        "uid": process.get("uid"),
        "exec_id": process.get("exec_id"),
        "parent_exec_id": process.get("parent_exec_id"),
        "binary": process.get("binary"),
        "arguments": process.get("arguments"),
        "cwd": process.get("cwd"),
        "flags": process.get("flags"),
        "start_time": process.get("start_time"),
        "auid": process.get("auid"),
    }


def normalize(event):
    """Transforme un événement brut Tetragon en format commun."""

    # Identifier le type d'événement.
    event_type = next(
        (name for name in EVENT_TYPES if name in event),
        None
    )

    if event_type is None:
        return None

    details = event[event_type]

    if not isinstance(details, dict):
        return None

    process = normalize_process(details.get("process"))
    parent = normalize_process(details.get("parent"))

    # Conserver les informations propres aux sondes Tetragon.
    return {
        "schema_version": "1.0",
        "timestamp": event.get("time"),
        "host": event.get("node_name"),
        "event_type": event_type,
        "source": "tetragon",

        "process": process,
        "parent": parent,

        "policy_name": details.get("policy_name"),
        "function_name": details.get("function_name"),
        "args": details.get("args"),
        "return_value": details.get("return"),

        # Conserver tous les autres champs pour éviter
        # de perdre des informations spécifiques aux sondes.
        "extra": {
            key: value
            for key, value in details.items()
            if key not in {
                "process", "parent", "policy_name",
                "function_name", "args", "return"
            }
        }
    }


def process_file(input_path, output_path):
    """Lit un JSONL et écrit les événements normalisés."""

    total = 0
    normalized_count = 0
    ignored = 0
    errors = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8") as source, \
         output_path.open("w", encoding="utf-8") as destination:

        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue

            total += 1

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    ignored += 1
                    continue

                result = normalize(event)

                if result is None:
                    ignored += 1
                    continue

                destination.write(
                    json.dumps(result, ensure_ascii=False) + "\n"
                )

                normalized_count += 1

            except (json.JSONDecodeError, TypeError, ValueError) as error:
                errors += 1
                print(f"Ligne {line_number} invalide : {error}")

    print(f"Événements lus         : {total}")
    print(f"Événements normalisés  : {normalized_count}")
    print(f"Événements ignorés     : {ignored}")
    print(f"Erreurs JSON           : {errors}")
    print(f"Fichier de sortie      : {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Normalisation des événements Tetragon"
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Fichier JSONL brut à lire"
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Fichier JSONL normalisé à créer"
    )

    args = parser.parse_args()

    if args.input.resolve() == args.output.resolve():
        parser.error("Les fichiers d'entrée et de sortie doivent être différents.")

    if not args.input.is_file():
        parser.error(f"Fichier introuvable : {args.input}")

    process_file(args.input, args.output)


if __name__ == "__main__":
    main()
