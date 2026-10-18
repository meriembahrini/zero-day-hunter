
import argparse
import csv
import json
import math

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from features import extract_features


def parse_timestamp(value):
    """Convertit une date Tetragon en objet datetime."""

    if not isinstance(value, str):
        return None

    try:
        date_part, separator, fraction = value.partition(".")

        if separator:
            digits = ""
            index = 0

            while index < len(fraction) and fraction[index].isdigit():
                digits += fraction[index]
                index += 1

            suffix = fraction[index:]
            value = date_part + "." + digits[:6] + suffix

        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        ).astimezone(timezone.utc)

    except ValueError:
        return None


def build_dataset(
    input_file,
    output_file,
    window_seconds,
    metadata_file=None
):

    windows = defaultdict(list)
    invalid = 0

    # 1. Lire les événements normalisés
    with input_file.open("r", encoding="utf-8") as source:

        for line in source:

            if not line.strip():
                continue

            event = json.loads(line)
            timestamp = parse_timestamp(event.get("timestamp"))

            if timestamp is None:
                invalid += 1
                continue

            unix_time = timestamp.timestamp()

            window_start = (
                math.floor(unix_time / window_seconds)
                * window_seconds
            )

            windows[window_start].append(event)

    # 2. Déterminer les fenêtres à analyser
    if metadata_file is not None:

        metadata = json.loads(
            metadata_file.read_text(encoding="utf-8")
        )

        start = parse_timestamp(metadata.get("start_time"))
        end = parse_timestamp(metadata.get("end_time"))

        if start is None or end is None or end <= start:
            raise ValueError(
                "Métadonnées temporelles invalides"
            )

        # Première fenêtre entièrement surveillée
        first_window = (
            math.ceil(start.timestamp() / window_seconds)
            * window_seconds
        )

        # Dernière fenêtre entièrement surveillée
        last_window = (
            math.floor(end.timestamp() / window_seconds)
            * window_seconds
            - window_seconds
        )

        # Les fenêtres partielles sont exclues.
        # Les événements bruts restent conservés.

    elif windows:

        # Sans métadonnées, utiliser la première
        # et la dernière fenêtre contenant des événements.
        first_window = min(windows)
        last_window = max(windows)

    else:

        print("Aucune fenêtre disponible.")
        return

    # 3. Vérifier qu'une fenêtre complète est disponible
    if last_window < first_window:

        print("Aucune fenêtre complète disponible.")
        return

    # 4. Calculer les caractéristiques par fenêtre
    rows = []

    for window_start in range(
        first_window,
        last_window + window_seconds,
        window_seconds
    ):

        events = windows.get(window_start, [])

        features = extract_features(events)

        row = {
            "window_start": datetime.fromtimestamp(
                window_start,
                tz=timezone.utc
            ).isoformat(),

            "event_count": len(events),

            **features
        }

        rows.append(row)

    # 5. Préparer le dossier de sortie
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # 6. Enregistrer le dataset CSV
    with output_file.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as destination:

        writer = csv.DictWriter(
            destination,
            fieldnames=rows[0].keys()
        )

        writer.writeheader()
        writer.writerows(rows)

    # 7. Afficher les résultats
    print(f"Fenêtres créées : {len(rows)}")
    print(f"Horodatages invalides : {invalid}")
    print(f"Dataset enregistré : {output_file}")


def main():

    parser = argparse.ArgumentParser(
        description="Construction du dataset Zero-Day Hunter"
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Fichier JSONL normalisé"
    )

    parser.add_argument(
        "output",
        type=Path,
        help="Fichier CSV à créer"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=30,
        help="Durée d'une fenêtre en secondes"
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        help="Fichier contenant les heures de collecte"
    )

    args = parser.parse_args()

    if args.window <= 0:
        parser.error(
            "La durée de fenêtre doit être supérieure à 0"
        )

    if not args.input.is_file():
        parser.error(
            "Fichier d'entrée introuvable"
        )

    if args.metadata and not args.metadata.is_file():
        parser.error(
            "Fichier de métadonnées introuvable"
        )

    if args.input.resolve() == args.output.resolve():
        parser.error(
            "Les fichiers d'entrée et de sortie doivent être différents"
        )

    build_dataset(
        args.input,
        args.output,
        args.window,
        args.metadata
    )


if __name__ == "__main__":
    main()
