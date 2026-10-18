
import argparse
import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib


PROJECT = Path(__file__).resolve().parent

RULES = {
    "R1": "r1_file_access.py",
    "R2": "r2_permission_change.py",
    "R3": "r3_web_shell.py",
    "R4": "r4_admin_tools.py",
    "R5": "r5_root_execution.py",
    "R6": "r6_tcp_connection.py",
    "R7": "r7_correlation.py",
}


def run_script(script, *arguments):
    """Exécute un script et arrête le pipeline en cas d'erreur."""

    command = [
        sys.executable,
        str(PROJECT / script),
        *[str(arg) for arg in arguments]
    ]

    print(f"\n>>> {script}", flush=True)

    subprocess.run(
        command,
        cwd=PROJECT,
        check=True
    )


def parse_time(value):
    """Convertit les horodatages Tetragon en UTC."""

    if not value:
        return None

    try:
        value = str(value)

        # Python accepte les microsecondes, Tetragon peut en
        # fournir jusqu'à neuf : nous gardons les six premières.
        if "." in value:
            prefix, fraction = value.split(".", 1)

            digits = ""
            index = 0

            while index < len(fraction) and fraction[index].isdigit():
                digits += fraction[index]
                index += 1

            suffix = fraction[index:]
            value = prefix + "." + digits[:6] + suffix

        result = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def combine_rule_results(results_dir, alert_file, review_file):
    """
    Regroupe les résultats des sept règles.

    ALERT  -> fichier utilisé par le moteur hybride.
    REVIEW -> observations à examiner séparément.
    NORMAL -> reste dans le fichier individuel de la règle.
    """

    alert_count = 0
    review_count = 0

    with alert_file.open("w", encoding="utf-8") as alerts, \
         review_file.open("w", encoding="utf-8") as reviews:

        for rule_id in RULES:

            file_path = results_dir / f"{rule_id.lower()}_results.jsonl"

            if not file_path.exists():
                raise FileNotFoundError(
                    f"Résultat de règle manquant : {file_path}"
                )

            with file_path.open(encoding="utf-8") as source:

                for line in source:
                    if not line.strip():
                        continue

                    item = json.loads(line)
                    status = str(
                        item.get("status", "")
                    ).upper()

                    if status not in {"ALERT", "REVIEW"}:
                        continue

                    # Harmonisation des identifiants historiques.
                    item["rule_id"] = rule_id

                    if status == "ALERT":
                        destination = alerts
                        alert_count += 1
                    else:
                        destination = reviews
                        review_count += 1

                    destination.write(
                        json.dumps(item, ensure_ascii=False) + "\n"
                    )

    print(f"Alertes des règles : {alert_count}")
    print(f"Observations à examiner : {review_count}")


def load_predictions(path):
    """Lit les prédictions du modèle Isolation Forest."""

    with path.open(
        newline="",
        encoding="utf-8"
    ) as file:
        return list(csv.DictReader(file))


def fuse_alerts(
    rule_file,
    predictions_file,
    output_file,
    window_seconds
):
    """
    Associe les alertes des règles aux fenêtres de l'IA.

    Une source HYBRID indique une coïncidence temporelle :
    elle ne prouve pas que l'IA et la règle ont détecté
    exactement le même processus.
    """

    predictions = []

    for row in load_predictions(predictions_file):

        timestamp = parse_time(
            row.get("window_start")
        )

        if timestamp is None:
            continue

        predictions.append({
            "start": timestamp,
            "score": float(row["anomaly_score"]),
            "prediction": row["prediction"]
        })

    rules = []

    with rule_file.open(encoding="utf-8") as file:

        for line in file:
            if not line.strip():
                continue

            item = json.loads(line)
            timestamp = parse_time(
                item.get("time")
            )

            if timestamp is None:
                continue

            rules.append((timestamp, item))

    alerts = []

    # 1. Fusion des alertes des règles avec l'IA.
    for timestamp, item in rules:

        matching = next(
            (
                pred for pred in predictions
                if (
                    pred["start"].timestamp()
                    <= timestamp.timestamp()
                    < pred["start"].timestamp() + window_seconds
                )
            ),
            None
        )

        ai_anomaly = (
            matching is not None
            and matching["prediction"] == "ANOMALY"
        )

        severity = str(
            item.get("severity") or "MEDIUM"
        ).upper()

        # R5 reste expérimentale.
        if item.get("rule_id") == "R5":
            priority = "LOW"

        elif severity == "CRITICAL":
            priority = "CRITICAL"

        elif ai_anomaly and severity == "HIGH":
            priority = "HIGH"

        else:
            priority = severity

        alerts.append({
            "timestamp": timestamp.isoformat(),
            "rule_id": item.get("rule_id"),
            "rule_severity": severity,
            "ai_prediction": (
                matching["prediction"] if matching else None
            ),
            "ai_score": (
                matching["score"] if matching else None
            ),
            "priority": priority,
            "reason": item.get("reason", ""),
            "source": (
                "HYBRID"
                if ai_anomaly
                else "RULE_ONLY"
            )
        })

    # 2. Anomalies statistiques sans alerte de règle
    # autre que R5 dans la même fenêtre.
    for pred in predictions:

        if pred["prediction"] != "ANOMALY":
            continue

        has_rule = any(
            (
                pred["start"].timestamp()
                <= timestamp.timestamp()
                < pred["start"].timestamp() + window_seconds
                and item.get("rule_id") != "R5"
            )
            for timestamp, item in rules
        )

        if not has_rule:
            alerts.append({
                "timestamp": pred["start"].isoformat(),
                "rule_id": None,
                "rule_severity": None,
                "ai_prediction": "ANOMALY",
                "ai_score": pred["score"],
                "priority": "MEDIUM",
                "reason": "Anomalie statistique détectée",
                "source": "AI_ONLY"
            })

    alerts.sort(
        key=lambda item: item["timestamp"]
    )

    with output_file.open("w", encoding="utf-8") as file:

        for alert in alerts:
            file.write(
                json.dumps(alert, ensure_ascii=False) + "\n"
            )

    print(f"Alertes hybrides : {len(alerts)}")


def main():

    parser = argparse.ArgumentParser(
        description="Pipeline Zero-Day Hunter"
    )

    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Capture Tetragon brute JSONL"
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=PROJECT / "data/models/isolation_forest_v4.joblib",
        help="Modèle Isolation Forest V4 ou V5"
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        help="Métadonnées temporelles de la capture"
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT / "data/pipeline",
        help="Dossier de sortie"
    )

    args = parser.parse_args()

    input_file = args.input.resolve()
    model_file = args.model.resolve()
    output_dir = args.output_dir.resolve()

    if not input_file.is_file():
        parser.error("Capture introuvable")

    if not model_file.is_file():
        parser.error("Modèle IA introuvable")

    if args.metadata and not args.metadata.is_file():
        parser.error("Fichier de métadonnées introuvable")

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    model_package = joblib.load(
        model_file
    )

    window_seconds = int(
        model_package.get("window_seconds", 30)
    )

    print("\n===== ZERO-DAY HUNTER =====")
    print("Capture :", input_file)
    print("Modèle :", model_file)

    # 1. RÈGLES
    print("\n===== RÈGLES =====")

    for rule_id, filename in RULES.items():

        result_file = output_dir / (
            f"{rule_id.lower()}_results.jsonl"
        )

        run_script(
            f"detection/{filename}",
            input_file,
            result_file
        )

    # 2. ALERTES ET OBSERVATIONS
    print("\n===== CLASSIFICATION DES RÈGLES =====")

    rules_output = output_dir / "rule_alerts.jsonl"
    reviews_output = output_dir / "rule_reviews.jsonl"

    combine_rule_results(
        output_dir,
        rules_output,
        reviews_output
    )

    # 3. NORMALISATION
    print("\n===== NORMALISATION =====")

    normalized_file = output_dir / "normalized.jsonl"

    run_script(
        "collector/normalize.py",
        input_file,
        normalized_file
    )

    # 4. DATASET
    print("\n===== DATASET =====")

    dataset_file = output_dir / "dataset.csv"

    # Évite d'utiliser un ancien dataset si la
    # nouvelle capture ne génère aucune fenêtre.
    if dataset_file.exists():
        dataset_file.unlink()

    dataset_arguments = [
        normalized_file,
        dataset_file,
        "--window",
        window_seconds
    ]

    if args.metadata:
        dataset_arguments.extend([
            "--metadata",
            args.metadata.resolve()
        ])

    run_script(
        "ml/build_dataset.py",
        *dataset_arguments
    )

    if not dataset_file.is_file():
        raise RuntimeError(
            "Aucun dataset créé : capture trop courte ?"
        )

    # 5. INTELLIGENCE ARTIFICIELLE
    print("\n===== INTELLIGENCE ARTIFICIELLE =====")

    predictions_file = output_dir / "predictions.csv"

    run_script(
        "ml/predict.py",
        model_file,
        dataset_file,
        predictions_file
    )

    # 6. MOTEUR HYBRIDE
    print("\n===== MOTEUR HYBRIDE =====")

    hybrid_file = output_dir / "hybrid_alerts.jsonl"

    fuse_alerts(
        rules_output,
        predictions_file,
        hybrid_file,
        window_seconds
    )

    print("\n===== PIPELINE TERMINÉ =====")
    print("Résultats :", output_dir)
    print("Alertes :", hybrid_file)
    print("Observations :", reviews_output)


if __name__ == "__main__":
    main()
