
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parent

RULE_NAMES = {
    "R1": "Acces a un fichier sensible",
    "R2": "Modification suspecte des permissions",
    "R3": "Shell lance par un serveur web",
    "R4": "Outil administratif inhabituel",
    "R5": "Execution avec privileges root",
    "R6": "Connexion TCP suspecte",
    "R7": "Correlation de comportements suspects",
}

SOURCE_NAMES = {
    "RULE_ONLY": "Regle de securite",
    "AI_ONLY": "Intelligence artificielle",
    "HYBRID": "Regle + IA (meme periode)",
}


def run_command(command):
    """Execute une commande et signale les echecs."""
    subprocess.run(
        command,
        check=True,
        cwd=PROJECT
    )


def read_jsonl(path):
    """Lit les evenements JSONL."""
    records = []

    if not path.is_file():
        return records

    with path.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            records.append(json.loads(line))

    return records


def check_sudo():
    """
    Verifie que sudo peut fonctionner sans demander
    le mot de passe pendant la capture.
    """
    result = subprocess.run(
        ["sudo", "-n", "true"],
        capture_output=True,
        text=True,
        cwd=PROJECT
    )

    return result.returncode == 0


def show_alerts(alerts, reviews):
    """
    Affiche les notifications dans le terminal
    apres chaque cycle d'analyse.
    """

    print("\n" + "=" * 55)
    print("       NOTIFICATIONS ZERO-DAY HUNTER")
    print("=" * 55)

    if not alerts:
        print("\n[OK] Aucune alerte de securite generee.")
        print(
            "Cela ne garantit pas l'absence d'attaque."
        )

    else:
        print(
            f"\n[!] {len(alerts)} ALERTE(S) DETECTEE(S)"
        )

        for index, alert in enumerate(alerts, start=1):
            rule_id = alert.get("rule_id")
            priority = alert.get("priority", "MEDIUM")
            source = alert.get("source", "UNKNOWN")

            name = (
                RULE_NAMES.get(rule_id, rule_id)
                if rule_id
                else "Anomalie statistique"
            )

            print("\n" + "-" * 55)
            print(f"ALERTE {index}/{len(alerts)}")
            print("-" * 55)

            print("Heure :", alert.get("timestamp", "-"))
            print("Priorite :", priority)
            print("Detecteur :", rule_id or "IA")
            print("Comportement :", name)
            print(
                "Origine :",
                SOURCE_NAMES.get(source, source)
            )
            print(
                "Explication :",
                alert.get("reason", "")
            )

            ai_prediction = alert.get("ai_prediction")

            if ai_prediction == "ANOMALY":
                print("IA : comportement inhabituel")

            elif ai_prediction == "NORMAL":
                print("IA : comportement non signale")

            else:
                print("IA : aucune fenetre associee")

            print(
                "Action : verifier cette session "
                "dans le dashboard."
            )

    print("\nObservations a examiner :", len(reviews))

    if reviews:
        by_rule = {}

        for review in reviews:
            rule_id = review.get("rule_id", "UNKNOWN")
            by_rule[rule_id] = by_rule.get(rule_id, 0) + 1

        for rule_id, count in sorted(by_rule.items()):
            print(
                f"  - {rule_id} : {count} observation(s)"
            )

        print(
            "Ces observations ne sont pas des "
            "attaques confirmees."
        )

    print("\n" + "=" * 55, flush=True)


def run_cycle(number, total, duration, model):
    """Effectue une capture, une analyse et les notifications."""

    now = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    output_dir = PROJECT / "data/monitor" / now

    output_dir.mkdir(
        parents=True,
        exist_ok=False
    )

    raw_file = output_dir / "events_raw.jsonl"
    metadata_file = output_dir / "events_raw.meta.json"
    analysis_dir = output_dir / "analysis"

    print(
        f"\n===== CYCLE {number}/{total} =====",
        flush=True
    )
    print("Session :", output_dir, flush=True)

    # ETAPE 1 : COLLECTE
    print("\n1. Collecte Tetragon", flush=True)

    run_command([
        sys.executable,
        str(PROJECT / "collector/capture.py"),
        str(raw_file),
        "--duration",
        str(duration)
    ])

    if not metadata_file.is_file():
        raise RuntimeError(
            "Metadonnees de collecte introuvables."
        )

    # ETAPE 2 : ANALYSE
    print("\n2. Analyse des regles et de l'IA", flush=True)

    run_command([
        sys.executable,
        str(PROJECT / "main.py"),
        "--input",
        str(raw_file),
        "--metadata",
        str(metadata_file),
        "--model",
        str(model),
        "--output-dir",
        str(analysis_dir)
    ])

    # ETAPE 3 : RECUPERATION DES RESULTATS
    alerts = read_jsonl(
        analysis_dir / "hybrid_alerts.jsonl"
    )

    rule_alerts = read_jsonl(
        analysis_dir / "rule_alerts.jsonl"
    )

    reviews = read_jsonl(
        analysis_dir / "rule_reviews.jsonl"
    )

    events = read_jsonl(raw_file)

    # ETAPE 4 : NOTIFICATIONS AUTOMATIQUES
    show_alerts(alerts, reviews)

    # ETAPE 5 : SAUVEGARDE DU BILAN
    summary = {
        "cycle": number,
        "timestamp": now,
        "events": len(events),
        "rule_alerts": len(rule_alerts),
        "reviews": len(reviews),
        "hybrid_alerts": len(alerts),
        "model": model.name,
        "analysis_dir": str(analysis_dir)
    }

    summary_file = output_dir / "summary.json"

    summary_file.write_text(
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )

    print("\n===== BILAN DU CYCLE =====")
    print("Evenements :", len(events))
    print("Alertes des regles :", len(rule_alerts))
    print("Observations REVIEW :", len(reviews))
    print("Alertes finales :", len(alerts))
    print("Resultats :", analysis_dir)

    return summary


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Surveillance et notifications Zero-Day Hunter"
        )
    )

    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duree de capture par cycle (secondes)"
    )

    parser.add_argument(
        "--cycles",
        type=int,
        default=1,
        help="Nombre de cycles"
    )

    parser.add_argument(
        "--model",
        type=Path,
        default=(
            PROJECT
            / "data/models/isolation_forest_v4.joblib"
        ),
        help="Modele IA V4 ou V5"
    )

    args = parser.parse_args()

    if args.duration < 60:
        parser.error(
            "La duree minimale est de 60 secondes."
        )

    if args.cycles < 1:
        parser.error(
            "Le nombre de cycles doit etre au moins 1."
        )

    model = args.model.resolve()

    if not model.is_file():
        parser.error(
            f"Modele introuvable : {model}"
        )

    print("\n===== ZERO-DAY HUNTER MONITOR =====")
    print("Modele :", model.name)
    print("Cycles :", args.cycles)
    print(
        "Duree par capture :",
        args.duration,
        "secondes"
    )
    print("Notifications : terminal Ubuntu")

    if not check_sudo():
        print("\nERREUR : autorisation sudo absente.")
        print("Execute d'abord : sudo -v")
        sys.exit(1)

    results = []

    try:
        for number in range(1, args.cycles + 1):

            if not check_sudo():
                print(
                    "\nSurveillance arretee : "
                    "autorisation sudo expiree."
                )
                break

            result = run_cycle(
                number=number,
                total=args.cycles,
                duration=args.duration,
                model=model
            )

            results.append(result)

    except KeyboardInterrupt:
        print("\nSurveillance arretee par l'utilisateur.")

    except (
        subprocess.CalledProcessError,
        RuntimeError,
        OSError,
        ValueError,
        json.JSONDecodeError
    ) as error:
        print(
            f"\nErreur pendant la surveillance : {error}"
        )

    print("\n===== BILAN GLOBAL =====")
    print("Cycles demandes :", args.cycles)
    print("Cycles reussis :", len(results))

    print(
        "Evenements collectes :",
        sum(item["events"] for item in results)
    )

    print(
        "Alertes finales :",
        sum(item["hybrid_alerts"] for item in results)
    )

    print(
        "Observations REVIEW :",
        sum(item["reviews"] for item in results)
    )

    print("\nHistorique : data/monitor/")

    if len(results) != args.cycles:
        sys.exit(1)


if __name__ == "__main__":
    main()
