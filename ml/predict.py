
import argparse
from pathlib import Path

import joblib
import pandas as pd


def predict(model_file, dataset_file, output_file):
    # Charger le modèle déjà entraîné
    saved = joblib.load(model_file)

    model = saved["model"]
    feature_columns = saved["features"]

    # Charger les nouvelles observations
    df = pd.read_csv(dataset_file)

    # Vérifier les caractéristiques attendues
    missing = [
        name for name in feature_columns
        if name not in df.columns
    ]

    if missing:
        raise ValueError(f"Colonnes manquantes : {missing}")

    X = df[feature_columns]

    if X.empty or X.isna().any().any():
        raise ValueError("Dataset vide ou contenant des valeurs manquantes")

    # Calculer le score et la classification
    scores = model.decision_function(X)
    predictions = model.predict(X)

    # Ajouter les résultats au tableau
    df["anomaly_score"] = scores
    df["prediction"] = [
        "ANOMALY" if value == -1 else "NORMAL"
        for value in predictions
    ]

    # Sauvegarder les résultats
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)

    print(f"Fenêtres analysées : {len(df)}")
    print(f"Anomalies signalées : {(predictions == -1).sum()}")
    print(f"Résultats enregistrés : {output_file}")

    print(df[
        ["window_start", "anomaly_score", "prediction"]
    ].to_string(index=False))


def main():
    parser = argparse.ArgumentParser(
        description="Prédictions Zero-Day Hunter"
    )

    parser.add_argument("model", type=Path)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)

    args = parser.parse_args()

    predict(args.model, args.dataset, args.output)


if __name__ == "__main__":
    main()
