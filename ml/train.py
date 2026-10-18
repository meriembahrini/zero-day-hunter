
import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


ALL_FEATURES = [
    "process_exec_count",
    "process_exit_count",
    "network_connect_count",
    "chmod_count",
    "dangerous_chmod_count",
    "unique_binary_count",
    "shell_exec_count",
    "unique_destination_port_count",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("model_output", type=Path)
    args = parser.parse_args()

    df = pd.read_csv(args.dataset)

    if len(df) < 20:
        raise ValueError(
            "Il faut au moins 20 fenêtres pour cet entraînement."
        )

    features = [f for f in ALL_FEATURES if f in df.columns]

    if not features:
        raise ValueError("Aucune caractéristique reconnue.")

    X = df[features]

    if X.isna().any().any():
        raise ValueError("Le dataset contient des valeurs manquantes.")

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
        n_jobs=1
    )

    model.fit(X)

    args.model_output.parent.mkdir(
        parents=True, exist_ok=True
    )

    joblib.dump(
        {
            "model": model,
            "features": features,
            "window_seconds": 30
        },
        args.model_output
    )

    print("Entraînement terminé !")
    print("Fenêtres :", len(df))
    print("Caractéristiques :", features)
    print("Modèle :", args.model_output)


if __name__ == "__main__":
    main()
