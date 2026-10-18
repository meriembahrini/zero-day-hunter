
from pathlib import Path
import pandas as pd

BASE = Path.home() / "zero-day-hunter/data/training"

SOURCES = [
    "normal_v3_dataset.csv",
    "normal_v4_dataset.csv",
    "normal_v5_dataset.csv",
]

OUTPUT = BASE / "normal_v5_combined_dataset.csv"

FEATURES = [
    "process_exec_count",
    "process_exit_count",
    "network_connect_count",
    "chmod_count",
    "dangerous_chmod_count",
    "unique_binary_count",
    "shell_exec_count",
    "unique_destination_port_count",
]

datasets = []

for filename in SOURCES:
    df = pd.read_csv(BASE / filename)

    required = ["window_start", "event_count"] + FEATURES
    missing = [col for col in required if col not in df.columns]

    if missing:
        raise ValueError(f"{filename}: colonnes manquantes {missing}")

    df = df[required].copy()
    df["window_start"] = pd.to_datetime(
        df["window_start"], utc=True, errors="raise"
    )

    if df[FEATURES + ["event_count"]].isna().any().any():
        raise ValueError(f"{filename}: valeurs manquantes")

    if (df[FEATURES + ["event_count"]] < 0).any().any():
        raise ValueError(f"{filename}: valeurs négatives")

    df["source"] = filename
    datasets.append(df)

combined = pd.concat(datasets, ignore_index=True)
combined = combined.sort_values("window_start")

duplicates = combined.duplicated("window_start", keep=False)

if duplicates.any():
    print("Fenêtres avec horodatages identiques :")
    print(combined.loc[duplicates, ["window_start", "source"]])
    raise ValueError("Doublons temporels : vérifier les captures.")

# Vérifier qu'aucune fenêtre de 30 s ne chevauche une autre
starts = combined["window_start"].reset_index(drop=True)
if (starts.diff().dropna() < pd.Timedelta(seconds=30)).any():
    raise ValueError("Chevauchement de fenêtres détecté.")

combined = combined.drop(columns="source")
combined["window_start"] = combined["window_start"].dt.strftime(
    "%Y-%m-%dT%H:%M:%S%z"
)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
combined.to_csv(OUTPUT, index=False)

active = int((combined["event_count"] > 0).sum())
empty = int((combined["event_count"] == 0).sum())

print("\n===== DATASET V5 =====")
print("Fenêtres totales :", len(combined))
print("Fenêtres actives :", active)
print("Fenêtres vides :", empty)
print("Connexions TCP :", int(combined["network_connect_count"].sum()))
print("Colonnes ML :", len(FEATURES))
print("Fichier :", OUTPUT)
