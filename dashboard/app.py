"""Zero-Day Hunter — Streamlit SOC dashboard (Ubuntu Server compatible)."""
import html
import json
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT = Path(__file__).resolve().parent.parent
RULE_NAMES = {
    "R1": "Accès à un fichier sensible",
    "R2": "Modification des permissions",
    "R3": "Shell lancé par un serveur web",
    "R4": "Outil administratif inhabituel",
    "R5": "Exécution avec privilèges root",
    "R6": "Connexion TCP inhabituelle",
    "R7": "Corrélation de comportements suspects",
}
PRIORITY_LABEL = {
    "CRITICAL": "Critique", "HIGH": "Élevée", "MEDIUM": "Moyenne",
    "LOW": "Faible", "INFO": "Information",
}
SOURCE_LABEL = {
    "RULE_ONLY": "Règle comportementale",
    "AI_ONLY": "Intelligence artificielle",
    "HYBRID": "Règle + IA (même fenêtre)",
}
FEATURE_LABEL = {
    "process_exec_count": "Programmes exécutés",
    "process_exit_count": "Processus terminés",
    "network_connect_count": "Connexions TCP",
    "chmod_count": "Modifications de permissions",
    "dangerous_chmod_count": "Permissions risquées",
    "unique_binary_count": "Programmes distincts",
    "shell_exec_count": "Shells exécutés",
    "unique_destination_port_count": "Ports de destination distincts",
}

st.set_page_config(page_title="Zero-Day Hunter · Security Operations", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp { background: #0b1220; color: #e6edf7; }
[data-testid="stSidebar"] { background: #111c2e; border-right: 1px solid #273650; }
[data-testid="stHeader"] { background: #0b1220; }
.block-container { padding-top: 1.5rem; max-width: 1500px; }
h1, h2, h3 { color: #f5f8fe !important; letter-spacing: -.02em; }
p, label { color: #d3ddec; }
[data-testid="stMetric"] { background: #152238; border: 1px solid #2b3b55; border-radius: 12px; padding: 16px; }
[data-testid="stMetricLabel"] { color: #aebdd1; }
[data-testid="stMetricValue"] { color: #f3f7fd; }
[data-baseweb="tab-list"] { gap: 8px; }
button[data-baseweb="tab"] { background: #152238; border-radius: 9px 9px 0 0; }
[data-testid="stDataFrame"] { border: 1px solid #2b3b55; border-radius: 10px; }
.soc-title { font-size: 1.85rem; font-weight: 760; color: #f6f9ff; letter-spacing: -.03em; margin-bottom: 0; }
.soc-sub { color: #93a7c3; font-size: .93rem; margin-top: .35rem; }
.soc-panel { background: #152238; border: 1px solid #2b3b55; border-radius: 12px; padding: 16px 20px; margin: 9px 0 16px; }
.soc-eyebrow { color: #80c9ed; font-size: .76rem; letter-spacing: .12em; font-weight: 700; text-transform: uppercase; }
.soc-status { font-size: 1.1rem; font-weight: 650; color: #eef4ff; margin: 7px 0; }
.soc-detail { color: #b4c4db; font-size: .89rem; }
.soc-pill { display: inline-block; padding: .23rem .62rem; border: 1px solid #45617a; border-radius: 16px; background: #1e354d; color: #d6eafa; font-size: .75rem; margin: .2rem .35rem .2rem 0; }
.soc-action { border-left: 3px solid #38bdf8; background: #14263c; padding: 12px 15px; border-radius: 4px 9px 9px 4px; margin: 8px 0; color: #d9e6f8; }
small.soc-note { color: #96a8c1; }
</style>
""", unsafe_allow_html=True)


def safe(value):
    return html.escape(str(value if value is not None else ""))


def read_jsonl(path):
    records = []
    if not path.is_file():
        return pd.DataFrame()
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                continue
    return pd.DataFrame.from_records(records)


def count_lines(path):
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as source:
        return sum(bool(line.strip()) for line in source)


def session_dirs():
    found = []
    for root in [PROJECT / "data/pipeline", PROJECT / "data/monitor"]:
        if not root.is_dir():
            continue
        if (root / "predictions.csv").is_file() and (root / "dataset.csv").is_file():
            found.append(root)
        for folder in root.iterdir():
            if not folder.is_dir():
                continue
            for candidate in [folder, folder / "analysis"]:
                if (candidate / "predictions.csv").is_file() and (candidate / "dataset.csv").is_file():
                    found.append(candidate)
    return sorted(set(found), key=lambda p: p.stat().st_mtime, reverse=True)


def readable_time(value):
    try:
        ts = pd.to_datetime(value, utc=True, errors="coerce")
        if pd.isna(ts):
            return "—"
        return ts.strftime("%d/%m/%Y · %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError):
        return "—"


def session_name(path):
    return str(path.relative_to(PROJECT))


def display_frame(df, columns, renames=None):
    frame = df.copy()
    for column in columns:
        if column not in frame.columns:
            frame[column] = None
    st.dataframe(frame[columns].rename(columns=renames or {}), use_container_width=True, hide_index=True)


def severity_label(value):
    return PRIORITY_LABEL.get(str(value).upper(), str(value))


with st.sidebar:
    st.markdown("### 🛡️ ZERO-DAY HUNTER")
    st.caption("Security Operations · Linux / eBPF")
    if st.button("↻  Actualiser les sessions", use_container_width=True):
        st.rerun()
    sessions = session_dirs()
    if not sessions:
        st.warning("Aucune session analysée. Exécute main.py ou run_monitor.py sur Ubuntu.")
        st.stop()
    selected = st.selectbox("Session analysée", sessions, format_func=session_name)
    st.markdown("---")
    st.caption("Modèle par défaut : Isolation Forest V4")
    st.caption("Capteurs : Tetragon / eBPF")
    st.caption("Analyse par cycles — pas de blocage automatique")
    st.caption("VM : terminal uniquement · affichage depuis le Mac")

try:
    dataset = pd.read_csv(selected / "dataset.csv")
    predictions = pd.read_csv(selected / "predictions.csv")
except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
    st.error(f"Impossible de lire cette session : {exc}")
    st.stop()

alerts = read_jsonl(selected / "hybrid_alerts.jsonl")
reviews = read_jsonl(selected / "rule_reviews.jsonl")
rule_alerts = read_jsonl(selected / "rule_alerts.jsonl")
raw_path = selected.parent / "events_raw.jsonl" if selected.name == "analysis" else None
raw_events = count_lines(raw_path) if raw_path is not None else None
if raw_events is None:
    raw_events = count_lines(selected / "normalized.jsonl")
visible_events = int(dataset["event_count"].sum()) if "event_count" in dataset else 0
anomalies = int(predictions["prediction"].eq("ANOMALY").sum()) if "prediction" in predictions else 0
critical = int(alerts["priority"].eq("CRITICAL").sum()) if "priority" in alerts else 0
high = int(alerts["priority"].eq("HIGH").sum()) if "priority" in alerts else 0

st.markdown('<div class="soc-eyebrow">SECURITY OPERATIONS CENTER / OVERVIEW</div>', unsafe_allow_html=True)
st.markdown('<div class="soc-title">Zero-Day Hunter <span style="color:#57c4f7">/ Security Monitor</span></div>', unsafe_allow_html=True)
st.markdown('<div class="soc-sub">Un tableau de bord conçu pour comprendre les alertes, enquêter et retrouver les preuves — sans connaître les règles par cœur.</div>', unsafe_allow_html=True)
st.caption(f"Session sélectionnée : {session_name(selected)}")

if raw_events == 0:
    status, detail = "Aucune télémétrie enregistrée", "La capture est vide. Aucune conclusion de sécurité ne peut être tirée de ce cycle."
elif len(alerts) > 0:
    status, detail = f"{len(alerts)} alerte(s) à examiner", "Des comportements ont été signalés. Ils ne constituent pas automatiquement une compromission."
elif len(reviews) > 0:
    status, detail = "Observations à vérifier", "Aucune alerte finale, mais certains événements méritent une vérification humaine."
else:
    status, detail = "Aucune alerte sur cette session", "Les capteurs ont enregistré de l'activité, sans déclenchement des détecteurs disponibles."

st.markdown(
    '<div class="soc-panel"><div class="soc-eyebrow">ÉTAT DE LA SESSION</div>'
    f'<div class="soc-status">{safe(status)}</div><div class="soc-detail">{safe(detail)}</div></div>',
    unsafe_allow_html=True,
)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Événements capturés", raw_events if raw_events is not None else "N/D")
k2.metric("Fenêtres IA", len(predictions))
k3.metric("Anomalies IA", anomalies)
k4.metric("Alertes finales", len(alerts))
k5.metric("À examiner", len(reviews))
st.caption(f"Événements des fenêtres IA complètes : {visible_events} · Alertes critiques : {critical} · Élevées : {high}. Les fenêtres incomplètes ne sont pas toutes comptées dans les caractéristiques IA.")

alerts_tab, reviews_tab, ai_tab, activity_tab, history_tab, guide_tab = st.tabs([
    "🚨 Alertes", "🔎 Observations", "🧠 Intelligence artificielle",
    "📈 Activité", "🗂️ Sessions", "📋 Guide SOC",
])

with alerts_tab:
    st.subheader("Alertes détectées")
    st.write("Ici se trouvent les événements qui nécessitent une analyse, avec leur origine et leur priorité.")
    if alerts.empty:
        st.info("Aucune alerte enregistrée dans cette session. Consulte les observations et la qualité de la capture avant de conclure.")
    else:
        frame = alerts.copy()
        frame["Heure"] = frame.get("timestamp", pd.Series(dtype=str)).map(readable_time)
        frame["Règle"] = frame.get("rule_id", pd.Series(index=frame.index, dtype=str)).fillna("IA")
        frame["Comportement"] = frame["Règle"].map(RULE_NAMES).fillna("Anomalie statistique")
        frame["Priorité"] = frame.get("priority", pd.Series(index=frame.index, dtype=str)).map(severity_label)
        frame["Origine"] = frame.get("source", pd.Series(index=frame.index, dtype=str)).map(lambda x: SOURCE_LABEL.get(x, x))
        priorities = sorted(frame["Priorité"].dropna().unique())
        chosen = st.multiselect("Priorités", priorities, default=priorities)
        shown = frame[frame["Priorité"].isin(chosen)]
        display_frame(shown, ["Heure", "Règle", "Comportement", "Priorité", "Origine", "reason", "ai_score"], {"reason": "Explication", "ai_score": "Score IA"})
        if not shown.empty:
            st.download_button("Exporter les alertes CSV", shown.to_csv(index=False).encode("utf-8"), "zero_day_hunter_alertes.csv", "text/csv")
            st.markdown("#### Examiner une alerte")
            options = shown.index.tolist()
            choice = st.selectbox("Alerte à analyser", options, format_func=lambda idx: f"{frame.at[idx, 'Heure']} · {frame.at[idx, 'Règle']} · {frame.at[idx, 'Priorité']}")
            item = frame.loc[choice]
            st.markdown(
                '<div class="soc-panel">'
                f'<div class="soc-eyebrow">{safe(item["Priorité"])} · {safe(item["Origine"])}</div>'
                f'<div class="soc-status">{safe(item["Comportement"])}</div>'
                f'<div class="soc-detail">{safe(item.get("reason", "Aucune justification disponible"))}</div>'
                '</div>', unsafe_allow_html=True,
            )
            st.markdown('<div class="soc-action"><b>Prochaine action :</b> vérifie les événements proches de cette heure, les processus impliqués, leur parent et les connexions réseau. Une alerte est un indice, pas une preuve.</div>', unsafe_allow_html=True)
        st.caption("HYBRID = coïncidence dans une fenêtre de 30 secondes ; cela ne prouve pas que la règle et l'IA ont observé le même processus.")

with reviews_tab:
    st.subheader("Observations nécessitant une vérification")
    st.write("Les événements REVIEW de R5 sont conservés ici. Ils ne sont pas assimilés à des attaques et ne gonflent pas les alertes.")
    if reviews.empty:
        st.info("Aucune observation à examiner dans cette session.")
    else:
        frame = reviews.copy()
        frame["Heure"] = frame["time"].map(readable_time) if "time" in frame else "—"
        cols = ["Heure", "rule_id", "severity", "reason", "binary", "parent_binary", "arguments", "pid", "uid"]
        labels = {"rule_id": "Règle", "severity": "Niveau", "reason": "Pourquoi", "binary": "Programme", "parent_binary": "Parent", "arguments": "Arguments", "pid": "PID", "uid": "UID"}
        display_frame(frame, cols, labels)
        st.download_button("Exporter les observations CSV", frame.to_csv(index=False).encode("utf-8"), "zero_day_hunter_reviews.csv", "text/csv")

with ai_tab:
    st.subheader("Analyse comportementale · Isolation Forest")
    st.write("L'IA compare les caractéristiques de chaque fenêtre temporelle à sa distribution d'entraînement. Elle ne reconnaît pas une attaque par son nom.")
    if predictions.empty or "anomaly_score" not in predictions:
        st.info("Pas de prédiction exploitable.")
    else:
        chart = predictions.copy()
        chart["window_start"] = pd.to_datetime(chart["window_start"], utc=True, errors="coerce")
        chart = chart.dropna(subset=["window_start"])
        st.line_chart(chart.set_index("window_start")["anomaly_score"], height=260)
        st.caption("Score négatif : anomalie statistique. Score positif ou nul : non signalée. Les scores de modèles différents ne se comparent pas directement.")
        decisions = predictions.copy()
        decisions["Décision"] = decisions["prediction"].replace({"NORMAL": "Non signalée", "ANOMALY": "Anomalie"})
        display_frame(decisions, ["window_start", "event_count", "anomaly_score", "Décision"], {"window_start": "Fenêtre UTC", "event_count": "Événements", "anomaly_score": "Score IA"})

with activity_tab:
    st.subheader("Activité Linux observée")
    activity = [{"Signal": label, "Nombre": int(dataset[key].sum())} for key, label in FEATURE_LABEL.items() if key in dataset.columns]
    if activity:
        st.bar_chart(pd.DataFrame(activity).set_index("Signal")["Nombre"], height=275)
        st.dataframe(pd.DataFrame(activity), hide_index=True, use_container_width=True)
    else:
        st.info("Aucune caractéristique d'activité disponible.")
    with st.expander("Voir les données brutes des fenêtres IA"):
        st.dataframe(dataset.rename(columns=FEATURE_LABEL), hide_index=True, use_container_width=True)
    st.caption("Les capteurs ne couvrent pas tous les événements Linux. Par exemple, une modification de permissions peut ne pas apparaître si la politique Tetragon ne la capture pas.")

with history_tab:
    st.subheader("Historique des sessions")
    st.write("Chaque cycle de surveillance crée un dossier distinct. Clique sur une session dans la barre latérale pour l'examiner.")
    history = []
    for path in sessions[:50]:
        summary_path = path.parent / "summary.json" if path.name == "analysis" else None
        summary = {}
        if summary_path and summary_path.is_file():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        history.append({
            "Session": session_name(path),
            "Événements": summary.get("events", "—"),
            "Alertes": summary.get("hybrid_alerts", "—"),
            "À examiner": summary.get("reviews", "—"),
        })
    st.dataframe(pd.DataFrame(history), hide_index=True, use_container_width=True)
    st.caption("Les anciennes sessions sans summary.json peuvent afficher — pour certains compteurs.")

with guide_tab:
    st.subheader("Que faire lorsqu'une activité paraît suspecte ?")
    procedures = [
        ("1 · Qualifier", "Note l'heure, la priorité, la règle, le score IA et la justification. Une anomalie statistique n'est pas une attaque confirmée."),
        ("2 · Identifier", "Recherche le programme, son PID, son UID, son parent, ses arguments et les connexions observables. Consulte les événements de la capture si nécessaire."),
        ("3 · Reconstituer", "Cherche une succession d'actions inhabituelles. R7 recherche une séquence spécifique ; une simple proximité temporelle ne suffit pas à prouver la causalité."),
        ("4 · Contenir si nécessaire", "Si la compromission paraît crédible, conserve les preuves puis envisage l'isolement de l'hôte avec l'autorisation adaptée. Ce prototype ne bloque rien automatiquement."),
        ("5 · Documenter", "Conserve l'heure, le scénario, les données observées, les vérifications réalisées, les captures d'écran et une conclusion prudente."),
    ]
    for heading, instructions in procedures:
        with st.expander(heading):
            st.write(instructions)
    st.markdown("#### Couverture actuelle des règles")
    display_frame(pd.DataFrame([{"Règle": rule, "Comportement": label} for rule, label in RULE_NAMES.items()]), ["Règle", "Comportement"])
    st.markdown('<div class="soc-action"><b>Important :</b> Zero-Day Hunter identifie certains comportements potentiellement associés à une exploitation inconnue. Il ne prouve pas qu’une vulnérabilité zero-day a été exploitée.</div>', unsafe_allow_html=True)

st.markdown("---")
st.caption("ZERO-DAY HUNTER · Prototype académique · Collecte par cycles · Pas de détection garantie, ni réaction ou blocage automatique")
