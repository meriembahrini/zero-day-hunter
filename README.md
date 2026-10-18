# Zero-Day Hunter

### Behavioral Threat Detection on Linux using eBPF, Tetragon and Machine Learning

Zero-Day Hunter is an experimental Linux security monitoring system developed as an academic cybersecurity project at Polytech Dijon.

It combines kernel-level observability, behavioral detection rules, and unsupervised machine learning to identify potentially suspicious system activities.

> **Disclaimer:** Zero-Day Hunter does not directly discover zero-day vulnerabilities. It detects behaviors that may accompany security incidents.

## Architecture

```text
Linux System
     |
     v
Tetragon + eBPF
     |
     v
Event Collection (JSONL)
     |
     +-----------------------+
     |                       |
     v                       v
Behavioral Rules         Feature Extraction
    R1-R7                 (30-second windows)
     |                       |
     |                       v
     |                 Isolation Forest
     |                       |
     +-----------+-----------+
                 |
                 v
          Hybrid Detection
                 |
                 v
       Alerts and Observations
                 |
                 v
          Streamlit Dashboard
```

## Main Features

- Linux runtime monitoring using Tetragon and eBPF
- Seven behavioral detection rules (R1-R7)
- Temporal correlation of suspicious activities
- Anomaly detection using Isolation Forest
- Hybrid alert classification: RULE_ONLY, AI_ONLY, HYBRID
- Separation of security alerts and REVIEW observations
- Automated collection and analysis cycles
- Interactive Streamlit SOC dashboard
- Historical monitoring sessions

## Detection Rules

| Rule | Description |
|------|-------------|
| R1 | Sensitive file access |
| R2 | Dangerous permission changes |
| R3 | Shell execution initiated by a web server |
| R4 | Unusual administrative tool usage |
| R5 | Root process execution and review |
| R6 | Unusual TCP connection |
| R7 | Correlation of suspicious event sequences |

## Machine Learning

The project uses Isolation Forest from scikit-learn.

Events are grouped into 30-second windows and transformed into seven numerical behavioral features.

Two experimental models are highlighted:

- **V4:** Default model used in the monitoring pipeline.
- **V5:** Experimental model trained on a more diverse dataset of normal activities.

V5 detected some anomalies missed by V4, but also produced more false positives in a small normal-activity evaluation.

## Experimental Scenarios

### S1 — Simulated Web Compromise

A controlled web server executes a shell, accesses a synthetic sensitive file, and initiates a local TCP connection.

**Result:** Behavioral rules identify the sequence, including a critical R7 correlation. V4 also detects anomalous windows.

### S2 — Dangerous Permission Changes

A test file undergoes several permission changes, including `chmod 777`.

**Result:** Rule R2 detects the dangerous permission change, while V4 does not flag an anomaly.

### S3 — Simulated System Reconnaissance

A Python script executes 18 system reconnaissance commands.

**Result:** V5 identifies a statistical anomaly that is not flagged by V4 or the behavioral rules.

All experiments were conducted in a controlled laboratory environment.

## Project Structure

```text
zero-day-hunter/
|-- collector/        Event collection and normalization
|-- detection/        Rules R1-R7 and hybrid engine
|-- ml/               Feature extraction and ML models
|-- policies/         Tetragon tracing policies
|-- dashboard/        Streamlit interface
|-- lab/              Controlled test scenarios
|-- main.py           Main analysis pipeline
|-- run_monitor.py    Automated monitoring cycles
|-- requirements.txt  Python dependencies
|-- README.md         Project documentation
```

## Requirements

- Linux with compatible eBPF capabilities
- Tetragon installed and configured
- Python 3
- Dependencies listed in `requirements.txt`
- Appropriate permissions for event collection
- A trained Isolation Forest model

Development environment: Ubuntu Server 24.04 ARM64 running in VirtualBox.

## Installation

Clone the repository:

```bash
git clone https://github.com/meriembahrini/zero-day-hunter.git
cd zero-day-hunter
```

Create a Python environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Tetragon must be installed separately and the relevant tracing policies must be activated.

Trained model files and raw monitoring datasets are not included in the public source distribution.

## Usage

Run a 60-second monitoring cycle:

```bash
python run_monitor.py --duration 60 --cycles 1
```

Launch the dashboard:

```bash
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

On a remote machine, use SSH port forwarding to access the dashboard securely.

## Limitations

- Experimental prototype, not production-ready
- No guarantee of detecting real zero-day exploits
- Limited training and evaluation datasets
- Potential false positives
- Detection coverage depends on configured Tetragon policies
- Monitoring is performed in collection and analysis cycles
- No automated blocking or incident response

## Future Improvements

- Continuous event processing
- Larger and more diverse training datasets
- Improved behavioral correlation
- Additional detection rules and evaluation scenarios
- AI-assisted SOC investigation agent
- Better alert prioritization and investigation workflows

## Authors

- Meriem Bahrini
- Stéphanie Fares Eid

Polytech Dijon — Informatique et Réseaux (SQR)

Academic Year: 2026-2027

## Disclaimer

This project is intended for educational and defensive cybersecurity research.

All scenarios use simulated activities in a controlled laboratory environment.
