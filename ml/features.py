
import json
import sys
from pathlib import Path


SHELLS = {
    "sh", "bash", "dash", "zsh", "fish", "ksh"
}


def extract_features(events):

    features = {
        "process_exec_count": 0,
        "process_exit_count": 0,
        "network_connect_count": 0,
        "chmod_count": 0,
        "dangerous_chmod_count": 0,
        "unique_binary_count": 0,
        "shell_exec_count": 0,
        "unique_destination_port_count": 0
    }

    binaries = set()
    destination_ports = set()

    for event in events:

        event_type = event.get("event_type")

        if event_type == "process_exec":
            features["process_exec_count"] += 1

            process = event.get("process") or {}
            binary = process.get("binary")

            if binary:
                binaries.add(binary)

                binary_name = Path(binary).name

                if binary_name in SHELLS:
                    features["shell_exec_count"] += 1

        elif event_type == "process_exit":
            features["process_exit_count"] += 1

        elif event_type == "process_kprobe":

            function_name = event.get("function_name")

            if function_name == "tcp_connect":

                features["network_connect_count"] += 1

                for arg in event.get("args") or []:
                    sock = arg.get("sock_arg")

                    if isinstance(sock, dict):
                        port = sock.get("dport")

                        if port is not None:
                            destination_ports.add(port)

            elif function_name == "security_path_chmod":

                features["chmod_count"] += 1

                for arg in event.get("args") or []:

                    if "uint_arg" in arg:
                        mode = arg["uint_arg"]

                        if isinstance(mode, int) and mode & 0o002:
                            features["dangerous_chmod_count"] += 1

    features["unique_binary_count"] = len(binaries)

    features["unique_destination_port_count"] = len(
        destination_ports
    )

    return features


def main():

    if len(sys.argv) != 2:
        print("Usage: python3 ml/features.py fichier.jsonl")
        sys.exit(1)

    input_path = Path(sys.argv[1])

    with input_path.open("r", encoding="utf-8") as f:
        events = [
            json.loads(line)
            for line in f
            if line.strip()
        ]

    features = extract_features(events)

    print(json.dumps(features, indent=4))


if __name__ == "__main__":
    main()
