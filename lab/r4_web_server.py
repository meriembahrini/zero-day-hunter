
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess

PROJECT = Path.home() / "zero-day-hunter"
SECRET = PROJECT / "lab/secrets.txt"

class LabHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Lab server OK")
            return

        if self.path == "/simulate":
            # Simulation fixe, sans commande fournie par le client.
            script = (
                'cat "$1" >/dev/null; '
                'python3 -c '
                '\'import socket; s=socket.socket(); '
                's.settimeout(2); '
                's.connect(("127.0.0.1",9090)); s.close()\''
            )

            try:
                result = subprocess.run(
                    ["/bin/sh", "-c", script, "lab", str(SECRET)],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                message = (
                    f"Simulation terminee (code={result.returncode})"
                )
            except subprocess.TimeoutExpired:
                message = "Simulation interrompue (timeout)"

            self.send_response(200)
            self.end_headers()
            self.wfile.write(message.encode())
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8088), LabHandler)
    print("Serveur de laboratoire : http://127.0.0.1:8088", flush=True)
    server.serve_forever()
