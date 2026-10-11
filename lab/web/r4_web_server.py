from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import subprocess

SECRET = Path.home() / "zero-day-hunter/lab/secrets.txt"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):

        if self.path == "/health":
            message = "Serveur OK"

        elif self.path == "/simulate":
            subprocess.run(
                ["/bin/sh", "-c", "printf 'Simulation R4 OK\n'"],
                check=True
            )
            message = "Simulation R4 terminee"

        elif self.path == "/chain":
            commande = (
                f"cat '{SECRET}' > /dev/null && "
                "curl -fsS http://127.0.0.1:9090/ > /dev/null"
            )

            subprocess.run(
                ["/bin/sh", "-c", commande],
                check=True
            )
            message = "Simulation R14 terminee"

        else:
            self.send_error(404)
            return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(message.encode())

server = HTTPServer(("127.0.0.1", 8081), Handler)
print("Serveur R4/R14 sur le port 8081", flush=True)
server.serve_forever()
