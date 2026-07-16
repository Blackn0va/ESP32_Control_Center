#!/usr/bin/env python3
"""Lokaler Server fuer das Marauder Control Center.

Serviert index.html UND proxyt Firmware-Downloads von GitHub serverseitig.
Damit umgeht der Flash-Tab das CORS-/403-Problem der oeffentlichen Proxies:
der Browser holt die .bin von /proxy?url=..., dieser Server laedt sie und
reicht sie mit Access-Control-Allow-Origin durch.

Start:
    python serve.py            # http://localhost:8000
    python serve.py 9000       # anderer Port

Nur Python-3-Standardbibliothek, keine Abhaengigkeiten.
"""
import http.server
import socketserver
import urllib.request
import urllib.parse
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000

# Nur diese Host-Suffixe darf der Proxy laden (kein offener SSRF-Proxy).
ALLOWED_SUFFIXES = ("github.com", "githubusercontent.com")


def host_allowed(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in ALLOWED_SUFFIXES)


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/proxy?"):
            return self._proxy()
        return super().do_GET()

    def _proxy(self):
        qs = urllib.parse.urlparse(self.path).query
        url = urllib.parse.parse_qs(qs).get("url", [""])[0]
        host = urllib.parse.urlparse(url).hostname or ""

        # fail-closed: nur erlaubte Hosts, nur https
        if not url.lower().startswith("https://") or not host_allowed(host):
            self.send_error(403, "Host nicht erlaubt")
            return

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MCC-Proxy"})
            with urllib.request.urlopen(req, timeout=60) as up:
                data = up.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:  # explizit: Fehler an den Client melden, nicht schlucken
            self.send_error(502, "Proxy-Fehler: %s" % e)

    def end_headers(self):
        # statische Antworten ebenfalls CORS-frei fuer localhost-Nutzung
        if not self.path.startswith("/proxy?"):
            self.send_header("Access-Control-Allow-Origin", "*")
        super().end_headers()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        print("Marauder Control Center: http://localhost:%d" % PORT)
        print("Firmware-Proxy aktiv unter /proxy?url=... (nur github.com/githubusercontent.com)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nBeendet.")
