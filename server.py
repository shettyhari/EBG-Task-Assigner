"""EBG Task Assigner - local server.

Run on a PC with:  python server.py   (or double-click start-server.bat)
Serves index.html and the API at http://localhost:8090, storing data in data.json.

The same API runs on Vercel through api/index.py, storing data in Upstash Redis.
All rules live in api/_ebg_core.py.
"""
import http.server
import json
import os
import socketserver
import sys
import webbrowser

DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(DIR, "api"))
from _ebg_core import Api, FileStorage, Result, upgrade_data  # noqa: E402

PORT = int(os.environ.get("EBG_PORT", "8090"))
PUBLIC_FILES = {"/", "/index.html"}

STORAGE = FileStorage(DIR)
API = Api(STORAGE, background_webhooks=True)


class EBGHandler(http.server.SimpleHTTPRequestHandler):
    timeout = 30  # seconds; drop idle or stalled connections

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def log_message(self, fmt, *args):
        # Keep the console readable: skip the browser's routine background refreshes
        if len(args) > 1 and str(args[1]) == "200" and str(args[0]).startswith("GET /api/data"):
            return
        super().log_message(fmt, *args)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def path_only(self):
        return self.path.split("?", 1)[0].split("#", 1)[0]

    def send_api(self, method):
        body = b""
        if method == "POST":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(min(length, 6 * 1024 * 1024)) if length else b""
        status, payload = API.handle(method, self.path_only(), self.headers, body, self.client_address[0])
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path_only()
        if path.startswith("/api/"):
            self.send_api("GET")
            return
        # Only serve the app itself. Never expose data.json, sessions.json, server code or .git
        if path not in PUBLIC_FILES:
            self.send_error(404)
            return
        super().do_GET()

    def do_HEAD(self):
        if self.path_only() not in PUBLIC_FILES:
            self.send_error(404)
            return
        super().do_HEAD()

    def do_POST(self):
        if self.path_only().startswith("/api/"):
            self.send_api("POST")
        else:
            self.send_error(404)


class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # One slow or idle browser connection must not block everyone else's requests
    daemon_threads = True


def run():
    try:
        def upgrade(data):
            result = Result()
            result.changed = upgrade_data(data)  # hash old plaintext passwords, add task history
            return result
        STORAGE.transact(upgrade)
    except Exception as e:
        print("Could not read data.json:", e)
        sys.exit(1)

    # On Windows SO_REUSEADDR lets a second server bind the same port. Refuse instead.
    socketserver.TCPServer.allow_reuse_address = os.name != "nt"
    try:
        httpd = ThreadingServer(("", PORT), EBGHandler)
    except OSError:
        print(f"Port {PORT} is already in use: the EBG server is probably already running. "
              f"Close the other server window first, then start this one again.")
        sys.exit(1)
    with httpd:
        print(f"EBG Server running at http://localhost:{PORT}")
        print("Keep this window open while the team uses the app. Press Ctrl+C to stop.")
        sys.stdout.flush()
        if "--open" in sys.argv:
            webbrowser.open(f"http://localhost:{PORT}/")
        httpd.serve_forever()


if __name__ == "__main__":
    run()
