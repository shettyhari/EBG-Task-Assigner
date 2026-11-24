import http.server
import json
import os
import socketserver
import sys
import threading
import urllib.request

PORT = 8090
DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(DIR, "data.json")

def dispatch_whatsapp_webhook(tasks, members):
    webhook_url = os.environ.get("WHATSAPP_WEBHOOK_URL")
    if not webhook_url:
        return
    for t in tasks:
        try:
            assignee_phone = ""
            for m in members:
                if m.get("uid") == t.get("assigneeId"):
                    assignee_phone = m.get("phone", "")
                    break
            payload = json.dumps({
                "event": "task_alert",
                "taskId": t.get("code"),
                "title": t.get("title"),
                "department": t.get("tag"),
                "assignee": t.get("assigneeName"),
                "assigneePhone": assignee_phone,
                "priority": t.get("priority"),
                "status": t.get("status"),
                "dueDate": t.get("dueDate"),
                "scheduledDate": t.get("scheduledDate", "")
            }).encode("utf-8")
            req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            print(f"[WhatsApp Webhook] Dispatched alert for {t.get('code')} to {webhook_url}")
        except Exception as e:
            print("[WhatsApp Webhook Error]:", e)

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print("Error loading data.json:", e)
    return {"organizations": {}, "members": [], "tasks": [], "users": {}}

def save_data(data):
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print("Error saving data.json:", e)

class EBGHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/api/data"):
            data = load_data()
            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/data"):
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length).decode("utf-8")
                patch = json.loads(body)
                current = load_data()

                if "organizations" in patch and isinstance(patch["organizations"], dict):
                    current["organizations"].update(patch["organizations"])

                if "members" in patch and isinstance(patch["members"], list):
                    existing = {m.get("uid") for m in current["members"] if m.get("uid")}
                    for m in patch["members"]:
                        if m.get("uid") in existing:
                            current["members"] = [x if x.get("uid") != m.get("uid") else m for x in current["members"]]
                        else:
                            current["members"].append(m)

                if "tasks" in patch and isinstance(patch["tasks"], list):
                    existing = {t.get("id") for t in current["tasks"] if t.get("id")}
                    for t in patch["tasks"]:
                        if t.get("id") in existing:
                            current["tasks"] = [x if x.get("id") != t.get("id") else t for x in current["tasks"]]
                        else:
                            current["tasks"].append(t)

                if "deleteTaskId" in patch:
                    current["tasks"] = [t for t in current["tasks"] if t.get("id") != patch["deleteTaskId"]]

                if "users" in patch and isinstance(patch["users"], dict):
                    current["users"].update(patch["users"])

                save_data(current)

                if "tasks" in patch and isinstance(patch["tasks"], list) and patch["tasks"]:
                    threading.Thread(target=dispatch_whatsapp_webhook, args=(patch["tasks"], current.get("members", []))).start()
                response = json.dumps({"success": True, "data": current}, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except Exception as err:
                err_resp = json.dumps({"success": False, "error": str(err)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(err_resp)))
                self.end_headers()
                self.wfile.write(err_resp)
            return
        super().do_POST()

def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), EBGHandler) as httpd:
        print(f"EBG Server with shared sync API running at http://localhost:{PORT}")
        sys.stdout.flush()
        httpd.serve_forever()

if __name__ == "__main__":
    run()
