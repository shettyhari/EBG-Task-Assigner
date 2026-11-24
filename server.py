import hashlib
import hmac
import http.server
import json
import os
import secrets
import socketserver
import sys
import threading
import time
import urllib.request

PORT = 8090
DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(DIR, "data.json")
PUBLIC_FILES = {"/", "/index.html"}

ALLOWED_DOMAIN = "@theebg.com"
ORG_ID = "EBG-GROUP"
ORG_NAME = "EBG Group"
MIN_PASSWORD_LEN = 6
SESSION_TTL_SECONDS = 7 * 24 * 3600
PBKDF2_ITERATIONS = 200_000
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 5 * 60
MAX_BODY_BYTES = 5 * 1024 * 1024

# In-memory session store: token -> {"email": str, "expires": float}.
# Sessions are cleared when the server restarts (everyone signs in again).
SESSIONS = {}
# email -> {"count": int, "until": float}
FAILED_LOGINS = {}


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def migrate_plaintext_passwords(data):
    """Replace any legacy plaintext `password` fields with a salted hash. Returns True if changed."""
    changed = False
    for rec in data.get("users", {}).values():
        if not isinstance(rec, dict):
            continue
        if "password" in rec:
            plain = rec.pop("password")
            if plain and not rec.get("passwordHash"):
                rec["passwordHash"] = hash_password(str(plain))
            changed = True
    return changed


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------
def load_data():
    # If data.json exists but cannot be read, raise instead of returning an empty
    # workspace: an empty result would be saved back by the next POST and wipe all data.
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {}
    for key, default in (("organizations", {}), ("members", []), ("tasks", []), ("users", {})):
        if not isinstance(data.get(key), type(default)):
            data[key] = default
    return data


def save_data(data):
    # Write to a temp file then atomically replace, so a crash mid-write cannot corrupt data.json
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, DATA_FILE)


def norm_email(email):
    return str(email or "").strip().lower()


def find_member(data, uid=None, email=None):
    for m in data["members"]:
        if not isinstance(m, dict):
            continue
        if uid and m.get("uid") == uid:
            return m
        if email and norm_email(m.get("email")) == email:
            return m
    return None


def effective_role(user, member):
    if member and member.get("role"):
        return member["role"]
    return (user or {}).get("role") or "Member"


def is_suspended(user, member):
    user = user or {}
    member = member or {}
    return (
        user.get("status") == "suspended"
        or user.get("accountStatus") == "suspended"
        or (user.get("profile") or {}).get("accountStatus") == "suspended"
        or member.get("accountStatus") == "suspended"
    )


def public_user(rec):
    """A user record with all credential fields removed."""
    out = {k: v for k, v in rec.items() if k not in ("password", "passwordHash")}
    return out


def profile_for(data, email):
    user = data["users"].get(email) or {}
    member = find_member(data, uid=user.get("uid"), email=email)
    base = dict(user.get("profile") or {})
    if member:
        base.update(member)
    base.setdefault("uid", user.get("uid"))
    base.setdefault("email", email)
    base.setdefault("displayName", user.get("displayName") or email.split("@")[0])
    base.setdefault("role", user.get("role") or "Member")
    base.setdefault("department", user.get("department") or "Performance Marketing")
    base.setdefault("phone", user.get("phone") or "")
    base.setdefault("orgId", ORG_ID)
    base.setdefault("orgName", ORG_NAME)
    return base


def view_for(data, is_admin):
    """What the requester is allowed to see. Passwords are never included."""
    return {
        "organizations": data["organizations"],
        "members": data["members"],
        "tasks": data["tasks"],
        # Only Admins need account status for the management console
        "users": {e: public_user(u) for e, u in data["users"].items() if isinstance(u, dict)} if is_admin else {},
    }


def revoke_sessions(email, keep_token=None):
    for token in [t for t, s in SESSIONS.items() if s["email"] == email and t != keep_token]:
        del SESSIONS[token]


def new_session(email):
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {"email": email, "expires": time.time() + SESSION_TTL_SECONDS}
    return token


def has_admin(data):
    return any(isinstance(m, dict) and m.get("role") == "Admin" and m.get("accountStatus") != "suspended" for m in data["members"])


def new_uid():
    return "usr_" + secrets.token_hex(6)


def create_account(data, email, password, display_name, department, role, phone):
    uid = new_uid()
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    member = {
        "uid": uid,
        "displayName": display_name,
        "email": email,
        "role": role,
        "department": department,
        "phone": phone,
        "orgId": ORG_ID,
        "orgName": ORG_NAME,
        "status": "online",
        "accountStatus": "active",
        "joinedAt": now,
    }
    data["users"][email] = {
        "uid": uid,
        "email": email,
        "passwordHash": hash_password(password),
        "displayName": display_name,
        "department": department,
        "role": role,
        "phone": phone,
        "status": "active",
        "profile": dict(member),
    }
    data["members"].append(member)
    data["organizations"].setdefault(ORG_ID, {"orgId": ORG_ID, "orgName": ORG_NAME, "createdAt": now})
    return member


def validate_new_account(data, body):
    email = norm_email(body.get("email"))
    password = str(body.get("password") or "")
    display_name = str(body.get("displayName") or "").strip()
    if not email.endswith(ALLOWED_DOMAIN) or len(email) <= len(ALLOWED_DOMAIN):
        return None, "Only official @theebg.com email addresses are permitted."
    if len(password) < MIN_PASSWORD_LEN:
        return None, f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if not display_name:
        return None, "Full name is required."
    if email in data["users"] or find_member(data, email=email):
        return None, "An account with this email already exists. Please Sign In."
    return {
        "email": email,
        "password": password,
        "display_name": display_name,
        "department": str(body.get("department") or "Performance Marketing"),
        "role": str(body.get("role") or "Member"),
        "phone": str(body.get("phone") or "").strip(),
    }, None


# ---------------------------------------------------------------------------
# WhatsApp webhook
# ---------------------------------------------------------------------------
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


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


# Member fields only an Admin may change
ADMIN_ONLY_MEMBER_FIELDS = ("role", "department", "accountStatus", "email", "uid", "orgId")
# Task fields set by the server, never trusted from the client
SERVER_TASK_FIELDS = ("createdBy", "createdByName", "createdAt", "orgId")


class EBGHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    # ---- helpers ---------------------------------------------------------
    def send_json(self, status, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "Request too large")
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            raise ApiError(400, "Invalid JSON")
        if not isinstance(body, dict):
            raise ApiError(400, "Request body must be a JSON object")
        return body

    def bearer_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def require_session(self, data):
        """Returns (token, email, user, member, is_admin) or raises 401."""
        token = self.bearer_token()
        sess = SESSIONS.get(token) if token else None
        if not sess or sess["expires"] < time.time():
            SESSIONS.pop(token, None)
            raise ApiError(401, "Please sign in again.")
        email = sess["email"]
        user = data["users"].get(email)
        member = find_member(data, uid=(user or {}).get("uid"), email=email)
        if not user:
            SESSIONS.pop(token, None)
            raise ApiError(401, "Account no longer exists.")
        if is_suspended(user, member):
            revoke_sessions(email)
            raise ApiError(401, "Your login access has been suspended by the workspace Admin. Please contact Admin.")
        return token, email, user, member, effective_role(user, member) == "Admin"

    def path_only(self):
        return self.path.split("?", 1)[0].split("#", 1)[0]

    # ---- routing ---------------------------------------------------------
    def do_GET(self):
        path = self.path_only()
        if path.startswith("/api/"):
            try:
                data = load_data()
                _, email, _, _, is_admin = self.require_session(data)
                if path == "/api/me":
                    self.send_json(200, {"success": True, "profile": profile_for(data, email)})
                elif path == "/api/data":
                    self.send_json(200, view_for(data, is_admin))
                else:
                    raise ApiError(404, "Not found")
            except ApiError as e:
                self.send_json(e.status, {"success": False, "error": e.message})
            except Exception as e:
                print("GET error:", e)
                self.send_json(500, {"success": False, "error": "Server error"})
            return
        # Only serve the app itself. Never expose data.json, server.py or .git
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
        path = self.path_only()
        routes = {
            "/api/login": self.api_login,
            "/api/register": self.api_register,
            "/api/logout": self.api_logout,
            "/api/admin/reset-password": self.api_admin_reset_password,
            "/api/admin/provision": self.api_admin_provision,
            "/api/data": self.api_data,
        }
        handler = routes.get(path)
        if not handler:
            self.send_json(404, {"success": False, "error": "Not found"})
            return
        try:
            body = self.read_body()
            data = load_data()
            status, result = handler(body, data)
            self.send_json(status, result)
        except ApiError as e:
            self.send_json(e.status, {"success": False, "error": e.message})
        except Exception as e:
            print("POST error:", e)
            self.send_json(500, {"success": False, "error": "Server error"})

    # ---- auth endpoints --------------------------------------------------
    def api_login(self, body, data):
        email = norm_email(body.get("email"))
        password = str(body.get("password") or "")
        if not email.endswith(ALLOWED_DOMAIN):
            raise ApiError(400, "Access restricted: Only official @theebg.com email addresses are permitted.")

        lock = FAILED_LOGINS.get(email)
        if lock and lock.get("until", 0) > time.time():
            mins = int((lock["until"] - time.time()) // 60) + 1
            raise ApiError(429, f"Too many failed attempts. Try again in {mins} minute(s).")

        user = data["users"].get(email)
        if not user or not user.get("passwordHash") or not verify_password(password, user["passwordHash"]):
            rec = FAILED_LOGINS.setdefault(email, {"count": 0, "until": 0})
            rec["count"] += 1
            if rec["count"] >= MAX_FAILED_LOGINS:
                rec["count"] = 0
                rec["until"] = time.time() + LOCKOUT_SECONDS
            if user and not user.get("passwordHash"):
                raise ApiError(401, "This account has no password set. Ask the workspace Admin to reset your password.")
            # Same message for unknown email and wrong password
            raise ApiError(401, "Incorrect email or password.")

        member = find_member(data, uid=user.get("uid"), email=email)
        if is_suspended(user, member):
            raise ApiError(403, "Your login access has been suspended by the workspace Admin. Please contact Admin.")

        FAILED_LOGINS.pop(email, None)
        token = new_session(email)
        return 200, {"success": True, "token": token, "profile": profile_for(data, email)}

    def api_register(self, body, data):
        fields, err = validate_new_account(data, body)
        if err:
            raise ApiError(400, err)
        # Self-registration may only create an Admin when the workspace has none yet
        if fields["role"] == "Admin" and has_admin(data):
            raise ApiError(403, "Admin accounts can only be granted by an existing Admin. Please pick your team role.")
        create_account(data, fields["email"], fields["password"], fields["display_name"],
                       fields["department"], fields["role"], fields["phone"])
        save_data(data)
        token = new_session(fields["email"])
        return 200, {"success": True, "token": token, "profile": profile_for(data, fields["email"])}

    def api_logout(self, body, data):
        SESSIONS.pop(self.bearer_token(), None)
        return 200, {"success": True}

    def api_admin_reset_password(self, body, data):
        token, _, _, _, is_admin = self.require_session(data)
        if not is_admin:
            raise ApiError(403, "Admin privilege required.")
        email = norm_email(body.get("email"))
        new_password = str(body.get("newPassword") or "")
        if len(new_password) < MIN_PASSWORD_LEN:
            raise ApiError(400, f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        user = data["users"].get(email)
        if not user:
            member = find_member(data, email=email)
            if not member:
                raise ApiError(404, "No member with this email.")
            # Member without a login record yet: create one
            user = {
                "uid": member.get("uid") or new_uid(),
                "email": email,
                "displayName": member.get("displayName") or email.split("@")[0],
                "department": member.get("department") or "Performance Marketing",
                "role": member.get("role") or "Member",
                "phone": member.get("phone") or "",
                "status": "active",
                "profile": dict(member),
            }
            data["users"][email] = user
        user["passwordHash"] = hash_password(new_password)
        user.pop("password", None)
        save_data(data)
        revoke_sessions(email, keep_token=token)
        FAILED_LOGINS.pop(email, None)
        return 200, {"success": True}

    def api_admin_provision(self, body, data):
        _, _, _, _, is_admin = self.require_session(data)
        if not is_admin:
            raise ApiError(403, "Admin privilege required.")
        fields, err = validate_new_account(data, body)
        if err:
            raise ApiError(400, err)
        member = create_account(data, fields["email"], fields["password"], fields["display_name"],
                                fields["department"], fields["role"], fields["phone"])
        save_data(data)
        return 200, {"success": True, "member": member, "data": view_for(data, True)}

    # ---- shared data endpoint ---------------------------------------------
    def api_data(self, patch, data):
        token, my_email, my_user, my_member, is_admin = self.require_session(data)
        my_uid = (my_member or {}).get("uid") or my_user.get("uid")
        my_name = (my_member or {}).get("displayName") or my_user.get("displayName") or my_email
        changed_tasks = []

        if isinstance(patch.get("organizations"), dict):
            if not is_admin:
                raise ApiError(403, "Admin privilege required to change workspace settings.")
            data["organizations"].update({k: v for k, v in patch["organizations"].items() if isinstance(v, dict)})

        if isinstance(patch.get("members"), list):
            for m in patch["members"]:
                if not isinstance(m, dict) or not m.get("uid"):
                    continue
                existing = find_member(data, uid=m["uid"])
                if not is_admin:
                    if m["uid"] != my_uid or not existing:
                        raise ApiError(403, "You can only update your own profile.")
                    m = dict(m)
                    for field in ADMIN_ONLY_MEMBER_FIELDS:
                        if field in existing:
                            m[field] = existing[field]
                        else:
                            m.pop(field, None)
                if existing:
                    if norm_email(m.get("email")) != norm_email(existing.get("email")):
                        m = dict(m, email=existing.get("email"))  # email is the login id: immutable
                    existing.clear()
                    existing.update(m)
                else:
                    email = norm_email(m.get("email"))
                    if not email.endswith(ALLOWED_DOMAIN) or find_member(data, email=email):
                        continue
                    data["members"].append(m)

        if isinstance(patch.get("tasks"), list):
            by_id = {t.get("id"): t for t in data["tasks"] if isinstance(t, dict)}
            for t in patch["tasks"]:
                if not isinstance(t, dict) or not t.get("id"):
                    continue
                existing = by_id.get(t["id"])
                t = dict(t)
                if existing:
                    for field in SERVER_TASK_FIELDS:
                        if field in existing:
                            t[field] = existing[field]
                    existing.clear()
                    existing.update(t)
                else:
                    t["createdBy"] = my_uid
                    t["createdByName"] = my_name
                    t["orgId"] = ORG_ID
                    t.setdefault("createdAt", time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()))
                    data["tasks"].append(t)
                    by_id[t["id"]] = t
                changed_tasks.append(t)

        if patch.get("deleteTaskId"):
            target = next((t for t in data["tasks"] if isinstance(t, dict) and t.get("id") == patch["deleteTaskId"]), None)
            if target:
                if not is_admin and target.get("createdBy") != my_uid:
                    raise ApiError(403, "Only the task creator or an Admin can delete this task.")
                data["tasks"] = [t for t in data["tasks"] if t is not target]

        if patch.get("deleteMemberUid") or patch.get("deleteUserEmail"):
            if not is_admin:
                raise ApiError(403, "Admin privilege required.")
            del_uid = patch.get("deleteMemberUid")
            del_email = norm_email(patch.get("deleteUserEmail"))
            if del_uid == my_uid or del_email == my_email:
                raise ApiError(400, "You cannot delete your own account.")
            if del_uid:
                gone = find_member(data, uid=del_uid)
                if gone:
                    del_email = del_email or norm_email(gone.get("email"))
                data["members"] = [m for m in data["members"] if not (isinstance(m, dict) and m.get("uid") == del_uid)]
            if del_email:
                data["users"].pop(del_email, None)
                data["members"] = [m for m in data["members"] if not (isinstance(m, dict) and norm_email(m.get("email")) == del_email)]
                revoke_sessions(del_email)

        if isinstance(patch.get("users"), dict):
            if not is_admin:
                raise ApiError(403, "Admin privilege required.")
            for email, rec in patch["users"].items():
                email = norm_email(email)
                if not isinstance(rec, dict) or email not in data["users"]:
                    continue  # new logins go through /api/register or /api/admin/provision
                rec = {k: v for k, v in rec.items() if k not in ("password", "passwordHash", "email", "uid")}
                data["users"][email].update(rec)
                if rec.get("status") == "suspended":
                    if email == my_email:
                        raise ApiError(400, "You cannot suspend your own account.")
                    revoke_sessions(email)

        if not has_admin(data):
            raise ApiError(400, "The workspace must keep at least one active Admin.")

        save_data(data)

        if changed_tasks:
            threading.Thread(target=dispatch_whatsapp_webhook, args=(changed_tasks, data["members"]), daemon=True).start()
        return 200, {"success": True, "data": view_for(data, is_admin)}


def run():
    # One-time upgrade: hash any plaintext passwords left in data.json
    try:
        data = load_data()
        if migrate_plaintext_passwords(data):
            save_data(data)
            print("Upgraded plaintext passwords in data.json to salted hashes.")
    except Exception as e:
        print("Could not check data.json for plaintext passwords:", e)

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), EBGHandler) as httpd:
        print(f"EBG Server with shared sync API running at http://localhost:{PORT}")
        sys.stdout.flush()
        httpd.serve_forever()


if __name__ == "__main__":
    run()
