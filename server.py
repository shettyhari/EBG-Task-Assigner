"""EBG Task Assigner server.

Serves index.html and a small JSON API backed by data.json:
  - password hashing (PBKDF2) and server-side sessions (persisted in sessions.json)
  - role checks for every write
  - field-level task/member updates so concurrent edits don't overwrite each other
  - automatic release of scheduled tasks and creation of recurring occurrences
"""
import calendar
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import socketserver
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone

PORT = int(os.environ.get("EBG_PORT", "8090"))
DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(DIR, "data.json")
SESSIONS_FILE = os.path.join(DIR, "sessions.json")
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
MAX_TEXT = 5000

TASK_STATUSES = {"Scheduled", "To Do", "In Progress", "In Review", "Done"}
TASK_PRIORITIES = {"Low", "Medium", "High", "Urgent"}
RECURRENCES = {"none", "daily", "weekly", "biweekly", "monthly"}
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Task fields the client may set. Everything else is server-managed or ignored.
TASK_CLIENT_FIELDS = {
    "title", "description", "brand", "format", "tag", "priority", "status", "dueDate",
    "assigneeId", "assigneeName", "contentDriveUrl", "submissionDriveUrl",
    "submissionSubmittedAt", "submissionSubmittedBy", "isScheduled", "scheduledDate", "recurrence",
    "delegatedBy", "delegatedTo", "delegatedToUid", "delegatedAt", "delegationNote",
    "assignedByRole", "subtasks",
}
URL_FIELDS = {"contentDriveUrl", "submissionDriveUrl"}
MEMBER_SELF_FIELDS = {"displayName", "phone"}
MEMBER_ADMIN_FIELDS = {"displayName", "phone", "role", "department", "accountStatus"}

FAILED_LOGINS = {}  # (email, ip) -> {"count": int, "until": float}


def now_iso():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Passwords
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
    changed = False
    for rec in data["users"].values():
        if isinstance(rec, dict) and "password" in rec:
            plain = rec.pop("password")
            if plain and not rec.get("passwordHash"):
                rec["passwordHash"] = hash_password(str(plain))
            changed = True
    return changed


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def atomic_write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def load_data():
    # A read error raises instead of returning an empty workspace that would be saved back.
    data = {}
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    for key, default in (("organizations", {}), ("members", []), ("tasks", []), ("users", {})):
        if not isinstance(data.get(key), type(default)):
            data[key] = default
    data["members"] = [m for m in data["members"] if isinstance(m, dict)]
    data["tasks"] = [t for t in data["tasks"] if isinstance(t, dict)]
    return data


def save_data(data):
    atomic_write_json(DATA_FILE, data)


class SessionStore:
    """Sessions survive restarts. Only SHA-256 hashes of tokens are stored on disk."""

    def __init__(self, path):
        self.path = path
        self.sessions = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            now = time.time()
            self.sessions = {k: v for k, v in raw.items() if isinstance(v, dict) and v.get("expires", 0) > now}
        except (FileNotFoundError, ValueError):
            pass

    @staticmethod
    def _key(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _save(self):
        atomic_write_json(self.path, self.sessions)

    def create(self, email):
        token = secrets.token_urlsafe(32)
        self.sessions[self._key(token)] = {"email": email, "expires": time.time() + SESSION_TTL_SECONDS}
        self._save()
        return token

    def get(self, token):
        if not token:
            return None
        key = self._key(token)
        sess = self.sessions.get(key)
        if sess and sess["expires"] < time.time():
            del self.sessions[key]
            self._save()
            return None
        return sess

    def delete(self, token):
        if token and self.sessions.pop(self._key(token), None):
            self._save()

    def revoke_email(self, email, keep_token=None):
        keep = self._key(keep_token) if keep_token else None
        before = len(self.sessions)
        self.sessions = {k: v for k, v in self.sessions.items() if v["email"] != email or k == keep}
        if len(self.sessions) != before:
            self._save()


SESSIONS = SessionStore(SESSIONS_FILE)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------
def norm_email(email):
    return str(email or "").strip().lower()


def find_member(data, uid=None, email=None):
    for m in data["members"]:
        if uid and m.get("uid") == uid:
            return m
        if email and norm_email(m.get("email")) == email:
            return m
    return None


def find_task(data, task_id):
    return next((t for t in data["tasks"] if t.get("id") == task_id), None)


def effective_role(user, member):
    if member and member.get("role"):
        return member["role"]
    return (user or {}).get("role") or "Member"


def is_suspended(user, member):
    user = user or {}
    member = member or {}
    return (
        user.get("status") == "suspended"
        or member.get("accountStatus") == "suspended"
        or (user.get("profile") or {}).get("accountStatus") == "suspended"
    )


def has_admin(data):
    return any(m.get("role") == "Admin" and m.get("accountStatus") != "suspended" for m in data["members"])


def public_user(rec):
    return {k: v for k, v in rec.items() if k not in ("password", "passwordHash")}


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
    """What a signed-in user may see. Passwords are never included; account records only for Admins."""
    return {
        "organizations": data["organizations"],
        "members": data["members"],
        "tasks": data["tasks"],
        "users": {e: public_user(u) for e, u in data["users"].items() if isinstance(u, dict)} if is_admin else {},
    }


def sync_user_from_member(data, member):
    """Keep the login record consistent with the member record (role, status, name...)."""
    user = data["users"].get(norm_email(member.get("email")))
    if not user:
        return
    for field in ("displayName", "role", "department", "phone"):
        if field in member:
            user[field] = member[field]
    user["status"] = "suspended" if member.get("accountStatus") == "suspended" else "active"
    profile = user.setdefault("profile", {})
    profile.update({k: v for k, v in member.items()})


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def clean_text(value, limit=MAX_TEXT):
    return str(value if value is not None else "")[:limit]


def clean_url(value):
    url = str(value or "").strip()
    return url[:2000] if re.match(r"^https?://", url, re.I) else ""


def clean_date(value):
    value = str(value or "").strip()
    return value if re.match(r"^\d{4}-\d{2}-\d{2}$", value) else ""


def clean_datetime_local(value):
    value = str(value or "").strip()
    return value if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$", value) else ""


def clean_task_fields(raw):
    out = {}
    for key, value in raw.items():
        if key not in TASK_CLIENT_FIELDS:
            continue
        if key in URL_FIELDS:
            out[key] = clean_url(value)
        elif key == "status":
            if value in TASK_STATUSES:
                out[key] = value
        elif key == "priority":
            if value in TASK_PRIORITIES:
                out[key] = value
        elif key == "recurrence":
            out[key] = value if value in RECURRENCES else "none"
        elif key == "dueDate":
            out[key] = clean_date(value)
        elif key == "scheduledDate":
            out[key] = clean_datetime_local(value)
        elif key == "isScheduled":
            out[key] = bool(value)
        elif key == "subtasks":
            subs = []
            for s in value if isinstance(value, list) else []:
                if isinstance(s, dict) and str(s.get("text") or "").strip():
                    sid = str(s.get("id") or "")
                    subs.append({
                        "id": sid if ID_RE.match(sid) else "sub_" + secrets.token_hex(4),
                        "text": clean_text(s.get("text"), 500),
                        "done": bool(s.get("done")),
                    })
            out[key] = subs[:100]
        elif key in ("assigneeId", "delegatedToUid"):
            out[key] = str(value) if ID_RE.match(str(value or "")) else ""
        else:
            out[key] = clean_text(value)
    return out


# ---------------------------------------------------------------------------
# Scheduling & recurrence
# ---------------------------------------------------------------------------
def parse_local_dt(value):
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            pass
    return None


def add_interval(dt, recurrence):
    if recurrence == "daily":
        return dt + timedelta(days=1)
    if recurrence == "weekly":
        return dt + timedelta(weeks=1)
    if recurrence == "biweekly":
        return dt + timedelta(weeks=2)
    if recurrence == "monthly":
        month = dt.month % 12 + 1
        year = dt.year + (1 if dt.month == 12 else 0)
        day = min(dt.day, calendar.monthrange(year, month)[1])
        return dt.replace(year=year, month=month, day=day)
    return None


def next_task_code(data):
    highest = 0
    for t in data["tasks"]:
        m = re.match(r"^EBG-(\d+)$", str(t.get("code") or ""))
        if m:
            highest = max(highest, int(m.group(1)))
    return f"EBG-{highest + 1:03d}"


def set_status(task, status, at=None):
    at = at or now_iso()
    if task.get("status") == status and task.get("statusHistory"):
        return
    task["status"] = status
    task.setdefault("statusHistory", []).append({"status": status, "at": at})
    task["statusHistory"] = task["statusHistory"][-50:]
    if status == "Done":
        task["completedAt"] = at
    else:
        task.pop("completedAt", None)
    if status != "Scheduled":
        task["isScheduled"] = False


def release_due_tasks(data):
    """Move Scheduled tasks whose release time has passed to To Do, and queue the next
    occurrence of recurring ones. Returns the list of tasks that changed."""
    now_local = datetime.now()
    changed = []
    for task in list(data["tasks"]):
        if task.get("status") != "Scheduled":
            continue
        when = parse_local_dt(task.get("scheduledDate"))
        if not when or when > now_local:
            continue
        set_status(task, "To Do")
        changed.append(task)
        recurrence = task.get("recurrence") or "none"
        if recurrence == "none":
            continue
        nxt = add_interval(when, recurrence)
        while nxt and nxt <= now_local:  # server was off for a while: skip missed slots
            nxt = add_interval(nxt, recurrence)
        if not nxt:
            continue
        task["recurrence"] = "none"  # the chain continues on the new occurrence
        shift = nxt - when
        due = task.get("dueDate")
        new_due = ""
        if due:
            try:
                new_due = (datetime.strptime(due, "%Y-%m-%d") + shift).strftime("%Y-%m-%d")
            except ValueError:
                new_due = ""
        created = now_iso()
        occurrence = {
            key: task.get(key) for key in (
                "title", "description", "brand", "format", "tag", "priority", "assigneeId",
                "assigneeName", "contentDriveUrl", "createdBy", "createdByName", "assignedByRole",
            )
        }
        occurrence.update({
            "id": "tsk_" + secrets.token_hex(8),
            "code": next_task_code(data),
            "orgId": ORG_ID,
            "submissionDriveUrl": "",
            "delegatedBy": "", "delegatedTo": "", "delegatedToUid": "", "delegatedAt": "", "delegationNote": "",
            "isScheduled": True,
            "scheduledDate": nxt.strftime("%Y-%m-%dT%H:%M"),
            "recurrence": recurrence,
            "recurrenceOf": task.get("recurrenceOf") or task.get("id"),
            "dueDate": new_due,
            "subtasks": [dict(s, done=False) for s in task.get("subtasks") or []],
            "comments": [],
            "createdAt": created,
            "status": "Scheduled",
            "statusHistory": [{"status": "Scheduled", "at": created}],
        })
        data["tasks"].append(occurrence)
        changed.append(occurrence)
    return changed


# ---------------------------------------------------------------------------
# WhatsApp webhook (only for new tasks, reassignments and status changes)
# ---------------------------------------------------------------------------
def dispatch_whatsapp_webhook(tasks, members):
    webhook_url = os.environ.get("WHATSAPP_WEBHOOK_URL")
    if not webhook_url:
        return
    phones = {m.get("uid"): m.get("phone", "") for m in members}
    for t in tasks:
        try:
            payload = json.dumps({
                "event": "task_alert",
                "taskId": t.get("code"),
                "title": t.get("title"),
                "department": t.get("tag"),
                "assignee": t.get("assigneeName"),
                "assigneePhone": phones.get(t.get("assigneeId"), ""),
                "priority": t.get("priority"),
                "status": t.get("status"),
                "dueDate": t.get("dueDate"),
                "scheduledDate": t.get("scheduledDate", ""),
            }).encode("utf-8")
            req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
            print(f"[WhatsApp Webhook] Dispatched alert for {t.get('code')}")
        except Exception as e:
            print("[WhatsApp Webhook Error]:", e)


def notify(tasks, members):
    if tasks and os.environ.get("WHATSAPP_WEBHOOK_URL"):
        threading.Thread(target=dispatch_whatsapp_webhook, args=(list(tasks), list(members)), daemon=True).start()


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------
def new_uid():
    return "usr_" + secrets.token_hex(6)


def validate_new_account(data, body):
    email = norm_email(body.get("email"))
    password = str(body.get("password") or "")
    display_name = clean_text(body.get("displayName"), 120).strip()
    if not email.endswith(ALLOWED_DOMAIN) or len(email) <= len(ALLOWED_DOMAIN) or not re.match(r"^[^@\s]+@[^@\s]+$", email):
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
        "department": clean_text(body.get("department") or "Performance Marketing", 120),
        "role": clean_text(body.get("role") or "Member", 120),
        "phone": clean_text(body.get("phone"), 40).strip(),
    }, None


def create_account(data, fields):
    uid = new_uid()
    member = {
        "uid": uid,
        "displayName": fields["display_name"],
        "email": fields["email"],
        "role": fields["role"],
        "department": fields["department"],
        "phone": fields["phone"],
        "orgId": ORG_ID,
        "orgName": ORG_NAME,
        "accountStatus": "active",
        "joinedAt": now_iso(),
    }
    data["users"][fields["email"]] = {
        "uid": uid,
        "email": fields["email"],
        "passwordHash": hash_password(fields["password"]),
        "displayName": fields["display_name"],
        "department": fields["department"],
        "role": fields["role"],
        "phone": fields["phone"],
        "status": "active",
        "profile": dict(member),
    }
    data["members"].append(member)
    data["organizations"].setdefault(ORG_ID, {"orgId": ORG_ID, "orgName": ORG_NAME, "createdAt": now_iso()})
    return member


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


class Ctx:
    """The signed-in caller."""

    def __init__(self, token, email, user, member):
        self.token = token
        self.email = email
        self.user = user
        self.member = member or {}
        self.uid = self.member.get("uid") or user.get("uid")
        self.name = self.member.get("displayName") or user.get("displayName") or email
        self.is_admin = effective_role(user, member) == "Admin"


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class EBGHandler(http.server.SimpleHTTPRequestHandler):
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
        return auth[7:].strip() if auth.startswith("Bearer ") else ""

    def require_session(self, data):
        token = self.bearer_token()
        sess = SESSIONS.get(token)
        if not sess:
            raise ApiError(401, "Please sign in again.")
        email = sess["email"]
        user = data["users"].get(email)
        if not user:
            SESSIONS.delete(token)
            raise ApiError(401, "Account no longer exists.")
        member = find_member(data, uid=user.get("uid"), email=email)
        if is_suspended(user, member):
            SESSIONS.revoke_email(email)
            raise ApiError(401, "Your login access has been suspended by the workspace Admin. Please contact Admin.")
        return Ctx(token, email, user, member)

    def require_admin(self, data):
        ctx = self.require_session(data)
        if not ctx.is_admin:
            raise ApiError(403, "Admin privilege required.")
        return ctx

    def path_only(self):
        return self.path.split("?", 1)[0].split("#", 1)[0]

    # ---- routing ---------------------------------------------------------
    def do_GET(self):
        path = self.path_only()
        if not path.startswith("/api/"):
            if path not in PUBLIC_FILES:
                self.send_error(404)
                return
            super().do_GET()
            return
        try:
            data = load_data()
            if path == "/api/bootstrap":
                # Public: lets the sign-up form know whether the first Admin still has to register
                self.send_json(200, {"hasAdmin": has_admin(data)})
                return
            ctx = self.require_session(data)
            if path == "/api/me":
                self.send_json(200, {"success": True, "profile": profile_for(data, ctx.email)})
            elif path == "/api/data":
                released = release_due_tasks(data)
                if released:
                    save_data(data)
                    notify([t for t in released if t.get("status") == "To Do"], data["members"])
                self.send_json(200, view_for(data, ctx.is_admin))
            else:
                raise ApiError(404, "Not found")
        except ApiError as e:
            self.send_json(e.status, {"success": False, "error": e.message})
        except Exception as e:
            print("GET error:", repr(e))
            self.send_json(500, {"success": False, "error": "Server error"})

    def do_HEAD(self):
        if self.path_only() not in PUBLIC_FILES:
            self.send_error(404)
            return
        super().do_HEAD()

    def do_POST(self):
        routes = {
            "/api/login": self.api_login,
            "/api/register": self.api_register,
            "/api/logout": self.api_logout,
            "/api/change-password": self.api_change_password,
            "/api/admin/reset-password": self.api_admin_reset_password,
            "/api/admin/provision": self.api_admin_provision,
            "/api/data": self.api_data,
        }
        handler = routes.get(self.path_only())
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
            print("POST error:", repr(e))
            self.send_json(500, {"success": False, "error": "Server error"})

    # ---- auth ------------------------------------------------------------
    def api_login(self, body, data):
        email = norm_email(body.get("email"))
        password = str(body.get("password") or "")
        if not email.endswith(ALLOWED_DOMAIN):
            raise ApiError(400, "Access restricted: Only official @theebg.com email addresses are permitted.")

        # Lock per email + address, so a stranger can't lock a colleague out from elsewhere
        key = (email, self.client_address[0])
        lock = FAILED_LOGINS.get(key)
        if lock and lock["until"] > time.time():
            mins = int((lock["until"] - time.time()) // 60) + 1
            raise ApiError(429, f"Too many failed attempts. Try again in {mins} minute(s).")

        user = data["users"].get(email)
        if not user or not user.get("passwordHash") or not verify_password(password, user["passwordHash"]):
            rec = FAILED_LOGINS.setdefault(key, {"count": 0, "until": 0})
            rec["count"] += 1
            if rec["count"] >= MAX_FAILED_LOGINS:
                rec.update(count=0, until=time.time() + LOCKOUT_SECONDS)
            if user and not user.get("passwordHash"):
                raise ApiError(401, "This account has no password set. Ask the workspace Admin to reset your password.")
            raise ApiError(401, "Incorrect email or password.")

        member = find_member(data, uid=user.get("uid"), email=email)
        if is_suspended(user, member):
            raise ApiError(403, "Your login access has been suspended by the workspace Admin. Please contact Admin.")
        FAILED_LOGINS.pop(key, None)
        return 200, {"success": True, "token": SESSIONS.create(email), "profile": profile_for(data, email)}

    def api_register(self, body, data):
        fields, err = validate_new_account(data, body)
        if err:
            raise ApiError(400, err)
        if fields["role"] == "Admin" and has_admin(data):
            raise ApiError(403, "Admin accounts can only be granted by an existing Admin. Please pick your team role.")
        create_account(data, fields)
        save_data(data)
        return 200, {"success": True, "token": SESSIONS.create(fields["email"]), "profile": profile_for(data, fields["email"])}

    def api_logout(self, body, data):
        SESSIONS.delete(self.bearer_token())
        return 200, {"success": True}

    def api_change_password(self, body, data):
        ctx = self.require_session(data)
        current = str(body.get("currentPassword") or "")
        new = str(body.get("newPassword") or "")
        if not verify_password(current, ctx.user.get("passwordHash") or ""):
            raise ApiError(400, "Your current password is incorrect.")
        if len(new) < MIN_PASSWORD_LEN:
            raise ApiError(400, f"New password must be at least {MIN_PASSWORD_LEN} characters.")
        ctx.user["passwordHash"] = hash_password(new)
        save_data(data)
        SESSIONS.revoke_email(ctx.email, keep_token=ctx.token)
        return 200, {"success": True}

    def api_admin_reset_password(self, body, data):
        ctx = self.require_admin(data)
        email = norm_email(body.get("email"))
        new_password = str(body.get("newPassword") or "")
        if len(new_password) < MIN_PASSWORD_LEN:
            raise ApiError(400, f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        user = data["users"].get(email)
        if not user:
            member = find_member(data, email=email)
            if not member:
                raise ApiError(404, "No member with this email.")
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
        SESSIONS.revoke_email(email, keep_token=ctx.token)
        for key in [k for k in FAILED_LOGINS if k[0] == email]:
            FAILED_LOGINS.pop(key, None)
        return 200, {"success": True}

    def api_admin_provision(self, body, data):
        self.require_admin(data)
        fields, err = validate_new_account(data, body)
        if err:
            raise ApiError(400, err)
        member = create_account(data, fields)
        save_data(data)
        return 200, {"success": True, "member": member, "data": view_for(data, True)}

    # ---- workspace data ----------------------------------------------------
    def api_data(self, patch, data):
        ctx = self.require_session(data)
        to_notify = []

        # Organization settings (Admin)
        if isinstance(patch.get("organizations"), dict):
            if not ctx.is_admin:
                raise ApiError(403, "Admin privilege required to change workspace settings.")
            for org_id, org in patch["organizations"].items():
                if isinstance(org, dict):
                    data["organizations"].setdefault(org_id, {}).update(
                        {k: clean_text(v, 200) for k, v in org.items() if k in ("orgName",)})

        # Member profiles: field-level updates. New members only via /api/admin/provision.
        if isinstance(patch.get("members"), list):
            for m in patch["members"]:
                if not isinstance(m, dict):
                    continue
                existing = find_member(data, uid=m.get("uid"))
                if not existing:
                    continue
                if ctx.is_admin:
                    allowed = MEMBER_ADMIN_FIELDS
                elif existing.get("uid") == ctx.uid:
                    allowed = MEMBER_SELF_FIELDS
                else:
                    raise ApiError(403, "You can only update your own profile.")
                updates = {k: clean_text(v, 200) for k, v in m.items() if k in allowed}
                if "accountStatus" in updates:
                    if updates["accountStatus"] not in ("active", "suspended"):
                        updates.pop("accountStatus")
                    elif updates["accountStatus"] == "suspended" and existing.get("uid") == ctx.uid:
                        raise ApiError(400, "You cannot suspend your own account.")
                if "displayName" in updates and not updates["displayName"].strip():
                    updates.pop("displayName")
                old_name = existing.get("displayName")
                existing.update(updates)
                sync_user_from_member(data, existing)
                if existing.get("accountStatus") == "suspended":
                    SESSIONS.revoke_email(norm_email(existing.get("email")))
                if existing.get("displayName") != old_name:
                    for t in data["tasks"]:
                        if t.get("assigneeId") == existing["uid"]:
                            t["assigneeName"] = existing["displayName"]
                        if t.get("delegatedToUid") == existing["uid"]:
                            t["delegatedTo"] = existing["displayName"]

        # Account status by email (Admin) — kept for the management console
        if isinstance(patch.get("users"), dict):
            if not ctx.is_admin:
                raise ApiError(403, "Admin privilege required.")
            for email, rec in patch["users"].items():
                email = norm_email(email)
                member = find_member(data, email=email)
                if not isinstance(rec, dict) or not member or rec.get("status") not in ("active", "suspended"):
                    continue
                if rec["status"] == "suspended" and email == ctx.email:
                    raise ApiError(400, "You cannot suspend your own account.")
                member["accountStatus"] = rec["status"]
                sync_user_from_member(data, member)
                if rec["status"] == "suspended":
                    SESSIONS.revoke_email(email)

        # Tasks: create, or update only the fields that were sent
        if isinstance(patch.get("tasks"), list):
            for raw in patch["tasks"]:
                if not isinstance(raw, dict) or not ID_RE.match(str(raw.get("id") or "")):
                    continue
                fields = clean_task_fields(raw)
                if fields.get("assigneeId"):
                    assignee = find_member(data, uid=fields["assigneeId"])
                    if not assignee:
                        raise ApiError(400, "The selected assignee is no longer a team member.")
                    fields["assigneeName"] = assignee.get("displayName", "")
                if fields.get("delegatedToUid"):
                    delegate = find_member(data, uid=fields["delegatedToUid"])
                    fields["delegatedTo"] = delegate.get("displayName", "") if delegate else ""
                existing = find_task(data, raw["id"])
                if existing:
                    new_status = fields.pop("status", None)
                    old_assignee = existing.get("assigneeId")
                    existing.update(fields)
                    status_changed = new_status and new_status != existing.get("status")
                    if status_changed:
                        set_status(existing, new_status)
                    if status_changed or existing.get("assigneeId") != old_assignee:
                        to_notify.append(existing)
                else:
                    if not fields.get("title", "").strip():
                        raise ApiError(400, "Task title is required.")
                    created = now_iso()
                    task = {
                        "id": raw["id"],
                        "code": next_task_code(data),
                        "orgId": ORG_ID,
                        "title": "", "description": "", "brand": "EBG Performance", "format": "General Deliverable",
                        "tag": "Performance Marketing", "priority": "Medium", "dueDate": "",
                        "assigneeId": ctx.uid, "assigneeName": ctx.name,
                        "contentDriveUrl": "", "submissionDriveUrl": "",
                        "delegatedBy": "", "delegatedTo": "", "delegatedToUid": "", "delegatedAt": "", "delegationNote": "",
                        "isScheduled": False, "scheduledDate": "", "recurrence": "none",
                        "subtasks": [], "comments": [],
                    }
                    status = fields.pop("status", None) or ("Scheduled" if fields.get("isScheduled") else "To Do")
                    task.update(fields)
                    task.update({"createdBy": ctx.uid, "createdByName": ctx.name, "createdAt": created,
                                 "status": status, "statusHistory": [{"status": status, "at": created}]})
                    if status != "Scheduled":
                        task["isScheduled"] = False
                    data["tasks"].append(task)
                    to_notify.append(task)

        # Comments are appended on the server so simultaneous comments are never lost
        comment = patch.get("addComment")
        if isinstance(comment, dict):
            task = find_task(data, comment.get("taskId"))
            text = clean_text(comment.get("text"), 2000).strip()
            if task and text:
                task.setdefault("comments", []).append({
                    "id": "cmt_" + secrets.token_hex(6),
                    "author": ctx.name,
                    "authorId": ctx.uid,
                    "text": text,
                    "timestamp": now_iso(),
                })

        if patch.get("deleteTaskId"):
            task = find_task(data, patch["deleteTaskId"])
            if task:
                if not ctx.is_admin and task.get("createdBy") != ctx.uid:
                    raise ApiError(403, "Only the task creator or an Admin can delete this task.")
                data["tasks"] = [t for t in data["tasks"] if t is not task]

        if patch.get("deleteMemberUid") or patch.get("deleteUserEmail"):
            if not ctx.is_admin:
                raise ApiError(403, "Admin privilege required.")
            gone = find_member(data, uid=patch.get("deleteMemberUid")) or find_member(data, email=norm_email(patch.get("deleteUserEmail")))
            del_email = norm_email((gone or {}).get("email") or patch.get("deleteUserEmail"))
            del_uid = (gone or {}).get("uid") or patch.get("deleteMemberUid")
            if del_uid == ctx.uid or del_email == ctx.email:
                raise ApiError(400, "You cannot delete your own account.")
            data["members"] = [m for m in data["members"] if m.get("uid") != del_uid and norm_email(m.get("email")) != del_email]
            data["users"].pop(del_email, None)
            SESSIONS.revoke_email(del_email)
            # Open tasks of a removed member go back to the pool instead of pointing at nobody
            for t in data["tasks"]:
                if del_uid and t.get("assigneeId") == del_uid:
                    t["assigneeId"] = ""
                    t["assigneeName"] = "Unassigned"
                if del_uid and t.get("delegatedToUid") == del_uid:
                    t.update(delegatedTo="", delegatedToUid="")

        if not has_admin(data):
            raise ApiError(400, "The workspace must keep at least one active Admin.")

        released = release_due_tasks(data)
        save_data(data)
        notify(to_notify + [t for t in released if t.get("status") == "To Do"], data["members"])
        return 200, {"success": True, "data": view_for(data, ctx.is_admin)}


def run():
    try:
        data = load_data()
        changed = migrate_plaintext_passwords(data)
        # Older records: ensure every task has a status history for the trend chart
        for t in data["tasks"]:
            if not t.get("statusHistory"):
                t["statusHistory"] = [{"status": t.get("status") or "To Do", "at": t.get("createdAt") or now_iso()}]
                changed = True
        if changed:
            save_data(data)
            print("Upgraded data.json (hashed passwords / task history).")
    except Exception as e:
        print("Could not read data.json:", e)
        sys.exit(1)

    # On Windows SO_REUSEADDR lets a second server bind the same port. Refuse instead.
    socketserver.TCPServer.allow_reuse_address = os.name != "nt"
    try:
        httpd = socketserver.TCPServer(("", PORT), EBGHandler)
    except OSError:
        print(f"Port {PORT} is already in use: the EBG server is probably already running. "
              f"Close the other server window first, then start this one again.")
        sys.exit(1)
    with httpd:
        print(f"EBG Server running at http://localhost:{PORT}")
        sys.stdout.flush()
        httpd.serve_forever()


if __name__ == "__main__":
    run()
