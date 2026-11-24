"""Shared logic for the EBG Task Assigner API.

Used by both:
  - server.py        (runs on a PC; data in data.json / sessions.json)
  - api/index.py     (Vercel serverless function; data in Upstash Redis)

The leading underscore stops Vercel from turning this file into its own endpoint.
"""
import calendar
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None

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
# Scheduled release times are entered in the team's local time. Vercel runs in UTC, so be explicit.
TEAM_TIMEZONE = os.environ.get("EBG_TIMEZONE", "Asia/Kolkata")

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
# Projects are the departments, plus "all" for workspace-wide messages
MESSAGE_PROJECTS = {"all", "Performance Marketing", "Graphic Designing", "Web Developer"}
MAX_MESSAGES = 2000


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def now_iso():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def team_now():
    """Current wall-clock time in the team's timezone, without tzinfo (matches <input type=datetime-local>)."""
    if ZoneInfo:
        try:
            return datetime.now(ZoneInfo(TEAM_TIMEZONE)).replace(tzinfo=None)
        except Exception:
            pass
    return datetime.now()


def empty_data():
    return {"organizations": {}, "members": [], "tasks": [], "users": {}, "messages": []}


def normalize_data(data):
    data = data if isinstance(data, dict) else {}
    for key, default in (("organizations", {}), ("members", []), ("tasks", []), ("users", {}), ("messages", [])):
        if not isinstance(data.get(key), type(default)):
            data[key] = default
    data["members"] = [m for m in data["members"] if isinstance(m, dict)]
    data["tasks"] = [t for t in data["tasks"] if isinstance(t, dict)]
    data["messages"] = [m for m in data["messages"] if isinstance(m, dict)]
    return data


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


def upgrade_data(data):
    """Hash any plaintext passwords and give every task a status history. Returns True if changed."""
    changed = False
    for rec in data["users"].values():
        if isinstance(rec, dict) and "password" in rec:
            plain = rec.pop("password")
            if plain and not rec.get("passwordHash"):
                rec["passwordHash"] = hash_password(str(plain))
            changed = True
    for t in data["tasks"]:
        if not t.get("statusHistory"):
            t["statusHistory"] = [{"status": t.get("status") or "To Do", "at": t.get("createdAt") or now_iso()}]
            changed = True
    return changed


def token_key(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Storage backends
# ---------------------------------------------------------------------------
class FileStorage:
    """data.json + sessions.json on disk (for running server.py on a PC)."""

    def __init__(self, directory):
        self.data_file = os.path.join(directory, "data.json")
        self.sessions_file = os.path.join(directory, "sessions.json")
        self.lock = threading.RLock()
        self.failures = {}
        try:
            with open(self.sessions_file, "r", encoding="utf-8") as f:
                raw = json.load(f)
            now = time.time()
            self.sessions = {k: v for k, v in raw.items() if isinstance(v, dict) and v.get("expires", 0) > now}
        except (FileNotFoundError, ValueError):
            self.sessions = {}

    @staticmethod
    def _write(path, obj):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)

    def read(self):
        # A read error raises instead of returning an empty workspace that would be saved back.
        with self.lock:
            if not os.path.exists(self.data_file):
                return empty_data()
            with open(self.data_file, "r", encoding="utf-8") as f:
                return normalize_data(json.load(f))

    def transact(self, fn):
        with self.lock:
            data = self.read()
            result = fn(data)
            if result.changed:
                self._write(self.data_file, data)
            return result

    # sessions
    def _save_sessions(self):
        self._write(self.sessions_file, self.sessions)

    def create_session(self, email):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token_key(token)] = {"email": email, "expires": time.time() + SESSION_TTL_SECONDS}
            self._save_sessions()
        return token

    def session_email(self, token):
        if not token:
            return None
        with self.lock:
            key = token_key(token)
            sess = self.sessions.get(key)
            if sess and sess["expires"] < time.time():
                del self.sessions[key]
                self._save_sessions()
                return None
            return sess["email"] if sess else None

    def delete_session(self, token):
        if not token:
            return
        with self.lock:
            if self.sessions.pop(token_key(token), None):
                self._save_sessions()

    def revoke_email(self, email, keep_token=None):
        keep = token_key(keep_token) if keep_token else None
        with self.lock:
            before = len(self.sessions)
            self.sessions = {k: v for k, v in self.sessions.items() if v["email"] != email or k == keep}
            if len(self.sessions) != before:
                self._save_sessions()

    # login throttling
    def locked_seconds(self, key):
        rec = self.failures.get(key)
        return max(0, int(rec["until"] - time.time())) if rec and rec["until"] > time.time() else 0

    def record_failure(self, key):
        with self.lock:
            rec = self.failures.setdefault(key, {"count": 0, "until": 0})
            rec["count"] += 1
            if rec["count"] >= MAX_FAILED_LOGINS:
                rec.update(count=0, until=time.time() + LOCKOUT_SECONDS)

    def clear_failures(self, email, ip=None):
        with self.lock:
            for k in [k for k in self.failures if k[0] == email and (ip is None or k[1] == ip)]:
                self.failures.pop(k, None)


class RedisStorage:
    """Upstash Redis over its REST API (for Vercel). No extra Python packages needed."""

    CAS_SCRIPT = (
        "local cur = redis.call('GET', KEYS[2]) or '0' "
        "if cur == ARGV[1] then "
        "redis.call('SET', KEYS[1], ARGV[2]) redis.call('SET', KEYS[2], ARGV[3]) return 1 "
        "end return 0"
    )

    def __init__(self, url, token, prefix="ebg"):
        self.url = url.rstrip("/")
        self.token = token
        self.k_data = f"{prefix}:data"
        self.k_ver = f"{prefix}:ver"
        self.p = prefix

    def _request(self, path, body):
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode("utf-8"), method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise ApiError(503, f"Database error ({e.code}). Check the Upstash Redis connection in Vercel.")
        except urllib.error.URLError:
            raise ApiError(503, "Cannot reach the database. Check the Upstash Redis connection in Vercel.")

    def cmd(self, *args):
        res = self._request("", [str(a) for a in args])
        if "error" in res:
            raise ApiError(503, "Database error: " + str(res["error"]))
        return res.get("result")

    def pipeline(self, commands):
        res = self._request("/pipeline", [[str(a) for a in c] for c in commands])
        return [r.get("result") for r in res]

    def _read_with_version(self):
        raw, ver = self.cmd("MGET", self.k_data, self.k_ver)
        data = normalize_data(json.loads(raw)) if raw else empty_data()
        return data, ver or "0"

    def read(self):
        return self._read_with_version()[0]

    def transact(self, fn, attempts=25):
        for attempt in range(attempts):
            data, ver = self._read_with_version()
            result = fn(data)
            if not result.changed:
                return result
            new_ver = str(int(ver) + 1)
            ok = self.cmd("EVAL", self.CAS_SCRIPT, 2, self.k_data, self.k_ver, ver,
                          json.dumps(data, ensure_ascii=False), new_ver)
            if int(ok or 0) == 1:
                return result
            # Someone else saved first: wait a random moment and retry on fresh data
            time.sleep(random.uniform(0.01, 0.05) * min(attempt + 1, 6))
        raise ApiError(409, "The workspace is busy. Please try again.")

    # sessions
    def _sk(self, key):
        return f"{self.p}:sess:{key}"

    def _ik(self, email):
        return f"{self.p}:sessidx:{email}"

    def create_session(self, email):
        token = secrets.token_urlsafe(32)
        key = token_key(token)
        self.pipeline([
            ["SET", self._sk(key), email, "EX", SESSION_TTL_SECONDS],
            ["SADD", self._ik(email), key],
            ["EXPIRE", self._ik(email), SESSION_TTL_SECONDS],
        ])
        return token

    def session_email(self, token):
        return self.cmd("GET", self._sk(token_key(token))) if token else None

    def delete_session(self, token):
        if not token:
            return
        key = token_key(token)
        email = self.cmd("GET", self._sk(key))
        cmds = [["DEL", self._sk(key)]]
        if email:
            cmds.append(["SREM", self._ik(email), key])
        self.pipeline(cmds)

    def revoke_email(self, email, keep_token=None):
        keep = token_key(keep_token) if keep_token else None
        keys = self.cmd("SMEMBERS", self._ik(email)) or []
        cmds = [["DEL", self._sk(k)] for k in keys if k != keep]
        cmds += [["SREM", self._ik(email), k] for k in keys if k != keep]
        if cmds:
            self.pipeline(cmds)

    # login throttling
    def _fk(self, key):
        return f"{self.p}:fail:{key[0]}:{key[1]}"

    def _lk(self, key):
        return f"{self.p}:lock:{key[0]}:{key[1]}"

    def locked_seconds(self, key):
        ttl = self.cmd("TTL", self._lk(key))
        return int(ttl) if ttl and int(ttl) > 0 else 0

    def record_failure(self, key):
        count, _ = self.pipeline([["INCR", self._fk(key)], ["EXPIRE", self._fk(key), 15 * 60]])
        if int(count) >= MAX_FAILED_LOGINS:
            self.pipeline([["SET", self._lk(key), 1, "EX", LOCKOUT_SECONDS], ["DEL", self._fk(key)]])

    def clear_failures(self, email, ip=None):
        if ip is not None:
            self.pipeline([["DEL", self._fk((email, ip))], ["DEL", self._lk((email, ip))]])
        else:
            keys = (self.cmd("KEYS", f"{self.p}:fail:{email}:*") or []) + (self.cmd("KEYS", f"{self.p}:lock:{email}:*") or [])
            if keys:
                self.cmd("DEL", *keys)


def storage_from_env():
    url = os.environ.get("UPSTASH_REDIS_REST_URL") or os.environ.get("KV_REST_API_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN") or os.environ.get("KV_REST_API_TOKEN")
    if not url or not token:
        return None
    return RedisStorage(url, token, os.environ.get("EBG_REDIS_PREFIX", "ebg"))


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
        "messages": data.get("messages", []),
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
    user.setdefault("profile", {}).update(member)


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
    now_local = team_now()
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
        while nxt and nxt <= now_local:  # skip slots missed while nobody had the app open
            nxt = add_interval(nxt, recurrence)
        if not nxt:
            continue
        task["recurrence"] = "none"  # the chain continues on the new occurrence
        shift = nxt - when
        new_due = ""
        if task.get("dueDate"):
            try:
                new_due = (datetime.strptime(task["dueDate"], "%Y-%m-%d") + shift).strftime("%Y-%m-%d")
            except ValueError:
                new_due = ""
        created = now_iso()
        occurrence = {key: task.get(key) for key in (
            "title", "description", "brand", "format", "tag", "priority", "assigneeId",
            "assigneeName", "contentDriveUrl", "createdBy", "createdByName", "assignedByRole",
        )}
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
            urllib.request.urlopen(req, timeout=4)
        except Exception as e:
            print("[WhatsApp Webhook Error]:", e)


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
        raise ApiError(400, "Only official @theebg.com email addresses are permitted.")
    if len(password) < MIN_PASSWORD_LEN:
        raise ApiError(400, f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if not display_name:
        raise ApiError(400, "Full name is required.")
    if email in data["users"] or find_member(data, email=email):
        raise ApiError(400, "An account with this email already exists. Please Sign In.")
    return {
        "email": email,
        "password": password,
        "display_name": display_name,
        "department": clean_text(body.get("department") or "Performance Marketing", 120),
        "role": clean_text(body.get("role") or "Member", 120),
        "phone": clean_text(body.get("phone"), 40).strip(),
    }


def create_account(data, fields, password_hash):
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
        "passwordHash": password_hash,
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


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------
class Result:
    """Outcome of one transaction attempt. `after` runs only once the data is saved."""

    def __init__(self, status=200, payload=None, changed=False):
        self.status = status
        self.payload = payload if payload is not None else {}
        self.changed = changed
        self.after = []   # callables run after a successful save
        self.notify = []  # tasks for the WhatsApp webhook


class Caller:
    def __init__(self, token, email, user, member):
        self.token = token
        self.email = email
        self.user = user
        self.member = member or {}
        self.uid = self.member.get("uid") or user.get("uid")
        self.name = self.member.get("displayName") or user.get("displayName") or email
        self.is_admin = effective_role(user, member) == "Admin"


class Api:
    """Transport-independent API. `handle()` returns (http_status, json_payload)."""

    def __init__(self, storage, background_webhooks=True):
        self.storage = storage
        self.background_webhooks = background_webhooks

    # ---- entry point -------------------------------------------------------
    def handle(self, method, path, headers, body_bytes, client_ip):
        try:
            if self.storage is None:
                raise ApiError(503, "The database is not connected. Add Upstash Redis to this Vercel project (see DEPLOY.md).")
            token = ""
            auth = headers.get("Authorization") or headers.get("authorization") or ""
            if auth.startswith("Bearer "):
                token = auth[7:].strip()
            if method == "GET":
                return self.get(path, token)
            if method == "POST":
                if len(body_bytes or b"") > MAX_BODY_BYTES:
                    raise ApiError(413, "Request too large")
                try:
                    body = json.loads((body_bytes or b"{}").decode("utf-8") or "{}")
                except (ValueError, UnicodeDecodeError):
                    raise ApiError(400, "Invalid JSON")
                if not isinstance(body, dict):
                    raise ApiError(400, "Request body must be a JSON object")
                return self.post(path, token, body, client_ip)
            raise ApiError(405, "Method not allowed")
        except ApiError as e:
            return e.status, {"success": False, "error": e.message}
        except Exception as e:
            print("API error:", repr(e))
            return 500, {"success": False, "error": "Server error"}

    def caller(self, data, token):
        email = self.storage.session_email(token)
        if not email:
            raise ApiError(401, "Please sign in again.")
        user = data["users"].get(email)
        if not user:
            self.storage.delete_session(token)
            raise ApiError(401, "Account no longer exists.")
        member = find_member(data, uid=user.get("uid"), email=email)
        if is_suspended(user, member):
            self.storage.revoke_email(email)
            raise ApiError(401, "Your login access has been suspended by the workspace Admin. Please contact Admin.")
        return Caller(token, email, user, member)

    def run(self, fn):
        """Run fn(data) -> Result in a transaction, then its after-save effects."""
        result = self.storage.transact(fn)
        for effect in result.after:
            effect()
        if result.notify and os.environ.get("WHATSAPP_WEBHOOK_URL"):
            view = result.payload.get("data", result.payload)
            members = list(view.get("members", []))
            if self.background_webhooks:
                threading.Thread(target=dispatch_whatsapp_webhook, args=(result.notify, members), daemon=True).start()
            else:
                dispatch_whatsapp_webhook(result.notify, members)
        return result.status, result.payload

    # ---- GET ---------------------------------------------------------------
    def get(self, path, token):
        if path == "/api/bootstrap":
            # Public: lets the sign-up form know whether the first Admin still has to register
            return 200, {"hasAdmin": has_admin(self.storage.read()), "server": "ebg"}
        if path == "/api/me":
            data = self.storage.read()
            ctx = self.caller(data, token)
            return 200, {"success": True, "profile": profile_for(data, ctx.email)}
        if path == "/api/data":
            def fn(data):
                ctx = self.caller(data, token)
                released = release_due_tasks(data)
                res = Result(200, view_for(data, ctx.is_admin), changed=bool(released))
                res.notify = [t for t in released if t.get("status") == "To Do"]
                return res
            return self.run(fn)
        raise ApiError(404, "Not found")

    # ---- POST --------------------------------------------------------------
    def post(self, path, token, body, client_ip):
        if path == "/api/login":
            return self.login(body, client_ip)
        if path == "/api/register":
            return self.register(body)
        if path == "/api/logout":
            self.storage.delete_session(token)
            return 200, {"success": True}
        if path == "/api/change-password":
            return self.change_password(body, token)
        if path == "/api/admin/reset-password":
            return self.admin_reset_password(body, token)
        if path == "/api/admin/provision":
            return self.admin_provision(body, token)
        if path == "/api/data":
            return self.run(lambda data: self.apply_patch(data, body, token))
        raise ApiError(404, "Not found")

    def login(self, body, client_ip):
        email = norm_email(body.get("email"))
        password = str(body.get("password") or "")
        if not email.endswith(ALLOWED_DOMAIN):
            raise ApiError(400, "Access restricted: Only official @theebg.com email addresses are permitted.")
        # Lock per email + address, so a stranger can't lock a colleague out from elsewhere
        key = (email, client_ip)
        wait = self.storage.locked_seconds(key)
        if wait:
            raise ApiError(429, f"Too many failed attempts. Try again in {wait // 60 + 1} minute(s).")
        data = self.storage.read()
        user = data["users"].get(email)
        if not user or not user.get("passwordHash") or not verify_password(password, user["passwordHash"]):
            self.storage.record_failure(key)
            if user and not user.get("passwordHash"):
                raise ApiError(401, "This account has no password set. Ask the workspace Admin to reset your password.")
            raise ApiError(401, "Incorrect email or password.")
        member = find_member(data, uid=user.get("uid"), email=email)
        if is_suspended(user, member):
            raise ApiError(403, "Your login access has been suspended by the workspace Admin. Please contact Admin.")
        self.storage.clear_failures(email, client_ip)
        return 200, {"success": True, "token": self.storage.create_session(email), "profile": profile_for(data, email)}

    def register(self, body):
        password_hash = hash_password(str(body.get("password") or ""))  # hashed once, outside retries

        def fn(data):
            fields = validate_new_account(data, body)
            if fields["role"] == "Admin" and has_admin(data):
                raise ApiError(403, "Admin accounts can only be granted by an existing Admin. Please pick your team role.")
            create_account(data, fields, password_hash)
            res = Result(200, {"success": True, "profile": profile_for(data, fields["email"])}, changed=True)
            res.email = fields["email"]
            return res

        result = self.storage.transact(fn)
        result.payload["token"] = self.storage.create_session(result.email)
        return 200, result.payload

    def change_password(self, body, token):
        new = str(body.get("newPassword") or "")
        if len(new) < MIN_PASSWORD_LEN:
            raise ApiError(400, f"New password must be at least {MIN_PASSWORD_LEN} characters.")
        new_hash = hash_password(new)

        def fn(data):
            ctx = self.caller(data, token)
            if not verify_password(str(body.get("currentPassword") or ""), ctx.user.get("passwordHash") or ""):
                raise ApiError(400, "Your current password is incorrect.")
            ctx.user["passwordHash"] = new_hash
            res = Result(200, {"success": True}, changed=True)
            res.after.append(lambda: self.storage.revoke_email(ctx.email, keep_token=token))
            return res

        return self.run(fn)

    def admin_reset_password(self, body, token):
        new_password = str(body.get("newPassword") or "")
        if len(new_password) < MIN_PASSWORD_LEN:
            raise ApiError(400, f"Password must be at least {MIN_PASSWORD_LEN} characters.")
        new_hash = hash_password(new_password)
        email = norm_email(body.get("email"))

        def fn(data):
            ctx = self.caller(data, token)
            if not ctx.is_admin:
                raise ApiError(403, "Admin privilege required.")
            user = data["users"].get(email)
            if not user:
                member = find_member(data, email=email)
                if not member:
                    raise ApiError(404, "No member with this email.")
                user = {
                    "uid": member.get("uid") or new_uid(), "email": email,
                    "displayName": member.get("displayName") or email.split("@")[0],
                    "department": member.get("department") or "Performance Marketing",
                    "role": member.get("role") or "Member", "phone": member.get("phone") or "",
                    "status": "active", "profile": dict(member),
                }
                data["users"][email] = user
            user["passwordHash"] = new_hash
            user.pop("password", None)
            res = Result(200, {"success": True}, changed=True)
            res.after.append(lambda: self.storage.revoke_email(email, keep_token=token))
            res.after.append(lambda: self.storage.clear_failures(email))
            return res

        return self.run(fn)

    def admin_provision(self, body, token):
        password_hash = hash_password(str(body.get("password") or ""))

        def fn(data):
            ctx = self.caller(data, token)
            if not ctx.is_admin:
                raise ApiError(403, "Admin privilege required.")
            member = create_account(data, validate_new_account(data, body), password_hash)
            return Result(200, {"success": True, "member": member, "data": view_for(data, True)}, changed=True)

        return self.run(fn)

    # ---- the shared workspace endpoint -------------------------------------
    def apply_patch(self, data, patch, token):
        ctx = self.caller(data, token)
        res = Result(changed=True)
        revoke = set()

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
                    revoke.add(norm_email(existing.get("email")))
                if existing.get("displayName") != old_name:
                    for t in data["tasks"]:
                        if t.get("assigneeId") == existing["uid"]:
                            t["assigneeName"] = existing["displayName"]
                        if t.get("delegatedToUid") == existing["uid"]:
                            t["delegatedTo"] = existing["displayName"]

        # Account status by email (Admin console)
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
                    revoke.add(email)

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
                    status_changed = bool(new_status) and new_status != existing.get("status")
                    if status_changed:
                        set_status(existing, new_status)
                    if status_changed or existing.get("assigneeId") != old_assignee:
                        res.notify.append(existing)
                else:
                    if not fields.get("title", "").strip():
                        raise ApiError(400, "Task title is required.")
                    created = now_iso()
                    task = {
                        "id": raw["id"], "code": next_task_code(data), "orgId": ORG_ID,
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
                    res.notify.append(task)

        # Comments are appended on the server so simultaneous comments are never lost
        comment = patch.get("addComment")
        if isinstance(comment, dict):
            task = find_task(data, comment.get("taskId"))
            text = clean_text(comment.get("text"), 2000).strip()
            if task and text:
                task.setdefault("comments", []).append({
                    "id": "cmt_" + secrets.token_hex(6), "author": ctx.name, "authorId": ctx.uid,
                    "text": text, "timestamp": now_iso(),
                })

        # Project messages (the Messages tab)
        message = patch.get("addMessage")
        if isinstance(message, dict):
            project = str(message.get("project") or "all")
            text = clean_text(message.get("text"), 4000).strip()
            if project not in MESSAGE_PROJECTS:
                raise ApiError(400, "Unknown project for this message.")
            if not text:
                raise ApiError(400, "Message is empty.")
            data["messages"].append({
                "id": "msg_" + secrets.token_hex(6), "project": project,
                "author": ctx.name, "authorId": ctx.uid, "text": text, "timestamp": now_iso(),
            })
            data["messages"] = data["messages"][-MAX_MESSAGES:]

        if patch.get("deleteMessageId"):
            target = next((m for m in data["messages"] if m.get("id") == patch["deleteMessageId"]), None)
            if target:
                if not ctx.is_admin and target.get("authorId") != ctx.uid:
                    raise ApiError(403, "Only the author or an Admin can delete this message.")
                data["messages"] = [m for m in data["messages"] if m is not target]

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
            revoke.add(del_email)
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
        res.notify += [t for t in released if t.get("status") == "To Do"]
        for email in revoke:
            res.after.append(lambda e=email: self.storage.revoke_email(e))
        res.payload = {"success": True, "data": view_for(data, ctx.is_admin)}
        return res
