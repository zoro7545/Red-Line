#!/usr/bin/env python3
"""
Red Line - phone server
-----------------------
Run this on the SERVER PC (next to redline_db.py, licensing.py and redline_mobile.html):

    python redline_api.py                      start the server (port 8080)
    python redline_api.py user add NAME admin  create a login (role: admin or staff) - asks for a password
    python redline_api.py user list | passwd NAME | disable NAME
    python redline_api.py install              (Windows) start automatically at every log-in, hidden - no window
    python redline_api.py status | uninstall   check / remove that automatic start

Phones use the Red Line APK (built with make_apk.py).  There is NO web page: a browser pointed at this server
gets "404".  The APK carries a secret key (phone_key.txt) and the server ignores everything without it.
Phones never touch the database: they only talk to this server, which checks the login AND the product key on
every request.  Revoke the product key and every phone is locked within a few minutes.
"""
import base64
import getpass
import hashlib
import hmac
import json
import math
import os
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import redline_db as RDB

try:
    import licensing
except ImportError:
    licensing = None

HERE = os.path.dirname(os.path.abspath(__file__))
LICENSE_PATH = os.path.join(RDB.APP_DIR, "license.key")
LICENSE_STATE_PATH = os.path.join(RDB.APP_DIR, "license_state.json")
PORT = int(os.environ.get("REDLINE_PORT", "8080"))
HOST = os.environ.get("REDLINE_HOST", "0.0.0.0")     # 0.0.0.0 = every address of this PC, incl. its Tailscale IP
TOKEN_HOURS = 12
RECHECK_SECONDS = 300
PAYMENTS = ["Cash", "UPI", "Card"]
ROLES = ("admin", "staff")


class ApiError(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


# ---------------------------------------------------------------- product key
class License:
    ok, msg = False, "Checking the product key..."

    def check(self):
        if licensing is None:
            self.ok, self.msg = False, "licensing.py is missing on the server."
            return
        try:
            with open(LICENSE_PATH, encoding="utf-8") as fh:
                info = licensing.check_key(fh.read())
            licensing.check_revocation(info, LICENSE_STATE_PATH)
            self.ok, self.msg = True, ""
        except OSError:
            self.ok, self.msg = False, "No product key on the server PC. Activate the desktop app there first."
        except licensing.LicenseError as e:
            self.ok, self.msg = False, str(e)
        except Exception:
            pass                                      # network trouble: keep the last answer (same as the desktop app)

    def watch(self):
        while True:
            time.sleep(RECHECK_SECONDS)
            self.check()


LIC = License()


# ---------------------------------------------------------------- passwords + tokens
def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def check_pw(pw, stored):
    try:
        return hmac.compare_digest(hash_pw(pw, stored.split("$", 1)[0]), stored)
    except Exception:
        return False


class Auth:
    def __init__(self, db):
        self.db = db
        db.x("INSERT INTO settings(key,value) VALUES('api_secret',?) ON CONFLICT (key) DO NOTHING",
             (secrets.token_hex(32),))
        self.secret = db.setting("api_secret").encode()
        self.fails = {}                               # (ip, user) -> (count, locked_until)

    def sign(self, payload):
        return hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()

    def make_token(self, uid):
        p = f"{uid}.{int(RDB.now()) + TOKEN_HOURS * 3600}"
        return base64.urlsafe_b64encode((p + "." + self.sign(p)).encode()).decode()

    def user_from_token(self, token):
        try:
            p, sig = base64.urlsafe_b64decode(token.encode()).decode().rsplit(".", 1)
            uid, exp = p.split(".")
            if not hmac.compare_digest(sig, self.sign(p)) or int(exp) < RDB.now():
                return None
            r = self.db.q("SELECT * FROM app_users WHERE id=? AND active=1", (int(uid),))
            return r[0] if r else None                # a disabled user is locked out immediately
        except Exception:
            return None

    def login(self, ip, username, password):
        key = (ip, username.lower())
        cnt, until = self.fails.get(key, (0, 0))
        if until > time.time():
            raise ApiError(429, "Too many wrong attempts. Wait a minute and try again.")
        r = self.db.q("SELECT * FROM app_users WHERE lower(username)=lower(?) AND active=1", (username,))
        if not r or not check_pw(password, r[0]["pw_hash"]):
            cnt += 1
            self.fails[key] = (cnt, time.time() + 60 if cnt >= 5 else 0)
            raise ApiError(401, "Wrong user name or password.")
        self.fails.pop(key, None)
        return r[0]


# ---------------------------------------------------------------- business logic (mirrors the desktop app)
def time_charge(rate, secs, round_min):
    minutes = max(0.0, secs / 60.0)
    if round_min > 1:
        minutes = math.ceil(minutes / round_min) * round_min
    return round(rate * minutes / 60.0)


def play_secs(s, now):
    paused = s["paused_total"] or 0
    if s["paused_at"]:
        paused += max(0, now - s["paused_at"])
    return max(0.0, now - s["start_ts"] - paused)


class Service:
    def __init__(self, db):
        self.db = db
        self.auth = Auth(db)

    def cfg(self, key, default):
        return self.db.setting(key, default)

    def round_min(self):
        try:
            return max(1, int(float(self.cfg("round_min", "1"))))
        except ValueError:
            return 1

    # -- reading
    def state(self, admin):
        now = RDB.now()
        food = {r["session_id"]: r["t"] for r in self.db.q(
            "SELECT session_id, SUM(price*qty) t FROM orders GROUP BY session_id")}
        sess = {r["station_id"]: r for r in self.db.q("SELECT * FROM sessions WHERE status='active'")}
        out = []
        for st in self.db.q("SELECT * FROM stations ORDER BY type, id"):
            row = {"id": st["id"], "name": st["name"], "type": st["type"], "session": None}
            if admin:
                row["rate"] = st["rate"]
            s = sess.get(st["id"])
            if s:
                secs = play_secs(s, now)
                row["session"] = {"id": s["id"], "customer": s["customer"], "game": s["game"],
                                  "elapsed": secs, "paused": bool(s["paused_at"])}
                if admin:
                    row["session"].update(time_charge=time_charge(s["rate"], secs, self.round_min()),
                                          food=food.get(s["id"], 0) or 0)
            out.append(row)
        return {"now": now, "stations": out, "currency": self.cfg("currency", "₹")}

    def menu(self):
        return [dict(r) for r in self.db.q("SELECT id,category,name,price FROM menu ORDER BY category, name")]

    def session_detail(self, sid, admin):
        r = self.db.q("SELECT * FROM sessions WHERE id=?", (sid,))
        if not r:
            raise ApiError(404, "Session not found.")
        s, now = r[0], RDB.now()
        orders = [{"id": o["id"], "item": o["item_name"], "qty": o["qty"], **({"price": o["price"]} if admin else {})}
                  for o in self.db.q("SELECT * FROM orders WHERE session_id=? ORDER BY id", (sid,))]
        d = {"id": s["id"], "station": s["station_name"], "customer": s["customer"], "status": s["status"],
             "elapsed": play_secs(s, s["end_ts"] or now), "orders": orders}
        if admin:
            food = sum(o["price"] * o["qty"] for o in orders)
            d.update(rate=s["rate"], food=food, time_charge=time_charge(s["rate"], d["elapsed"], self.round_min()))
        return d

    def events(self, after):
        new = [dict(r) for r in self.db.q("SELECT * FROM food_events WHERE id>? ORDER BY id", (after,))]
        pending = [dict(r) for r in self.db.q(
            "SELECT e.* FROM food_events e JOIN sessions s ON s.id=e.session_id AND s.status='active' "
            "WHERE e.source='reception' AND e.served_ts IS NULL ORDER BY e.id")]
        last = self.db.q("SELECT COALESCE(MAX(id),0) m FROM food_events")[0]["m"]
        return {"events": new, "pending": pending, "last": last}

    def report(self):
        now = RDB.now_dt()
        base = now.replace(hour=int(float(self.cfg("day_start", "5"))), minute=0, second=0, microsecond=0)
        if now < base:
            base -= RDB.dt.timedelta(days=1)
        t0 = base.timestamp()
        rows = self.db.q("SELECT * FROM sessions WHERE status='closed' AND end_ts>=? AND end_ts<? ORDER BY end_ts DESC",
                         (t0, t0 + 86400))
        by = {}
        for r in rows:
            by[r["payment"] or "-"] = by.get(r["payment"] or "-", 0) + (r["total"] or 0)
        return {"since": t0, "count": len(rows), "total": sum(r["total"] or 0 for r in rows), "by_payment": by,
                "sessions": [{"station": r["station_name"], "customer": r["customer"], "end": r["end_ts"],
                              "total": r["total"], "payment": r["payment"]} for r in rows[:100]]}

    # -- writing
    def add_food(self, user, sid, item_id, qty):
        qty = int(qty)
        if not 1 <= qty <= 50:
            raise ApiError(400, "Quantity must be between 1 and 50.")
        it = self.db.q("SELECT * FROM menu WHERE id=?", (int(item_id),))
        if not it:
            raise ApiError(404, "That item is no longer on the menu.")
        src = "staff" if user["role"] == "staff" else "reception"
        who = user["username"] if src == "staff" else "Reception"
        if not self.db.add_food(int(sid), it[0]["category"], it[0]["name"], it[0]["price"], qty, who, src):
            raise ApiError(409, "That session has already ended.")

    def mark_served(self, user, eid):
        self.db.x("UPDATE food_events SET served_ts=?, served_by=? WHERE id=? AND served_ts IS NULL",
                  (RDB.now(), user["username"], int(eid)))

    def start(self, station_id, customer, phone, game):
        customer = (customer or "").strip()
        if not customer:
            raise ApiError(400, "Please enter the customer's name.")
        try:
            n = self.db.x(
                "INSERT INTO sessions(station_id,station_name,station_type,customer,phone,game,start_ts,rate,status)"
                " SELECT id,name,type,?,?,?,?,rate,'active' FROM stations WHERE id=?",
                (customer, (phone or "").strip(), (game or "").strip() or "-",
                 RDB.now(), int(station_id)))
        except RDB.IntegrityError:
            raise ApiError(409, "That station is already running (another PC just started it).")
        if not n:
            raise ApiError(404, "Station not found.")

    def pause(self, sid):
        self.db.x("UPDATE sessions SET paused_at=? WHERE id=? AND status='active' AND paused_at IS NULL",
                  (RDB.now(), int(sid)))

    def resume(self, sid):
        self.db.x("UPDATE sessions SET paused_total=COALESCE(paused_total,0)+(?-paused_at), paused_at=NULL"
                  " WHERE id=? AND status='active' AND paused_at IS NOT NULL", (RDB.now(), int(sid)))

    def end(self, sid, discount, payment):
        r = self.db.q("SELECT * FROM sessions WHERE id=? AND status='active'", (int(sid),))
        if not r:
            raise ApiError(409, "That session was already ended.")
        s, end = r[0], RDB.now()
        tc = time_charge(s["rate"], play_secs(s, end), self.round_min())
        food = self.db.q("SELECT COALESCE(SUM(price*qty),0) t FROM orders WHERE session_id=?", (s["id"],))[0]["t"]
        disc = min(max(0.0, float(discount or 0)), tc + food)
        extra = max(0, end - s["paused_at"]) if s["paused_at"] else 0
        payment = payment if payment in PAYMENTS else "Cash"
        if not self.db.x(
                "UPDATE sessions SET end_ts=?, time_charge=?, food_total=?, discount=?, total=?, payment=?,"
                " status='closed', paused_total=COALESCE(paused_total,0)+?, paused_at=NULL WHERE id=? AND status='active'",
                (end, tc, food, disc, tc + food - disc, payment, extra, s["id"])):
            raise ApiError(409, "That session was already ended.")
        return {"time_charge": tc, "food": food, "discount": disc, "total": tc + food - disc}

    def cancel(self, sid):
        self.db.x("DELETE FROM orders WHERE session_id=? AND EXISTS (SELECT 1 FROM sessions WHERE id=? AND status='active')",
                  (int(sid), int(sid)))
        self.db.x("DELETE FROM sessions WHERE id=? AND status='active'", (int(sid),))

    def save_menu(self, d):
        name, cat, price = str(d.get("name", "")).strip(), str(d.get("category", "")).strip(), float(d.get("price", 0))
        if not name or not cat or price < 0:
            raise ApiError(400, "Give a category, a name and a price.")
        if d.get("id"):
            self.db.x("UPDATE menu SET category=?, name=?, price=? WHERE id=?", (cat, name, price, int(d["id"])))
        else:
            self.db.x("INSERT INTO menu(category,name,price) VALUES(?,?,?)", (cat, name, price))

    def save_station(self, d):
        name, typ, rate = str(d.get("name", "")).strip(), d.get("type"), float(d.get("rate", 0))
        if not name or typ not in RDB.STATION_TYPES or rate < 0:
            raise ApiError(400, "Give a name, a type and a rate.")
        if d.get("id"):
            self.db.x("UPDATE stations SET name=?, type=?, rate=? WHERE id=?", (name, typ, rate, int(d["id"])))
        else:
            self.db.x("INSERT INTO stations(name,type,rate) VALUES(?,?,?)", (name, typ, rate))

    def delete_station(self, sid):
        if self.db.q("SELECT 1 FROM sessions WHERE station_id=? AND status='active'", (int(sid),)):
            raise ApiError(409, "That station has a running session.")
        self.db.x("DELETE FROM stations WHERE id=?", (int(sid),))

    def users(self):
        return [{"id": r["id"], "username": r["username"], "role": r["role"], "active": bool(r["active"])}
                for r in self.db.q("SELECT * FROM app_users ORDER BY role, username")]

    def save_user(self, me, d):
        name, role, pw = str(d.get("username", "")).strip(), d.get("role"), str(d.get("password", ""))
        active = 1 if d.get("active", True) else 0
        if not name or role not in ROLES:
            raise ApiError(400, "Give a user name and a role.")
        ex = self.db.q("SELECT * FROM app_users WHERE lower(username)=lower(?)", (name,))
        if ex:
            u = ex[0]
            if u["id"] == me["id"] and (role != "admin" or not active):
                raise ApiError(400, "You cannot remove your own admin access.")
            self.db.x("UPDATE app_users SET role=?, active=? WHERE id=?", (role, active, u["id"]))
            if pw:
                self.set_password(u["id"], pw)
        else:
            if len(pw) < 6:
                raise ApiError(400, "New users need a password of at least 6 characters.")
            self.db.x("INSERT INTO app_users(username,pw_hash,role,active) VALUES(?,?,?,?)",
                      (name, hash_pw(pw), role, active))

    def set_password(self, uid, pw):
        if len(pw) < 6:
            raise ApiError(400, "The password needs at least 6 characters.")
        self.db.x("UPDATE app_users SET pw_hash=? WHERE id=?", (hash_pw(pw), uid))


# ---------------------------------------------------------------- HTTP
SVC = None
APP_KEY = ""                                           # secret built into the APK; requests without it get "404"
ALLOWED_ORIGINS = {"http://localhost", "https://localhost", "capacitor://localhost"}   # the APK's own origin only


def load_app_key():
    """phone_key.txt next to this file.  make_apk.py puts the same key inside the APK.  Delete the file and restart
    the server to make every APK built before that stop working."""
    path = os.path.join(HERE, "phone_key.txt")
    try:
        with open(path, encoding="utf-8") as fh:
            key = fh.read().strip()
        if len(key) >= 16:
            return key
    except OSError:
        pass
    key = secrets.token_hex(24)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(key + "\n")
    return key


class Handler(BaseHTTPRequestHandler):
    server_version = "RedLine"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:                  # only the APK's own page may call from a web view
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def reply(self, code, obj):
        self.send(code, json.dumps(obj, default=str))

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 100_000:
            raise ApiError(413, "Request too large.")
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_OPTIONS(self):                              # browser-style pre-flight (only for the APK's own origin)
        origin = self.headers.get("Origin")
        if origin not in ALLOWED_ORIGINS:
            return self.send(404, "Not found", "text/plain")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-RedLine-Key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def route(self, method):
        path = self.path.split("?")[0]
        try:
            # No web page is served at all.  Only the APK knows the key, so a browser (or anything else) gets "404".
            sent = self.headers.get("X-RedLine-Key", "")
            if not path.startswith("/api/") or not APP_KEY or not hmac.compare_digest(sent, APP_KEY):
                return self.send(404, "Not found", "text/plain")
            if path == "/api/health":
                return self.reply(200, {"ok": True, "licensed": LIC.ok})
            if not LIC.ok:                                # revoked / missing key: everything stops
                return self.reply(403, {"error": LIC.msg or "The product key is not valid.", "license": True})
            data = self.dispatch(method, path)
            self.reply(200, data if data is not None else {"ok": True})
        except ApiError as e:
            self.reply(e.code, {"error": e.msg})
        except RDB.ServerOffline as e:
            self.reply(503, {"error": "The database is not reachable: " + str(e)})
        except (ValueError, KeyError, TypeError):
            self.reply(400, {"error": "Bad request."})
        except Exception as e:                            # never leak internals to the phone
            sys.stderr.write(f"error on {path}: {e!r}\n")
            self.reply(500, {"error": "Server error."})

    def dispatch(self, method, path):
        if path == "/api/login" and method == "POST":
            d = self.body()
            u = SVC.auth.login(self.client_address[0], str(d.get("username", "")), str(d.get("password", "")))
            return {"token": SVC.auth.make_token(u["id"]), "username": u["username"], "role": u["role"]}
        tok = (self.headers.get("Authorization") or "").replace("Bearer ", "")
        me = SVC.auth.user_from_token(tok)
        if not me:
            raise ApiError(401, "Please sign in again.")
        admin = me["role"] == "admin"
        q = self.path.split("?", 1)[1] if "?" in self.path else ""
        qs = dict(p.split("=", 1) for p in q.split("&") if "=" in p)
        d = self.body() if method == "POST" else {}
        S = SVC

        # ---- both roles (staff: food only) ----
        if path == "/api/me":
            return {"username": me["username"], "role": me["role"]}
        if path == "/api/state":
            return S.state(admin)
        if path == "/api/menu":
            return S.menu()
        if path == "/api/session":
            return S.session_detail(int(qs.get("id", 0)), admin)
        if path == "/api/events":
            return S.events(int(qs.get("after", 0)))
        if path == "/api/order" and method == "POST":
            return S.add_food(me, d["session_id"], d["item_id"], d.get("qty", 1))
        if path == "/api/served" and method == "POST":
            return S.mark_served(me, d["event_id"])

        # ---- admin only: the whole application ----
        if not admin:
            raise ApiError(403, "Only admin can do that.")
        if path == "/api/session/start":
            return S.start(d["station_id"], d.get("customer"), d.get("phone"), d.get("game"))
        if path == "/api/session/pause":
            return S.pause(d["session_id"])
        if path == "/api/session/resume":
            return S.resume(d["session_id"])
        if path == "/api/session/end":
            return S.end(d["session_id"], d.get("discount", 0), d.get("payment"))
        if path == "/api/session/cancel":
            return S.cancel(d["session_id"])
        if path == "/api/order/qty":
            S.db.x("UPDATE orders SET qty=qty+? WHERE id=? AND EXISTS (SELECT 1 FROM sessions s WHERE s.id=session_id AND s.status='active')",
                   (int(d["delta"]), int(d["order_id"])))
            S.db.x("DELETE FROM orders WHERE id=? AND qty<=0", (int(d["order_id"]),))
            return None
        if path == "/api/report":
            return S.report()
        if path == "/api/menu/save":
            return S.save_menu(d)
        if path == "/api/menu/delete":
            S.db.x("DELETE FROM menu WHERE id=?", (int(d["id"]),))
            return None
        if path == "/api/station/save":
            return S.save_station(d)
        if path == "/api/station/delete":
            return S.delete_station(d["id"])
        if path == "/api/users":
            return S.users()
        if path == "/api/users/save":
            return S.save_user(me, d)
        raise ApiError(404, "Unknown request.")


# ---------------------------------------------------------------- command line
def cli_user(db, args):
    cmd = args[0] if args else ""
    if cmd == "list":
        for u in Service(db).users():
            print(f"{u['username']:20} {u['role']:6} {'active' if u['active'] else 'DISABLED'}")
    elif cmd in ("add", "passwd") and len(args) >= 2:
        name = args[1]
        role = args[2] if len(args) > 2 else "staff"
        if cmd == "add" and role not in ROLES:
            sys.exit("Role must be admin or staff.")
        pw = getpass.getpass("Password (min 6 characters): ")
        if pw != getpass.getpass("Again: "):
            sys.exit("Passwords did not match.")
        svc = Service(db)
        if cmd == "add":
            svc.save_user({"id": 0}, {"username": name, "role": role, "password": pw})
        else:
            u = db.q("SELECT id FROM app_users WHERE lower(username)=lower(?)", (name,))
            if not u:
                sys.exit("No such user.")
            svc.set_password(u[0]["id"], pw)
        print("Saved.")
    elif cmd == "disable" and len(args) >= 2:
        db.x("UPDATE app_users SET active=0 WHERE lower(username)=lower(?)", (args[1],))
        print("Disabled.")
    else:
        sys.exit(__doc__)


TASK = "RedLinePhoneServer"


def _ps(script):
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()


def _startup_vbs():
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
                        "RedLinePhoneServer.vbs")


def _stop_running():
    """Stop a hidden (pythonw) copy of this server, so a new one can take its place."""
    _ps("Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe'\" | "
        "Where-Object { $_.CommandLine -like '*redline_api.py*' } | "
        "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }")


def _is_running():
    code, out = _ps("(Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe'\" | "
                    "Where-Object { $_.CommandLine -like '*redline_api.py*' } | Measure-Object).Count")
    return out.strip() not in ("", "0")


def task_cmd(cmd):
    """Windows only: run the phone server hidden at every log-in.
    First choice: Task Scheduler (restarts the server if it stops). Fallback: a hidden script in the Startup folder."""
    if os.name != "nt":
        sys.exit("The automatic start is for Windows. On Linux/macOS use systemd / launchd.")
    q = lambda t: str(t).replace("'", "''")
    me = os.path.abspath(__file__)
    if cmd == "install":
        exe = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")     # pythonw = Python without a window
        exe = exe if os.path.isfile(exe) else sys.executable
        _stop_running()
        code, out = _ps(
            f"$a = New-ScheduledTaskAction -Execute '{q(exe)}' -Argument '\"{q(me)}\"' -WorkingDirectory '{q(HERE)}'; "
            "$u = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; "          # COMPUTER\\name form
            "$t = New-ScheduledTaskTrigger -AtLogOn -User $u; "
            "$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited; "
            "$s = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) "
            "-ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries "
            "-DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew; "
            f"Register-ScheduledTask -TaskName '{TASK}' -Action $a -Trigger $t -Principal $p -Settings $s -Force "
            f"-ErrorAction Stop | Out-Null; Start-ScheduledTask -TaskName '{TASK}' -ErrorAction Stop")
        how = "Task Scheduler (it also restarts the server if it ever stops)"
        if code:                                                              # fallback: Startup folder, no admin needed
            try:
                vbs = _startup_vbs()
                with open(vbs, "w", encoding="utf-8") as fh:
                    fh.write('Set sh = CreateObject("WScript.Shell")\r\n'
                             f'sh.CurrentDirectory = "{HERE}"\r\n'
                             f'sh.Run """{exe}"" ""{me}""", 0, False\r\n')
                subprocess.Popen([exe, me], cwd=HERE, close_fds=True, creationflags=0x08000000 | 0x00000008)
                how = "your Windows Startup folder (Task Scheduler was refused: " + out.splitlines()[0][:80] + ")"
            except OSError as e:
                sys.exit("Could not set it up: " + str(e))
        print("Done. The phone server now starts by itself every time you log in to Windows, with no window.\n"
              "Set up with: " + how + "\nIt is running now.  Messages go to: "
              + os.path.join(RDB.APP_DIR, "phone_server.log"))
    elif cmd == "uninstall":
        _stop_running()
        _ps(f"Stop-ScheduledTask -TaskName '{TASK}' -ErrorAction SilentlyContinue")
        _ps(f"Unregister-ScheduledTask -TaskName '{TASK}' -Confirm:$false -ErrorAction SilentlyContinue")
        try:
            os.remove(_startup_vbs())
        except OSError:
            pass
        print("Removed. The phone server will no longer start by itself.")
    else:
        code, out = _ps(f"(Get-ScheduledTask -TaskName '{TASK}' -ErrorAction Stop).State")
        task = not code
        vbs = os.path.isfile(_startup_vbs())
        print("Automatic start: " + ("Task Scheduler" if task else "Startup folder" if vbs else "NOT installed"))
        print("Server running now: " + ("yes" if _is_running() else "no"))


def main():
    global SVC, APP_KEY
    if len(sys.argv) > 1 and sys.argv[1] in ("install", "uninstall", "status"):
        return task_cmd(sys.argv[1])
    if sys.stdout is None or sys.stderr is None:        # started without a window (pythonw): write to a log file
        path = os.path.join(RDB.APP_DIR, "phone_server.log")
        mode = "w" if os.path.isfile(path) and os.path.getsize(path) > 1_000_000 else "a"
        sys.stdout = sys.stderr = open(path, mode, encoding="utf-8", buffering=1)
    cfg = RDB.load_config()
    if not cfg:
        sys.exit("No server details yet. Run the desktop app once on this PC to save them.")
    try:
        db = RDB.DB(cfg)
    except RDB.ServerOffline as e:
        sys.exit(f"Cannot reach the database: {e}")
    if len(sys.argv) > 1 and sys.argv[1] == "user":
        return cli_user(db, sys.argv[2:])
    SVC = Service(db)
    APP_KEY = load_app_key()
    if not db.q("SELECT 1 FROM app_users WHERE role='admin' AND active=1"):
        print("No admin login exists yet - create one:")
        name = input("Admin user name: ").strip()
        pw = getpass.getpass("Password (min 6 characters): ")
        SVC.save_user({"id": 0}, {"username": name, "role": "admin", "password": pw})
    LIC.check()
    if not LIC.ok:
        print("WARNING: phones are locked -", LIC.msg)
    threading.Thread(target=LIC.watch, daemon=True).start()
    ts = ""
    try:                                                  # show the address phones should use
        ts = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5).stdout.split()[0]
    except Exception:
        pass
    print(f"Red Line phone server running on port {PORT}.  Press Ctrl+C to stop.")
    print("The APK connects to:  " + (f"{ts}:{PORT}   (this PC's Tailscale address)" if ts
                                      else f"<this PC's Tailscale IP>:{PORT}"))
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
