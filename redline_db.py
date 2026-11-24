#!/usr/bin/env python3
"""
Red Line - database layer (PostgreSQL server)
---------------------------------------------
All PCs connect to ONE PostgreSQL server (the mini PC), so stations, sessions,
orders and sales are shared live.  Keep this file next to game_cafe_manager.py.

Needs:  pip install psycopg2-binary
"""
import datetime as dt
import json
import os
import pathlib
import select
import sqlite3
import threading
import time

try:
    import psycopg2
    import psycopg2.extras
    IntegrityError = psycopg2.IntegrityError
except ImportError:                                  # the app shows a clear message for this
    psycopg2 = None

    class IntegrityError(Exception):
        pass

APP_DIR = os.path.join(os.path.expanduser("~"), "GameCafeManager")
SERVER_CONFIG_PATH = os.path.join(APP_DIR, "server.json")
BACKUP_DIR = os.path.join(APP_DIR, "backups")
DEFAULT_CONFIG = {"host": "", "port": 5432, "dbname": "redline", "user": "redline", "password": ""}

STATION_TYPES = ("pool", "ps5", "pc", "sim")


class ServerOffline(Exception):
    """The server cannot be reached.  The message is safe to show to the user."""


class DataError(Exception):
    """Message is safe to show to the user."""


# --------------------------------------------------------------------------
# connection settings (stored on each PC)
# --------------------------------------------------------------------------
def load_config():
    try:
        with open(SERVER_CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    cfg = dict(DEFAULT_CONFIG)
    cfg.update({k: data[k] for k in DEFAULT_CONFIG if k in data})
    try:
        cfg["port"] = int(cfg["port"])
    except (TypeError, ValueError):
        cfg["port"] = 5432
    return cfg if str(cfg["host"]).strip() else None


def save_config(cfg):
    os.makedirs(APP_DIR, exist_ok=True)
    clean = {k: cfg.get(k, DEFAULT_CONFIG[k]) for k in DEFAULT_CONFIG}
    clean["host"] = str(clean["host"]).strip()
    clean["port"] = int(clean["port"])
    with open(SERVER_CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(clean, fh, indent=1)
    try:
        os.chmod(SERVER_CONFIG_PATH, 0o600)          # best effort (ignored on Windows)
    except OSError:
        pass


def describe(cfg):
    return f"{cfg['host']}:{cfg['port']}  /  {cfg['dbname']}"


def friendly(err):
    s = str(err).strip()
    low = s.lower()
    if "password authentication failed" in low:
        return "Wrong user name or password."
    if "no pg_hba.conf entry" in low:
        return "The server refused this PC. Allow it in pg_hba.conf on the mini PC (see SERVER_SETUP.md)."
    if "database" in low and "does not exist" in low:
        return "The server is reachable, but that database name does not exist."
    if "timeout expired" in low or "timed out" in low:
        return ("The server did not answer. Check the address, that the mini PC is switched on, "
                "and that the firewall allows port 5432.")
    if ("refused" in low or "could not connect" in low or "could not translate" in low
            or "no route" in low or "unreachable" in low):
        return ("Cannot reach the server. Check the address, that the mini PC is on and on the same "
                "network, and that PostgreSQL is running.")
    return s.splitlines()[0] if s else "Unknown error."


def test_connection(cfg):
    """Returns None when the connection works, else a message for the user."""
    if psycopg2 is None:
        return "The database driver is missing.  Run:  pip install psycopg2-binary"
    try:
        con = psycopg2.connect(host=cfg["host"], port=int(cfg["port"]), dbname=cfg["dbname"],
                               user=cfg["user"], password=cfg["password"], connect_timeout=5)
        con.close()
    except psycopg2.Error as e:
        return friendly(e)
    except (ValueError, TypeError):
        return "Check the port number."
    return None


# --------------------------------------------------------------------------
# server clock: every PC uses the SERVER's time, so timers and bills agree
# --------------------------------------------------------------------------
_offset = 0.0


def now():
    """Seconds since 1970 according to the server's clock."""
    return time.time() + _offset


def now_dt():
    return dt.datetime.fromtimestamp(now())


# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS stations(
    id SERIAL PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL,
    rate DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS menu(
    id SERIAL PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL,
    price DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
    id SERIAL PRIMARY KEY, station_id INTEGER, station_name TEXT, station_type TEXT,
    customer TEXT, phone TEXT, game TEXT,
    start_ts DOUBLE PRECISION, end_ts DOUBLE PRECISION, rate DOUBLE PRECISION,
    time_charge DOUBLE PRECISION DEFAULT 0, food_total DOUBLE PRECISION DEFAULT 0,
    discount DOUBLE PRECISION DEFAULT 0, total DOUBLE PRECISION DEFAULT 0,
    payment TEXT, status TEXT DEFAULT 'active',
    paused_at DOUBLE PRECISION, paused_total DOUBLE PRECISION DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(
    id SERIAL PRIMARY KEY, session_id INTEGER NOT NULL,
    category TEXT, item_name TEXT, price DOUBLE PRECISION, qty INTEGER);
CREATE TABLE IF NOT EXISTS app_users(
    id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
    role TEXT NOT NULL, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS food_events(
    id SERIAL PRIMARY KEY, session_id INTEGER, station_name TEXT, customer TEXT,
    item_name TEXT, qty INTEGER, source TEXT, added_by TEXT,
    created_ts DOUBLE PRECISION, served_ts DOUBLE PRECISION, served_by TEXT);
CREATE INDEX IF NOT EXISTS sessions_end_idx ON sessions(end_ts);
CREATE INDEX IF NOT EXISTS orders_session_idx ON orders(session_id);
"""
ACTIVE_INDEX = ("CREATE UNIQUE INDEX IF NOT EXISTS one_active_session "
                "ON sessions(station_id) WHERE status='active'")
NOTIFY_CHANNEL = "redline_changes"
NOTIFY_FN = """CREATE OR REPLACE FUNCTION redline_notify() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('redline_changes', TG_TABLE_NAME);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql"""
SYNC_TABLES = ("settings", "stations", "menu", "sessions", "orders", "food_events")
LOCK_KEY = 727272                                    # advisory lock used while creating the tables


class _Listener(threading.Thread):
    """Background thread with its OWN connection.  It sleeps until PostgreSQL says 'something changed'
    (LISTEN/NOTIFY) and only records the table names - it never touches the screen or the main connection."""

    def __init__(self, cfg):
        super().__init__(daemon=True, name="RedLineListener")
        self.cfg = dict(cfg)
        self.stop_ev = threading.Event()
        self.lock = threading.Lock()
        self.tables = set()
        self.alive = False

    def run(self):
        backoff = 1
        while not self.stop_ev.is_set():
            con = None
            try:
                con = psycopg2.connect(
                    host=self.cfg["host"], port=int(self.cfg["port"]), dbname=self.cfg["dbname"],
                    user=self.cfg["user"], password=self.cfg["password"], connect_timeout=5,
                    application_name="RedLine-listen",
                    keepalives=1, keepalives_idle=20, keepalives_interval=5, keepalives_count=3)
                con.autocommit = True
                cur = con.cursor()
                cur.execute("LISTEN " + NOTIFY_CHANNEL)
                cur.close()
                self.alive, backoff = True, 1
                with self.lock:
                    self.tables.add("*")              # (re)connected: anything may have changed meanwhile
                while not self.stop_ev.is_set():
                    if select.select([con], [], [], 2.0)[0]:
                        con.poll()
                        got = set()
                        while con.notifies:
                            got.add(con.notifies.pop(0).payload or "*")
                        if got:
                            with self.lock:
                                self.tables |= got
            except Exception:
                pass                                   # network blip: reconnect below
            finally:
                self.alive = False
                if con is not None:
                    try:
                        con.close()
                    except Exception:
                        pass
            if self.stop_ev.wait(backoff):
                break
            backoff = min(backoff * 2, 10)

    def pop(self):
        with self.lock:
            got, self.tables = self.tables, set()
        return got


class DB:
    """Same small interface the app always used:  q() reads, x() writes."""

    def __init__(self, cfg, seed=True):
        if psycopg2 is None:
            raise ServerOffline("The database driver is missing.\nRun:  pip install psycopg2-binary")
        self.cfg = dict(cfg)
        self.con = None
        self._lock = threading.RLock()
        self._listener = None
        self.connect()
        self.init_schema(seed)
        self.sync_clock()
        self.start_listener()

    # ---- connection ----
    def connect(self):
        self._drop()
        try:
            con = psycopg2.connect(
                host=self.cfg["host"], port=int(self.cfg["port"]), dbname=self.cfg["dbname"],
                user=self.cfg["user"], password=self.cfg["password"], connect_timeout=5,
                application_name="RedLine", options="-c statement_timeout=15000",
                keepalives=1, keepalives_idle=20, keepalives_interval=5, keepalives_count=3,
                cursor_factory=psycopg2.extras.DictCursor)
        except psycopg2.Error as e:
            raise ServerOffline(friendly(e))
        con.autocommit = True                         # every statement is its own transaction
        self.con = con

    def _drop(self):
        if self.con is not None:
            try:
                self.con.close()
            except Exception:
                pass
        self.con = None

    def _ready(self):
        """Make sure there is a live connection (nothing has been sent yet, so this is safe)."""
        if self.con is not None and not self.con.closed:
            try:
                cur = self.con.cursor()
                cur.execute("SELECT 1")
                cur.close()
                return
            except (psycopg2.OperationalError, psycopg2.InterfaceError):
                pass
        self.connect()

    @staticmethod
    def _sql(sql):
        return sql.replace("?", "%s")

    # ---- the interface used by the app ----
    def q(self, sql, args=()):
        sql = self._sql(sql)
        with self._lock:
            for attempt in (1, 2):                    # reads are harmless to repeat
                try:
                    if self.con is None or self.con.closed:
                        self.connect()
                    cur = self.con.cursor()
                    cur.execute(sql, tuple(args) if args else None)
                    rows = cur.fetchall()
                    cur.close()
                    return rows
                except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                    self._drop()
                    if attempt == 2:
                        raise ServerOffline(friendly(e))

    def x(self, sql, args=()):
        """Run a write.  Returns the number of rows changed."""
        sql = self._sql(sql)
        with self._lock:
            self._ready()
            try:
                cur = self.con.cursor()
                cur.execute(sql, tuple(args) if args else None)
                n = cur.rowcount
                cur.close()
                return n
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                self._drop()                          # never repeat a write blindly
                raise ServerOffline("Lost the connection to the server while saving. "
                                    "Check the screen before repeating the action.\n" + friendly(e))

    def run_many(self, ops):
        """Run [(sql, args), ...] as ONE transaction: all of it happens or none of it."""
        with self._lock:
            self._ready()
            cur = self.con.cursor()
            try:
                cur.execute("BEGIN")
                for sql, args in ops:
                    cur.execute(self._sql(sql), tuple(args) if args else None)
                cur.execute("COMMIT")
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                self._drop()
                raise ServerOffline("Lost the connection to the server. Nothing was changed.\n" + friendly(e))
            except Exception:
                try:
                    cur.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def add_food(self, sid, category, name, price, qty, who, source):
        """The ONE way food is added (reception PC or staff phone): updates the bill and tells the other side.
        Returns False when the session has already ended."""
        live = "EXISTS (SELECT 1 FROM sessions WHERE id=? AND status='active')"
        done = 0
        ex = self.q("SELECT id FROM orders WHERE session_id=? AND item_name=? AND price=?", (sid, name, price))
        if ex:
            done = self.x("UPDATE orders SET qty=qty+? WHERE id=? AND " + live, (qty, ex[0]["id"], sid))
        if not done:
            done = self.x("INSERT INTO orders(session_id,category,item_name,price,qty) SELECT ?,?,?,?,? WHERE " + live,
                          (sid, category, name, price, qty, sid))
        if done:
            self.x("INSERT INTO food_events(session_id,station_name,customer,item_name,qty,source,added_by,created_ts)"
                   " SELECT ?,station_name,customer,?,?,?,?,? FROM sessions WHERE id=?",
                   (sid, name, qty, source, who, now(), sid))
        return bool(done)

    def setting(self, key, default=None):
        r = self.q("SELECT value FROM settings WHERE key=?", (key,))
        return r[0]["value"] if r else default

    def set_setting(self, key, value):
        self.x("INSERT INTO settings(key,value) VALUES(?,?) "
               "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (key, str(value)))

    def close(self):
        if self._listener is not None:
            self._listener.stop_ev.set()
            self._listener = None
        self._drop()

    # ---- instant "another PC changed something" signal ----
    def start_listener(self):
        if self._listener is None and getattr(self, "push_ready", False):
            self._listener = _Listener(self.cfg)
            self._listener.start()

    @property
    def push_ok(self):
        """True while the instant-update channel is connected (the app then polls far less often)."""
        return self._listener is not None and self._listener.alive

    def pop_changes(self):
        """Names of tables that changed since the last call (empty set = nothing). Cheap: no server round-trip."""
        return self._listener.pop() if self._listener is not None else set()

    def _ensure_push(self):
        """Create the notify function + one trigger per table (only if missing, so running PCs are never blocked)."""
        try:
            self.x(NOTIFY_FN)
            for t in SYNC_TABLES:
                if not self.q("SELECT 1 FROM pg_trigger WHERE tgname='redline_sync' "
                              "AND tgrelid=%s::regclass" % ("'" + t + "'",)):
                    self.x(f"CREATE TRIGGER redline_sync AFTER INSERT OR UPDATE OR DELETE ON {t} "
                           f"FOR EACH STATEMENT EXECUTE PROCEDURE redline_notify()")
            self.push_ready = True
        except psycopg2.Error:
            self.push_ready = False                   # no permission etc.: the app simply keeps polling

    # ---- server clock ----
    def sync_clock(self):
        global _offset
        t0 = time.time()
        rows = self.q("SELECT EXTRACT(EPOCH FROM clock_timestamp())::float8 AS t")
        t1 = time.time()
        _offset = float(rows[0]["t"]) - (t0 + t1) / 2

    # ---- tables + first-run defaults ----
    def init_schema(self, seed):
        with self._lock:
            self.x("SELECT pg_advisory_lock(?)", (LOCK_KEY,))     # two PCs starting together: one waits
            try:
                self.x(SCHEMA)
                try:
                    self.x(ACTIVE_INDEX)              # one running session per station, enforced here
                except IntegrityError:
                    pass                              # old data had duplicates: the app still works
                if seed:
                    self.seed()
                self._ensure_push()
            finally:
                self.x("SELECT pg_advisory_unlock(?)", (LOCK_KEY,))

    def seed(self):
        if not self.q("SELECT 1 FROM stations LIMIT 1"):
            ops = []
            for i in (1, 2):
                ops.append(("INSERT INTO stations(name,type,rate) VALUES(?,?,?)", (f"Pool Table {i}", "pool", 250)))
            for i in (1, 2, 3):
                ops.append(("INSERT INTO stations(name,type,rate) VALUES(?,?,?)", (f"PS5 {i}", "ps5", 150)))
            for i in range(1, 7):
                ops.append(("INSERT INTO stations(name,type,rate) VALUES(?,?,?)", (f"PC {i}", "pc", 80)))
            ops.append(("INSERT INTO stations(name,type,rate) VALUES(?,?,?)", ("Car Simulator 1", "sim", 300)))
            ops.append(("INSERT INTO settings(key,value) VALUES('sim_added','1') "
                        "ON CONFLICT (key) DO NOTHING", ()))
            self.run_many(ops)
        if not self.q("SELECT 1 FROM menu LIMIT 1"):
            items = {
                "Snacks": [("French Fries", 80), ("Nachos", 120), ("Veg Sandwich", 90),
                           ("Maggi", 60), ("Burger", 110), ("Chips", 20)],
                "Drinks": [("Water Bottle", 20), ("Tea", 20), ("Cold Coffee", 90),
                           ("Coke", 40), ("Energy Drink", 110), ("Lemon Soda", 40)],
                "Smokes": [("Cigarette (single)", 20), ("Lighter", 20)],
            }
            self.run_many([("INSERT INTO menu(category,name,price) VALUES(?,?,?)", (cat, n, p))
                           for cat, lst in items.items() for n, p in lst])
        for k, v in {"currency": "₹", "round_min": "1", "day_start": "5"}.items():
            self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT (key) DO NOTHING", (k, v))

    # ---- copy everything from an old single-PC cafe.db into the server ----
    def import_sqlite(self, path):
        """Replace the server's stations / menu / settings / sales with the contents of an old cafe.db.

        Only allowed while the server has no sales yet, so nothing real can be overwritten.
        """
        if not os.path.isfile(path):
            raise DataError("That file was not found.")
        if self.q("SELECT 1 FROM sessions LIMIT 1"):
            raise DataError("The server already has sales or sessions in it.\n"
                            "Importing is only allowed into a fresh server, so nothing is overwritten.")
        try:
            src = sqlite3.connect(pathlib.Path(path).resolve().as_uri() + "?mode=ro", uri=True)
            src.row_factory = sqlite3.Row
            have = {r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"stations", "menu", "sessions", "orders"} <= have:
                raise DataError("This does not look like a Red Line cafe.db file.")
            rows = {t: src.execute(f"SELECT * FROM {t}").fetchall()
                    for t in ("stations", "menu", "sessions", "orders", "settings") if t in have}
        except sqlite3.Error as e:
            raise DataError(f"Could not read that database:\n{e}")
        finally:
            try:
                src.close()
            except Exception:
                pass

        def g(r, k, default=None):
            return r[k] if k in r.keys() and r[k] is not None else default

        ops = [(f"DELETE FROM {t}", ()) for t in ("orders", "sessions", "menu", "stations", "settings")]
        for r in rows["stations"]:
            ops.append(("INSERT INTO stations(id,name,type,rate) VALUES(?,?,?,?)",
                        (r["id"], r["name"], r["type"], r["rate"])))
        for r in rows["menu"]:
            ops.append(("INSERT INTO menu(id,category,name,price) VALUES(?,?,?,?)",
                        (r["id"], r["category"], r["name"], r["price"])))
        for r in rows["sessions"]:
            ops.append((
                "INSERT INTO sessions(id,station_id,station_name,station_type,customer,phone,game,start_ts,"
                "end_ts,rate,time_charge,food_total,discount,total,payment,status,paused_at,paused_total)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["id"], g(r, "station_id"), g(r, "station_name"), g(r, "station_type"), g(r, "customer"),
                 g(r, "phone"), g(r, "game"), g(r, "start_ts"), g(r, "end_ts"), g(r, "rate", 0),
                 g(r, "time_charge", 0), g(r, "food_total", 0), g(r, "discount", 0), g(r, "total", 0),
                 g(r, "payment"), g(r, "status", "closed"), g(r, "paused_at"), g(r, "paused_total", 0))))
        for r in rows["orders"]:
            ops.append(("INSERT INTO orders(id,session_id,category,item_name,price,qty) VALUES(?,?,?,?,?,?)",
                        (r["id"], r["session_id"], g(r, "category"), g(r, "item_name"),
                         g(r, "price", 0), g(r, "qty", 1))))
        for r in rows.get("settings", []):
            ops.append(("INSERT INTO settings(key,value) VALUES(?,?)", (r["key"], r["value"])))
        for t in ("stations", "menu", "sessions", "orders"):          # keep new ids counting upwards
            ops.append((f"SELECT setval(pg_get_serial_sequence('{t}','id'), "
                        f"(SELECT COALESCE(MAX(id),0)+1 FROM {t}), false)", ()))
        try:
            self.run_many(ops)
        except psycopg2.Error as e:
            raise DataError(f"The import failed - nothing was changed.\n{friendly(e)}")
        self.seed()                                   # fills only anything the old file lacked
        return {t: len(v) for t, v in rows.items()}

    # ---- a plain-text safety copy of every table ----
    def backup_json(self, folder, label):
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"redline_{label}_{dt.datetime.now():%Y%m%d_%H%M%S}.json")
        data = {t: [dict(r) for r in self.q(f"SELECT * FROM {t} ORDER BY 1")]
                for t in ("settings", "stations", "menu", "sessions", "orders")}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, ensure_ascii=False, default=str)
        return path
