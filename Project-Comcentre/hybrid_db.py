#!/usr/bin/env python3
"""
hybrid_db.py
============
Hybrid database layer for the Advanced Kali Automator.

Strategy:
  - On every operation, attempt to reach MongoDB Atlas first.
  - If a network error is detected, fall back to the local SQLite database.
  - A background connectivity-checker thread continuously polls the network.
  - When connectivity is restored, a sync thread pushes pending SQLite changes
    (written while offline) up to MongoDB and pulls down any changes from Mongo.
  - The caller-facing API is identical regardless of which backend is active.

Collections/Tables mirrored:
  users, settings, templates, logs, scheduled_jobs

Sync strategy (simple "offline-queue" model):
  - Each SQLite row has a `_sync_pending` flag (0 = synced, 1 = needs push).
  - Rows created/updated offline get _sync_pending=1.
  - On reconnect, the sync thread pushes all _sync_pending=1 rows to Mongo.
  - Mongo is treated as the single source of truth when online.
"""

import os
import sqlite3
import threading
import time
import json
import socket
import datetime
import hashlib
import logging
from typing import Optional, List, Dict, Any, Callable

try:
    import pymongo
    from bson.objectid import ObjectId
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
MONGO_URI = "mongodb+srv://manankamboj66_db_user:HeZJf1a7BKEQq3IF@globaldb.jmzxyvp.mongodb.net/?appName=GlobalDB"
MONGO_DB_NAME = "advanced_automator_monolith"
SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "local_automator.db")
CONNECTIVITY_CHECK_INTERVAL = 10   # seconds between connectivity checks
CONNECTIVITY_TIMEOUT = 3           # seconds for ping timeout
CONNECTIVITY_HOST = "8.8.8.8"
CONNECTIVITY_PORT = 53

log = logging.getLogger("hybrid_db")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")


# ─────────────────────────────────────────────
# Connectivity helper
# ─────────────────────────────────────────────
def _is_internet_available() -> bool:
    """Quick TCP check to Google DNS."""
    try:
        socket.setdefaulttimeout(CONNECTIVITY_TIMEOUT)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((CONNECTIVITY_HOST, CONNECTIVITY_PORT))
        return True
    except (socket.error, OSError):
        return False


# ─────────────────────────────────────────────
# SQLite helpers
# ─────────────────────────────────────────────
def _sqlite_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _sqlite_init(conn: sqlite3.Connection):
    """Create all tables in SQLite if they don't exist."""
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mongo_id    TEXT UNIQUE,
            username    TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'operator',
            _sync_pending INTEGER DEFAULT 0,
            _deleted    INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mongo_id    TEXT UNIQUE,
            key         TEXT UNIQUE NOT NULL,
            value       TEXT NOT NULL,
            _sync_pending INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS templates (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mongo_id    TEXT UNIQUE,
            name        TEXT UNIQUE NOT NULL,
            pattern     TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            description TEXT DEFAULT '',
            approved    INTEGER DEFAULT 0,
            created_by  TEXT DEFAULT '',
            created_at  TEXT DEFAULT '',
            _sync_pending INTEGER DEFAULT 0,
            _deleted    INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            mongo_id        TEXT UNIQUE,
            template_id     TEXT,
            template_name   TEXT,
            user            TEXT,
            params_json     TEXT,
            command         TEXT,
            stdout          TEXT,
            stderr          TEXT,
            rc              INTEGER,
            started_at      TEXT,
            finished_at     TEXT,
            _sync_pending   INTEGER DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_jobs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mongo_id    TEXT UNIQUE,
            template_id TEXT,
            params_json TEXT,
            run_at      TEXT,
            created_by  TEXT,
            created_at  TEXT,
            executed    INTEGER DEFAULT 0,
            _sync_pending INTEGER DEFAULT 0
        )
    """)

    conn.commit()


# ─────────────────────────────────────────────
# HybridDB class
# ─────────────────────────────────────────────
class HybridDB:
    """
    Drop-in database facade. Exposes the same methods the app already used
    (via the module-level wrappers in app.py) but transparently routes between
    MongoDB Atlas and local SQLite.
    """

    def __init__(self):
        # SQLite is always kept in sync / available
        self._sqlite_conn = _sqlite_connect()
        _sqlite_init(self._sqlite_conn)
        self._lock = threading.Lock()

        # Mongo
        self._mongo_client: Optional[pymongo.MongoClient] = None
        self._mongo_db = None
        self._mongo_available = False

        # Status
        self._online = False
        self._status_callbacks: List[Callable[[bool], None]] = []

        # Try initial connection
        self._try_connect_mongo()

        # Background threads
        self._stop_event = threading.Event()
        self._conn_thread = threading.Thread(target=self._connectivity_loop, daemon=True)
        self._conn_thread.start()
        self._sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self._sync_thread.start()

    # ─── Internal ─────────────────────────────

    def _try_connect_mongo(self) -> bool:
        if not PYMONGO_AVAILABLE:
            return False
        if not _is_internet_available():
            return False
        try:
            client = pymongo.MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000,
                socketTimeoutMS=8000
            )
            # Force a lightweight command to verify connection
            client.admin.command("ping")
            self._mongo_client = client
            self._mongo_db = client[MONGO_DB_NAME]
            self._mongo_available = True
            was_offline = not self._online
            self._online = True
            if was_offline:
                log.info("✅ Connected to MongoDB Atlas (online mode)")
                self._fire_status(True)
            return True
        except Exception as e:
            log.warning(f"⚠️  MongoDB Atlas unavailable: {e}")
            self._mongo_available = False
            self._online = False
            return False

    def _connectivity_loop(self):
        """Periodically re-check connectivity and attempt Mongo reconnect."""
        while not self._stop_event.is_set():
            time.sleep(CONNECTIVITY_CHECK_INTERVAL)
            if not self._online:
                was_offline = True
                connected = self._try_connect_mongo()
                if connected and was_offline:
                    # Trigger a sync right away
                    self._do_sync()
            else:
                # Validate that the existing connection is still alive
                try:
                    self._mongo_client.admin.command("ping")
                except Exception:
                    log.warning("🔌 Lost connection to MongoDB Atlas – switching to offline mode")
                    self._online = False
                    self._mongo_available = False
                    self._fire_status(False)

    def _sync_loop(self):
        """Periodic sync when online (every 60 s)."""
        time.sleep(30)   # initial delay
        while not self._stop_event.is_set():
            if self._online:
                self._do_sync()
            time.sleep(60)

    def _do_sync(self):
        """Push offline-written rows to Mongo, then pull Mongo→SQLite."""
        log.info("🔄 Starting hybrid sync …")
        try:
            self._push_offline_changes()
            self._pull_from_mongo()
            log.info("✅ Sync complete")
        except Exception as e:
            log.error(f"❌ Sync error: {e}")

    def _push_offline_changes(self):
        """Push rows with _sync_pending=1 up to MongoDB."""
        mdb = self._mongo_db
        with self._lock:
            cur = self._sqlite_conn.cursor()

            # ── users ──
            for row in cur.execute("SELECT * FROM users WHERE _sync_pending=1").fetchall():
                doc = {
                    "username": row["username"],
                    "password_hash": row["password_hash"],
                    "role": row["role"]
                }
                if row["_deleted"]:
                    mdb.users.delete_one({"username": row["username"]})
                else:
                    result = mdb.users.update_one(
                        {"username": row["username"]},
                        {"$set": doc},
                        upsert=True
                    )
                    mongo_id = str(result.upserted_id) if result.upserted_id else row["mongo_id"]
                    if mongo_id:
                        self._sqlite_conn.execute(
                            "UPDATE users SET _sync_pending=0, mongo_id=? WHERE id=?",
                            (mongo_id, row["id"])
                        )
                    else:
                        self._sqlite_conn.execute(
                            "UPDATE users SET _sync_pending=0 WHERE id=?",
                            (row["id"],)
                        )

            # ── settings ──
            for row in cur.execute("SELECT * FROM settings WHERE _sync_pending=1").fetchall():
                mdb.settings.update_one(
                    {"key": row["key"]},
                    {"$set": {"key": row["key"], "value": row["value"]}},
                    upsert=True
                )
                self._sqlite_conn.execute(
                    "UPDATE settings SET _sync_pending=0 WHERE id=?",
                    (row["id"],)
                )

            # ── templates ──
            for row in cur.execute("SELECT * FROM templates WHERE _sync_pending=1").fetchall():
                if row["_deleted"]:
                    if row["mongo_id"]:
                        try:
                            mdb.templates.delete_one({"_id": ObjectId(row["mongo_id"])})
                        except Exception:
                            pass
                else:
                    doc = {
                        "name": row["name"],
                        "pattern": row["pattern"],
                        "metadata_json": row["metadata_json"],
                        "description": row["description"],
                        "approved": row["approved"],
                        "created_by": row["created_by"],
                        "created_at": row["created_at"]
                    }
                    result = mdb.templates.update_one(
                        {"name": row["name"]},
                        {"$set": doc},
                        upsert=True
                    )
                    mongo_id = str(result.upserted_id) if result.upserted_id else row["mongo_id"]
                    if mongo_id:
                        self._sqlite_conn.execute(
                            "UPDATE templates SET _sync_pending=0, mongo_id=? WHERE id=?",
                            (mongo_id, row["id"])
                        )
                    else:
                        self._sqlite_conn.execute(
                            "UPDATE templates SET _sync_pending=0 WHERE id=?",
                            (row["id"],)
                        )

            # ── logs ──  (only push, never pull logs from Mongo to keep perf reasonable)
            for row in cur.execute("SELECT * FROM logs WHERE _sync_pending=1").fetchall():
                doc = {
                    "template_id": row["template_id"],
                    "template_name": row["template_name"],
                    "user": row["user"],
                    "params_json": row["params_json"],
                    "command": row["command"],
                    "stdout": row["stdout"],
                    "stderr": row["stderr"],
                    "rc": row["rc"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"]
                }
                res = mdb.logs.insert_one(doc)
                self._sqlite_conn.execute(
                    "UPDATE logs SET _sync_pending=0, mongo_id=? WHERE id=?",
                    (str(res.inserted_id), row["id"])
                )

            # ── scheduled_jobs ──
            for row in cur.execute("SELECT * FROM scheduled_jobs WHERE _sync_pending=1").fetchall():
                doc = {
                    "template_id": row["template_id"],
                    "params_json": row["params_json"],
                    "run_at": row["run_at"],
                    "created_by": row["created_by"],
                    "created_at": row["created_at"],
                    "executed": row["executed"]
                }
                result = mdb.scheduled_jobs.update_one(
                    {"_id": ObjectId(row["mongo_id"])} if row["mongo_id"] else {"_no_match": True},
                    {"$set": doc},
                    upsert=True
                )
                mongo_id = str(result.upserted_id) if result.upserted_id else row["mongo_id"]
                self._sqlite_conn.execute(
                    "UPDATE scheduled_jobs SET _sync_pending=0, mongo_id=? WHERE id=?",
                    (mongo_id, row["id"])
                )

            self._sqlite_conn.commit()

    def _pull_from_mongo(self):
        """Pull Mongo data into SQLite so offline cache stays fresh."""
        mdb = self._mongo_db
        with self._lock:
            # ── users ──
            for doc in mdb.users.find():
                mid = str(doc["_id"])
                self._sqlite_conn.execute(
                    """
                    INSERT INTO users (mongo_id, username, password_hash, role, _sync_pending)
                    VALUES (?, ?, ?, ?, 0)
                    ON CONFLICT(username) DO UPDATE SET
                        password_hash=excluded.password_hash,
                        role=excluded.role,
                        mongo_id=excluded.mongo_id,
                        _sync_pending=0
                    """,
                    (mid, doc["username"], doc["password_hash"], doc.get("role", "operator"))
                )

            # ── settings ──
            for doc in mdb.settings.find():
                mid = str(doc["_id"])
                self._sqlite_conn.execute(
                    """
                    INSERT INTO settings (mongo_id, key, value, _sync_pending)
                    VALUES (?, ?, ?, 0)
                    ON CONFLICT(key) DO UPDATE SET
                        value=excluded.value,
                        mongo_id=excluded.mongo_id,
                        _sync_pending=0
                    """,
                    (mid, doc["key"], doc["value"])
                )

            # ── templates ──
            for doc in mdb.templates.find():
                mid = str(doc["_id"])
                self._sqlite_conn.execute(
                    """
                    INSERT INTO templates (mongo_id, name, pattern, metadata_json, description,
                                          approved, created_by, created_at, _sync_pending)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                    ON CONFLICT(name) DO UPDATE SET
                        mongo_id=excluded.mongo_id,
                        pattern=excluded.pattern,
                        metadata_json=excluded.metadata_json,
                        description=excluded.description,
                        approved=excluded.approved,
                        created_by=excluded.created_by,
                        created_at=excluded.created_at,
                        _sync_pending=0
                    """,
                    (mid, doc["name"], doc["pattern"],
                     doc.get("metadata_json", "{}"),
                     doc.get("description", ""),
                     int(bool(doc.get("approved", 0))),
                     doc.get("created_by", ""),
                     doc.get("created_at", ""))
                )

            self._sqlite_conn.commit()

    def _fire_status(self, online: bool):
        for cb in list(self._status_callbacks):
            try:
                cb(online)
            except Exception:
                pass

    def register_status_callback(self, cb: Callable[[bool], None]):
        """Register a function that is called whenever online status changes."""
        self._status_callbacks.append(cb)

    @property
    def is_online(self) -> bool:
        return self._online

    def force_sync(self):
        """Trigger an immediate sync attempt (called from UI)."""
        if self._online:
            threading.Thread(target=self._do_sync, daemon=True).start()
        else:
            threading.Thread(target=self._try_connect_mongo, daemon=True).start()

    def close(self):
        self._stop_event.set()
        try:
            self._sqlite_conn.close()
        except Exception:
            pass
        try:
            if self._mongo_client:
                self._mongo_client.close()
        except Exception:
            pass

    # ─────────────────────────────────────────
    # ── Settings ─────────────────────────────
    # ─────────────────────────────────────────

    def get_setting(self, key: str, default=None):
        with self._lock:
            if self._online:
                try:
                    r = self._mongo_db.settings.find_one({"key": key})
                    if r:
                        return json.loads(r["value"])
                    return default
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline path
            row = self._sqlite_conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            ).fetchone()
            return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value):
        serialized = json.dumps(value)
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.settings.update_one(
                        {"key": key},
                        {"$set": {"key": key, "value": serialized}},
                        upsert=True
                    )
                    # Mirror to SQLite (sync_pending=0, already in Mongo)
                    self._sqlite_conn.execute(
                        """INSERT INTO settings (key, value, _sync_pending)
                           VALUES (?, ?, 0)
                           ON CONFLICT(key) DO UPDATE SET value=excluded.value, _sync_pending=0""",
                        (key, serialized)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline path
            self._sqlite_conn.execute(
                """INSERT INTO settings (key, value, _sync_pending)
                   VALUES (?, ?, 1)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value, _sync_pending=1""",
                (key, serialized)
            )
            self._sqlite_conn.commit()

    # ─────────────────────────────────────────
    # ── Users ────────────────────────────────
    # ─────────────────────────────────────────

    def add_user(self, username: str, password_hash: str, role: str = "operator"):
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.users.insert_one({
                        "username": username,
                        "password_hash": password_hash,
                        "role": role
                    })
                    self._sqlite_conn.execute(
                        """INSERT OR IGNORE INTO users (username, password_hash, role, _sync_pending)
                           VALUES (?, ?, ?, 0)""",
                        (username, password_hash, role)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline
            self._sqlite_conn.execute(
                """INSERT OR IGNORE INTO users (username, password_hash, role, _sync_pending)
                   VALUES (?, ?, ?, 1)""",
                (username, password_hash, role)
            )
            self._sqlite_conn.commit()

    def delete_user(self, username: str):
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.users.delete_one({"username": username})
                    self._sqlite_conn.execute(
                        "UPDATE users SET _deleted=1, _sync_pending=0 WHERE username=?", (username,)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            self._sqlite_conn.execute(
                "UPDATE users SET _deleted=1, _sync_pending=1 WHERE username=?", (username,)
            )
            self._sqlite_conn.commit()

    def list_users(self) -> List[tuple]:
        with self._lock:
            if self._online:
                try:
                    rows = self._mongo_db.users.find().sort("username", 1)
                    return [(r["username"], r.get("role", "operator")) for r in rows]
                except Exception:
                    self._online = False
                    self._fire_status(False)
            rows = self._sqlite_conn.execute(
                "SELECT username, role FROM users WHERE _deleted=0 ORDER BY username"
            ).fetchall()
            return [(r["username"], r["role"]) for r in rows]

    def authenticate(self, username: str, password_hash: str) -> bool:
        with self._lock:
            if self._online:
                try:
                    r = self._mongo_db.users.find_one({"username": username})
                    return bool(r and r["password_hash"] == password_hash)
                except Exception:
                    self._online = False
                    self._fire_status(False)
            row = self._sqlite_conn.execute(
                "SELECT password_hash FROM users WHERE username=? AND _deleted=0", (username,)
            ).fetchone()
            return bool(row and row["password_hash"] == password_hash)

    def get_user_role(self, username: str) -> Optional[str]:
        with self._lock:
            if self._online:
                try:
                    r = self._mongo_db.users.find_one({"username": username})
                    return r["role"] if r else None
                except Exception:
                    self._online = False
                    self._fire_status(False)
            row = self._sqlite_conn.execute(
                "SELECT role FROM users WHERE username=? AND _deleted=0", (username,)
            ).fetchone()
            return row["role"] if row else None

    def update_password(self, username: str, new_password_hash: str):
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.users.update_one(
                        {"username": username},
                        {"$set": {"password_hash": new_password_hash}}
                    )
                    self._sqlite_conn.execute(
                        "UPDATE users SET password_hash=?, _sync_pending=0 WHERE username=?",
                        (new_password_hash, username)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            self._sqlite_conn.execute(
                "UPDATE users SET password_hash=?, _sync_pending=1 WHERE username=?",
                (new_password_hash, username)
            )
            self._sqlite_conn.commit()

    def ensure_default_user(self, username: str, password_hash: str, role: str = "admin"):
        """Insert a default user only if no users exist at all."""
        with self._lock:
            if self._online:
                try:
                    if self._mongo_db.users.count_documents({}) == 0:
                        self._mongo_db.users.insert_one({
                            "username": username,
                            "password_hash": password_hash,
                            "role": role
                        })
                except Exception:
                    pass
            # Always ensure a local user too
            count = self._sqlite_conn.execute(
                "SELECT COUNT(*) as c FROM users WHERE _deleted=0"
            ).fetchone()["c"]
            if count == 0:
                self._sqlite_conn.execute(
                    """INSERT OR IGNORE INTO users (username, password_hash, role, _sync_pending)
                       VALUES (?, ?, ?, 0)""",
                    (username, password_hash, role)
                )
                self._sqlite_conn.commit()

    # ─────────────────────────────────────────
    # ── Templates ────────────────────────────
    # ─────────────────────────────────────────

    def list_templates(self) -> List[Dict]:
        with self._lock:
            if self._online:
                try:
                    rows = self._mongo_db.templates.find().sort("name", 1)
                    result = []
                    for r in rows:
                        result.append({
                            "id": str(r["_id"]),
                            "name": r["name"],
                            "pattern": r["pattern"],
                            "metadata": json.loads(r.get("metadata_json", "{}")),
                            "description": r.get("description", ""),
                            "approved": bool(r.get("approved", 0)),
                            "created_by": r.get("created_by", ""),
                            "created_at": r.get("created_at", "")
                        })
                    return result
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline
            rows = self._sqlite_conn.execute(
                "SELECT * FROM templates WHERE _deleted=0 ORDER BY name"
            ).fetchall()
            result = []
            for r in rows:
                result.append({
                    "id": r["mongo_id"] or str(r["id"]),
                    "name": r["name"],
                    "pattern": r["pattern"],
                    "metadata": json.loads(r["metadata_json"] or "{}"),
                    "description": r["description"] or "",
                    "approved": bool(r["approved"]),
                    "created_by": r["created_by"] or "",
                    "created_at": r["created_at"] or ""
                })
            return result

    def save_template(self, name: str, pattern: str, metadata: dict,
                      description: str, created_by: str, approved: bool = False):
        meta_json = json.dumps(metadata)
        now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.templates.update_one(
                        {"name": name},
                        {"$set": {
                            "pattern": pattern,
                            "metadata_json": meta_json,
                            "description": description,
                            "approved": int(bool(approved)),
                            "created_by": created_by,
                            "created_at": now
                        }},
                        upsert=True
                    )
                    # Mirror to SQLite
                    self._sqlite_conn.execute(
                        """INSERT INTO templates (name, pattern, metadata_json, description,
                                                  approved, created_by, created_at, _sync_pending)
                           VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                           ON CONFLICT(name) DO UPDATE SET
                               pattern=excluded.pattern,
                               metadata_json=excluded.metadata_json,
                               description=excluded.description,
                               approved=excluded.approved,
                               created_by=excluded.created_by,
                               created_at=excluded.created_at,
                               _sync_pending=0""",
                        (name, pattern, meta_json, description, int(bool(approved)), created_by, now)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline
            self._sqlite_conn.execute(
                """INSERT INTO templates (name, pattern, metadata_json, description,
                                          approved, created_by, created_at, _sync_pending)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                   ON CONFLICT(name) DO UPDATE SET
                       pattern=excluded.pattern,
                       metadata_json=excluded.metadata_json,
                       description=excluded.description,
                       approved=excluded.approved,
                       created_by=excluded.created_by,
                       created_at=excluded.created_at,
                       _sync_pending=1""",
                (name, pattern, meta_json, description, int(bool(approved)), created_by, now)
            )
            self._sqlite_conn.commit()

    def delete_template(self, template_id: str):
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.templates.delete_one({"_id": ObjectId(template_id)})
                    self._sqlite_conn.execute(
                        "UPDATE templates SET _deleted=1, _sync_pending=0 WHERE mongo_id=?",
                        (template_id,)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline – attempt by mongo_id or numeric id
            self._sqlite_conn.execute(
                "UPDATE templates SET _deleted=1, _sync_pending=1 WHERE mongo_id=? OR CAST(id AS TEXT)=?",
                (template_id, template_id)
            )
            self._sqlite_conn.commit()

    def approve_template(self, template_id: str):
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.templates.update_one(
                        {"_id": ObjectId(template_id)},
                        {"$set": {"approved": 1}}
                    )
                    self._sqlite_conn.execute(
                        "UPDATE templates SET approved=1, _sync_pending=0 WHERE mongo_id=?",
                        (template_id,)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            self._sqlite_conn.execute(
                "UPDATE templates SET approved=1, _sync_pending=1 WHERE mongo_id=? OR CAST(id AS TEXT)=?",
                (template_id, template_id)
            )
            self._sqlite_conn.commit()

    def count_templates(self) -> int:
        with self._lock:
            if self._online:
                try:
                    return self._mongo_db.templates.count_documents({})
                except Exception:
                    self._online = False
                    self._fire_status(False)
            return self._sqlite_conn.execute(
                "SELECT COUNT(*) as c FROM templates WHERE _deleted=0"
            ).fetchone()["c"]

    def insert_sample_template(self, doc: dict):
        """Used only during ensure_samples()."""
        name = doc["name"]
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.templates.update_one({"name": name}, {"$set": doc}, upsert=True)
                except Exception:
                    self._online = False
                    self._fire_status(False)
            self._sqlite_conn.execute(
                """INSERT INTO templates (name, pattern, metadata_json, description,
                                          approved, created_by, created_at, _sync_pending)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                   ON CONFLICT(name) DO NOTHING""",
                (name, doc["pattern"], doc.get("metadata_json", "{}"),
                 doc.get("description", ""), doc.get("approved", 0),
                 doc.get("created_by", ""), doc.get("created_at", ""))
            )
            self._sqlite_conn.commit()

    # ─────────────────────────────────────────
    # ── Logs ─────────────────────────────────
    # ─────────────────────────────────────────

    def log_run(self, template_id, template_name, user, params_json,
                command, stdout, stderr, rc, started_at, finished_at):
        with self._lock:
            if self._online:
                try:
                    res = self._mongo_db.logs.insert_one({
                        "template_id": template_id,
                        "template_name": template_name,
                        "user": user,
                        "params_json": params_json,
                        "command": command,
                        "stdout": stdout,
                        "stderr": stderr,
                        "rc": rc,
                        "started_at": started_at,
                        "finished_at": finished_at
                    })
                    mid = str(res.inserted_id)
                    self._sqlite_conn.execute(
                        """INSERT INTO logs (mongo_id, template_id, template_name, user,
                                             params_json, command, stdout, stderr, rc,
                                             started_at, finished_at, _sync_pending)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                        (mid, template_id, template_name, user,
                         params_json, command, stdout, stderr, rc,
                         started_at, finished_at)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline
            self._sqlite_conn.execute(
                """INSERT INTO logs (template_id, template_name, user,
                                     params_json, command, stdout, stderr, rc,
                                     started_at, finished_at, _sync_pending)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (template_id, template_name, user,
                 params_json, command, stdout, stderr, rc,
                 started_at, finished_at)
            )
            self._sqlite_conn.commit()

    def get_logs(self, limit: int = 1000) -> List[tuple]:
        with self._lock:
            if self._online:
                try:
                    rows = self._mongo_db.logs.find().sort("_id", -1).limit(limit)
                    return [(str(r["_id"]), r.get("template_name"), r.get("user"),
                             r.get("started_at"), r.get("finished_at"), r.get("rc")) for r in rows]
                except Exception:
                    self._online = False
                    self._fire_status(False)
            rows = self._sqlite_conn.execute(
                """SELECT id, mongo_id, template_name, user, started_at, finished_at, rc
                   FROM logs ORDER BY id DESC LIMIT ?""",
                (limit,)
            ).fetchall()
            return [(r["mongo_id"] or str(r["id"]), r["template_name"], r["user"],
                     r["started_at"], r["finished_at"], r["rc"]) for r in rows]

    def get_log_detail(self, log_id: str):
        with self._lock:
            if self._online:
                try:
                    r = self._mongo_db.logs.find_one({"_id": ObjectId(log_id)})
                    if r:
                        return (r.get("template_name"), r.get("user"), r.get("params_json"),
                                r.get("command"), r.get("stdout"), r.get("stderr"),
                                r.get("rc"), r.get("started_at"), r.get("finished_at"))
                    return None
                except Exception:
                    self._online = False
                    self._fire_status(False)
            row = self._sqlite_conn.execute(
                """SELECT * FROM logs WHERE mongo_id=? OR CAST(id AS TEXT)=?""",
                (log_id, log_id)
            ).fetchone()
            if row:
                return (row["template_name"], row["user"], row["params_json"],
                        row["command"], row["stdout"], row["stderr"],
                        row["rc"], row["started_at"], row["finished_at"])
            return None

    def get_all_logs_raw(self):
        """Used for CSV export."""
        with self._lock:
            if self._online:
                try:
                    return list(self._mongo_db.logs.find().sort("_id", -1))
                except Exception:
                    self._online = False
                    self._fire_status(False)
            rows = self._sqlite_conn.execute(
                "SELECT * FROM logs ORDER BY id DESC"
            ).fetchall()
            return [dict(r) for r in rows]

    # ─────────────────────────────────────────
    # ── Scheduled Jobs ────────────────────────
    # ─────────────────────────────────────────

    def add_scheduled_job(self, template_id: str, params_json: str,
                          run_at: str, created_by: str, created_at: str) -> str:
        with self._lock:
            if self._online:
                try:
                    res = self._mongo_db.scheduled_jobs.insert_one({
                        "template_id": template_id,
                        "params_json": params_json,
                        "run_at": run_at,
                        "created_by": created_by,
                        "created_at": created_at,
                        "executed": 0
                    })
                    mid = str(res.inserted_id)
                    self._sqlite_conn.execute(
                        """INSERT INTO scheduled_jobs (mongo_id, template_id, params_json,
                                                       run_at, created_by, created_at, executed, _sync_pending)
                           VALUES (?, ?, ?, ?, ?, ?, 0, 0)""",
                        (mid, template_id, params_json, run_at, created_by, created_at)
                    )
                    self._sqlite_conn.commit()
                    return mid
                except Exception:
                    self._online = False
                    self._fire_status(False)
            # Offline
            cur = self._sqlite_conn.execute(
                """INSERT INTO scheduled_jobs (template_id, params_json, run_at,
                                               created_by, created_at, executed, _sync_pending)
                   VALUES (?, ?, ?, ?, ?, 0, 1)""",
                (template_id, params_json, run_at, created_by, created_at)
            )
            self._sqlite_conn.commit()
            return str(cur.lastrowid)

    def list_scheduled_jobs(self) -> List[Dict]:
        with self._lock:
            if self._online:
                try:
                    rows = self._mongo_db.scheduled_jobs.find().sort("run_at", 1)
                    out = []
                    for r in rows:
                        out.append({
                            "id": str(r["_id"]),
                            "template_id": r["template_id"],
                            "params": json.loads(r.get("params_json", "{}")),
                            "run_at": r["run_at"],
                            "created_by": r.get("created_by", ""),
                            "executed": bool(r.get("executed", 0))
                        })
                    return out
                except Exception:
                    self._online = False
                    self._fire_status(False)
            rows = self._sqlite_conn.execute(
                "SELECT * FROM scheduled_jobs ORDER BY run_at"
            ).fetchall()
            out = []
            for r in rows:
                out.append({
                    "id": r["mongo_id"] or str(r["id"]),
                    "template_id": r["template_id"],
                    "params": json.loads(r["params_json"] or "{}"),
                    "run_at": r["run_at"],
                    "created_by": r["created_by"] or "",
                    "executed": bool(r["executed"])
                })
            return out

    def mark_scheduled_executed(self, job_id: str):
        with self._lock:
            if self._online:
                try:
                    self._mongo_db.scheduled_jobs.update_one(
                        {"_id": ObjectId(job_id)},
                        {"$set": {"executed": 1}}
                    )
                    self._sqlite_conn.execute(
                        "UPDATE scheduled_jobs SET executed=1 WHERE mongo_id=? OR CAST(id AS TEXT)=?",
                        (job_id, job_id)
                    )
                    self._sqlite_conn.commit()
                    return
                except Exception:
                    self._online = False
                    self._fire_status(False)
            self._sqlite_conn.execute(
                "UPDATE scheduled_jobs SET executed=1 WHERE mongo_id=? OR CAST(id AS TEXT)=?",
                (job_id, job_id)
            )
            self._sqlite_conn.commit()


# ─────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────
_instance: Optional[HybridDB] = None

def get_db() -> HybridDB:
    global _instance
    if _instance is None:
        _instance = HybridDB()
    return _instance
