#!/usr/bin/env python3
"""
advanced_kali_automator_with_terminal.py

Monolithic advanced "safe-by-default" automation GUI for Kali/Linux,
with embedded interactive terminal (xterm -into) and external terminal launch option.

Author: Generated for user (educational / lab use only).
Date: 2025-09-28 (UTC)
"""

import os
import sys
import sqlite3
import json
import threading
import queue
import time
import datetime
import shlex
import subprocess
import csv
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

# -------------------------
# Configuration & safety
# -------------------------
APP_DB = "advanced_automator_monolith.db"
DEFAULT_ADMIN = "admin"
DEFAULT_ADMIN_PASS = "admin"  # change on first run!
DEFAULT_WHITELIST = ["echo", "date", "uptime", "whoami", "uname", "ls", "df", "free", "hostname", "id", "sudo","nmap"]
DISALLOWED_CHARS_RE = re.compile(r'[;&|`$<>\\\n]')
DANGEROUS_TOKENS = {"rm", "mkfs", "dd", "shutdown", "reboot", ":(){", "mkfs.", "nc", "ncat"}
MAX_WORKERS = 4
JOB_TIMEOUT = 300  # seconds
NOTIFY_CMD = "notify-send"  # used only if available

# -------------------------
# Utilities
# -------------------------
def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def safe_check_text(s: str):
    """Raise ValueError if text contains disallowed shell characters"""
    if s is None:
        return
    if DISALLOWED_CHARS_RE.search(s):
        raise ValueError("Text contains disallowed shell-special characters.")
    return s

def looks_dangerous(s: str):
    lower = (s or "").lower()
    for token in DANGEROUS_TOKENS:
        if token in lower:
            return True, token
    return False, None

def which(cmd):
    from shutil import which as _which
    return _which(cmd)

# -------------------------
# Database initialization
# -------------------------
def init_db():
    first_time = not os.path.exists(APP_DB)
    conn = sqlite3.connect(APP_DB, check_same_thread=False)
    cur = conn.cursor()
    # Users: username, password_hash, role (admin/operator/viewer)
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT CHECK(role IN ('admin','operator','viewer')) NOT NULL DEFAULT 'operator'
    )""")
    # Templates
    cur.execute("""CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE,
        pattern TEXT,
        metadata_json TEXT,
        description TEXT,
        approved INTEGER DEFAULT 0,
        created_by TEXT,
        created_at TEXT
    )""")
    # Logs
    cur.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY,
        template_id INTEGER,
        template_name TEXT,
        user TEXT,
        params_json TEXT,
        command TEXT,
        stdout TEXT,
        stderr TEXT,
        rc INTEGER,
        started_at TEXT,
        finished_at TEXT
    )""")
    # Settings
    cur.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")
    # Scheduled jobs persisted
    cur.execute("""CREATE TABLE IF NOT EXISTS scheduled_jobs (
        id INTEGER PRIMARY KEY,
        template_id INTEGER,
        params_json TEXT,
        run_at TEXT,
        created_by TEXT,
        created_at TEXT,
        executed INTEGER DEFAULT 0
    )""")
    conn.commit()

    # Default admin
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)",
                    (DEFAULT_ADMIN, hash_pw(DEFAULT_ADMIN_PASS), "admin"))
        conn.commit()

    # Default whitelist
    cur.execute("SELECT value FROM settings WHERE key='whitelist'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings (key,value) VALUES (?, ?)", ("whitelist", json.dumps(DEFAULT_WHITELIST)))
    # Execution flag (disabled)
    cur.execute("SELECT value FROM settings WHERE key='execution_enabled'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings (key,value) VALUES (?, ?)", ("execution_enabled", json.dumps(False)))
    # Theme
    cur.execute("SELECT value FROM settings WHERE key='theme'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings (key,value) VALUES (?, ?)", ("theme", json.dumps("light")))
    conn.commit()
    return conn

DB = init_db()
DB_LOCK = threading.Lock()

# -------------------------
# Database helpers
# -------------------------
def get_setting(key, default=None):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT value FROM settings WHERE key=?", (key,))
        r = cur.fetchone()
        return json.loads(r[0]) if r else default

def set_setting(key, value):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("REPLACE INTO settings (key,value) VALUES (?, ?)", (key, json.dumps(value)))
        DB.commit()

def get_whitelist():
    return get_setting("whitelist", DEFAULT_WHITELIST)

def set_whitelist(lst):
    set_setting("whitelist", lst)

def execution_enabled():
    return bool(get_setting("execution_enabled", False))

def set_execution_enabled(v: bool):
    set_setting("execution_enabled", bool(v))

def get_theme():
    return get_setting("theme", "light")

def set_theme(t: str):
    set_setting("theme", t)

# Users
def add_user(username, password, role="operator"):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("INSERT INTO users (username,password_hash,role) VALUES (?, ?, ?)", (username, hash_pw(password), role))
        DB.commit()

def delete_user(username):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("DELETE FROM users WHERE username=?", (username,))
        DB.commit()

def list_users():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT username, role FROM users ORDER BY username")
        return cur.fetchall()

def authenticate(username, password):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        r = cur.fetchone()
        return bool(r and r[0] == hash_pw(password))

def get_user_role(username):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT role FROM users WHERE username=?", (username,))
        r = cur.fetchone()
        return r[0] if r else None

# Templates
def list_templates():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id,name,pattern,metadata_json,description,approved,created_by,created_at FROM templates ORDER BY name")
        rows = cur.fetchall()
    templates = []
    for r in rows:
        templates.append({
            "id": r[0],
            "name": r[1],
            "pattern": r[2],
            "metadata": json.loads(r[3]) if r[3] else {},
            "description": r[4],
            "approved": bool(r[5]),
            "created_by": r[6],
            "created_at": r[7]
        })
    return templates

def save_template(name, pattern, metadata, description, created_by, approved=False):
    safe_check_text(pattern)
    if not re.match(r'^[A-Za-z0-9_\- ]+$', name):
        raise ValueError("Template name has invalid characters.")
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("""INSERT OR REPLACE INTO templates (name,pattern,metadata_json,description,approved,created_by,created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (name, pattern, json.dumps(metadata), description, int(bool(approved)), created_by, now_iso()))
        DB.commit()

def delete_template(template_id):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("DELETE FROM templates WHERE id=?", (template_id,))
        DB.commit()

def approve_template(template_id):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("UPDATE templates SET approved=1 WHERE id=?", (template_id,))
        DB.commit()

# Logs
def log_run(template_id, template_name, user, params, command, stdout, stderr, rc, started_at, finished_at):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("""INSERT INTO logs (template_id, template_name, user, params_json, command, stdout, stderr, rc, started_at, finished_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (template_id, template_name, user, json.dumps(params), command, stdout, stderr, rc, started_at, finished_at))
        DB.commit()

def get_logs(limit=1000):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id, template_name, user, started_at, finished_at, rc FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

def get_log_detail(log_id):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT template_name,user,params_json,command,stdout,stderr,rc,started_at,finished_at FROM logs WHERE id=?", (log_id,))
        return cur.fetchone()

# Scheduled jobs persistence
def add_scheduled_job(template_id, params, run_at_ts, created_by):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("INSERT INTO scheduled_jobs (template_id, params_json, run_at, created_by, created_at, executed) VALUES (?, ?, ?, ?, ?, 0)",
                    (template_id, json.dumps(params), datetime.datetime.utcfromtimestamp(run_at_ts).isoformat()+"Z", created_by, now_iso()))
        DB.commit()
        return cur.lastrowid

def list_scheduled_jobs():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id, template_id, params_json, run_at, created_by, executed FROM scheduled_jobs ORDER BY run_at")
        rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "id": r[0],
            "template_id": r[1],
            "params": json.loads(r[2]),
            "run_at": r[3],
            "created_by": r[4],
            "executed": bool(r[5])
        })
    return out

def mark_scheduled_executed(job_id):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("UPDATE scheduled_jobs SET executed=1 WHERE id=?", (job_id,))
        DB.commit()

# -------------------------
# Command builder and safety
# -------------------------
def build_command(pattern: str, params: dict) -> str:
    """Safely format the pattern with params after basic validations."""
    # pattern must be free of disallowed chars
    safe_check_text(pattern)
    # validate parameter names and param strings
    for k, v in params.items():
        if not re.match(r'^[A-Za-z0-9_]+$', k):
            raise ValueError("Invalid parameter name: only A-Za-z0-9_ allowed.")
        if isinstance(v, str):
            safe_check_text(v)
    try:
        cmd = pattern.format_map(params)
    except KeyError as e:
        raise ValueError(f"Missing parameter: {e}")
    except Exception as e:
        raise ValueError(f"Pattern formatting error: {e}")
    parts = shlex.split(cmd)
    if not parts:
        raise ValueError("Resulting command is empty.")
    whitelist = get_whitelist()
    if parts[0] not in whitelist:
        raise PermissionError(f"Command '{parts[0]}' not in whitelist.")
    # disallow dangerous tokens inside the command
    for token in parts:
        for bad in DANGEROUS_TOKENS:
            if bad in token.lower():
                raise PermissionError(f"Dangerous token detected in command: {bad}")
    return cmd

def run_command(cmd: str, timeout=JOB_TIMEOUT):
    """Run command safely without shell using shlex; return (rc, stdout, stderr)."""
    args = shlex.split(cmd)
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        err += "\n[TimeoutExpired]"
    return proc.returncode, out, err

# -------------------------
# Job queue & worker threads
# -------------------------
JOB_QUEUE = queue.Queue()
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)

def job_worker_loop():
    """Background worker: takes job dicts from JOB_QUEUE and executes them."""
    while True:
        job = JOB_QUEUE.get()
        if job is None:
            break
        template = job.get("template")
        params = job.get("params", {})
        user = job.get("user", "unknown")
        dry_run = bool(job.get("dry_run", True))
        as_root = bool(job.get("as_root", False))
        sandbox = bool(job.get("sandbox", False))
        on_update = job.get("on_update")
        started = now_iso()
        # dry-run handling
        if dry_run:
            summary = "[dry-run] " + (template["pattern"].format_map(params) if template else "[no-template]")
            log_run(template.get("id") if template else None,
                    template.get("name") if template else None,
                    user, params, summary, "[dry-run]", "", 0, started, now_iso())
            if on_update:
                on_update({"status":"dry-run","cmd":summary})
            JOB_QUEUE.task_done()
            continue
        # build command
        try:
            cmd = build_command(template["pattern"], params)
            # if wanting root: require admin + 'sudo' present in whitelist and execution enabled
            if as_root:
                if not get_user_role(user) == "admin":
                    raise PermissionError("Only admin users may request root execution.")
                if "sudo" not in get_whitelist():
                    raise PermissionError("sudo not in whitelist; cannot run as root.")
                cmd = "sudo " + cmd
            if sandbox:
                # If sandbox requested and Docker available, run inside Docker container (optional)
                if which("docker") is None:
                    raise RuntimeError("Docker not found; cannot run sandbox mode.")
                docker_cmd = ["docker", "run", "--rm", "--network", "none", "-v", "/tmp:/tmp:ro", "ubuntu:latest", "bash", "-lc", shlex.join(shlex.split(cmd))]
                proc = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    out, err = proc.communicate(timeout=JOB_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, err = proc.communicate()
                    err += "\n[TimeoutExpired]"
                rc = proc.returncode
                finished = now_iso()
                log_run(template.get("id"), template.get("name"), user, params, " ".join(docker_cmd), out, err, rc, started, finished)
                if on_update:
                    on_update({"status":"done","rc":rc,"stdout":out,"stderr":err})
                JOB_QUEUE.task_done()
                continue
            # regular run
            if not execution_enabled():
                raise PermissionError("Execution disabled in Settings.")
            fut = EXECUTOR.submit(run_command, cmd)
            rc, out, err = fut.result()
            finished = now_iso()
            log_run(template.get("id"), template.get("name"), user, params, cmd, out, err, rc, started, finished)
            # notification attempt
            try:
                if which(NOTIFY_CMD) and (len(out)+len(err) > 500 or rc != 0):
                    subprocess.Popen([NOTIFY_CMD, f"Job {template.get('name')} finished", f"rc={rc}"])
            except Exception:
                pass
            if on_update:
                on_update({"status":"done","rc":rc,"stdout":out,"stderr":err})
        except Exception as e:
            if on_update:
                on_update({"status":"error","error":str(e)})
        JOB_QUEUE.task_done()

_worker_thread = threading.Thread(target=job_worker_loop, daemon=True)
_worker_thread.start()

# -------------------------
# Scheduler thread that watches DB scheduled_jobs
# -------------------------
def scheduler_loop():
    while True:
        try:
            now_ts = time.time()
            jobs = list_scheduled_jobs()
            for j in jobs:
                if j["executed"]:
                    continue
                # parse run_at
                try:
                    run_at = datetime.datetime.fromisoformat(j["run_at"].replace("Z","+00:00")).timestamp()
                except Exception:
                    continue
                if run_at <= now_ts:
                    # find template info
                    templates = list_templates()
                    template = next((t for t in templates if t["id"] == j["template_id"]), None)
                    if template:
                        JOB_QUEUE.put({
                            "template": template,
                            "params": j["params"],
                            "user": j["created_by"],
                            "dry_run": False,
                            "as_root": False,
                            "sandbox": False,
                            "on_update": None
                        })
                    mark_scheduled_executed(j["id"])
            time.sleep(5)
        except Exception:
            time.sleep(5)

_scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
_scheduler_thread.start()

# -------------------------
# GUI Application (Tkinter)
# -------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Kali Automator (Safe)")
        self.geometry("1180x800")
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.current_user = None
        self.templates = []
        self.selected_template = None
        self.param_widgets = {}
        # Embedded terminal attributes
        self.embedded_term_proc = None
        self.embedded_term_winid = None

        self.init_ui()
        self.load_templates()
        self.apply_theme()

    def init_ui(self):
        # Menu
        menubar = tk.Menu(self)
        admin_menu = tk.Menu(menubar, tearoff=0)
        admin_menu.add_command(label="Users", command=self.open_users)
        admin_menu.add_command(label="Settings", command=self.open_settings)
        admin_menu.add_separator()
        admin_menu.add_command(label="Import Templates (JSON)", command=self.import_templates)
        admin_menu.add_command(label="Export Templates (JSON)", command=self.export_templates)
        menubar.add_cascade(label="Admin", menu=admin_menu)
        menubar.add_command(label="Help", command=self.open_help)
        self.config(menu=menubar)

        # Top bar
        topbar = ttk.Frame(self, padding=6)
        topbar.pack(fill="x")
        ttk.Label(topbar, text="Advanced Kali Automator (Safe)", font=("Helvetica", 16)).pack(side="left")
        self.user_label = ttk.Label(topbar, text="Not logged in")
        self.user_label.pack(side="left", padx=8)
        ttk.Button(topbar, text="Login", command=self.open_login).pack(side="right")
        ttk.Button(topbar, text="Theme", command=self.toggle_theme).pack(side="right", padx=4)

        # Main panes
        paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        paned.pack(fill="both", expand=True)

        # Left: template list
        left = ttk.Frame(paned, width=360, padding=8)
        paned.add(left, weight=1)
        ttk.Label(left, text="Templates").pack(anchor="w")
        self.tpl_listbox = tk.Listbox(left, height=30)
        self.tpl_listbox.pack(fill="both", expand=True)
        self.tpl_listbox.bind("<<ListboxSelect>>", self.on_select_template)
        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Add", command=self.add_template).pack(side="left", padx=2)
        ttk.Button(btns, text="Edit", command=self.edit_template).pack(side="left", padx=2)
        ttk.Button(btns, text="Delete", command=self.delete_template).pack(side="left", padx=2)
        ttk.Button(btns, text="Approve", command=self.approve_template).pack(side="left", padx=2)
        ttk.Button(btns, text="Reload", command=self.load_templates).pack(side="left", padx=2)

        # Right: parameters, preview, actions, interactive terminal + output
        right = ttk.Frame(paned, padding=8)
        paned.add(right, weight=3)
        ttk.Label(right, text="Parameters").pack(anchor="w")
        self.params_container = ttk.Frame(right)
        self.params_container.pack(fill="x")
        ttk.Label(right, text="Preview Command").pack(anchor="w", pady=(6,0))
        self.preview_box = tk.Text(right, height=4)
        self.preview_box.pack(fill="x")

        actionrow = ttk.Frame(right)
        actionrow.pack(fill="x", pady=6)
        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(actionrow, text="Dry-run (default)", variable=self.dry_run_var).pack(side="left", padx=4)
        self.as_root_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(actionrow, text="Run as root (sudo) [admin only]", variable=self.as_root_var).pack(side="left", padx=4)
        self.sandbox_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(actionrow, text="Sandbox (Docker) if available", variable=self.sandbox_var).pack(side="left", padx=4)
        ttk.Button(actionrow, text="Preview", command=self.preview_command).pack(side="left", padx=4)
        ttk.Button(actionrow, text="Run", command=self.run_template).pack(side="left", padx=4)
        ttk.Button(actionrow, text="Schedule", command=self.schedule_template).pack(side="left", padx=4)
        ttk.Button(actionrow, text="Show Logs", command=self.open_logs).pack(side="right", padx=4)

        # Embedded terminal area (replaces simple text output)
        ttk.Label(right, text="Interactive Terminal / Job updates").pack(anchor="w", pady=(6,0))

        self.term_container = tk.Frame(right, bg="black", height=360)
        self.term_container.pack(fill="both", expand=True, pady=(4,8))
        self.term_container.update()  # help ensure winfo_id is available later

        term_control_frame = ttk.Frame(right)
        term_control_frame.pack(fill="x", pady=(0,6))
        ttk.Button(term_control_frame, text="Open Embedded Terminal", command=self.open_embedded_terminal).pack(side="left", padx=4)
        ttk.Button(term_control_frame, text="Kill Embedded Terminal", command=self.kill_embedded_terminal).pack(side="left", padx=4)
        ttk.Button(term_control_frame, text="Run in Embedded Terminal", command=lambda: self.run_preview_in_terminal(embedded=True)).pack(side="left", padx=4)
        ttk.Button(term_control_frame, text="Run in External Terminal", command=lambda: self.run_preview_in_terminal(embedded=False)).pack(side="left", padx=4)

        # a small readonly text log duplicate for non-interactive job updates
        self.output_box = tk.Text(right, height=8)
        self.output_box.pack(fill="x", padx=2, pady=(4,0))

        # Bottom status
        self.status = ttk.Label(self, text="Ready", anchor="w")
        self.status.pack(fill="x", side="bottom")

    # -------------------------
    # Templates
    # -------------------------
    def load_templates(self):
        self.templates = list_templates()
        self.tpl_listbox.delete(0, tk.END)
        for t in self.templates:
            tag = "[A]" if t["approved"] else "[ ]"
            self.tpl_listbox.insert(tk.END, f"{tag} {t['name']}")

    def on_select_template(self, evt=None):
        sel = self.tpl_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        self.selected_template = self.templates[idx]
        self.preview_box.delete("1.0", tk.END)
        self.preview_box.insert("1.0", self.selected_template["pattern"])
        self.build_params_ui(self.selected_template.get("metadata", {}))

    def build_params_ui(self, metadata):
        # clear previous
        for child in self.params_container.winfo_children():
            child.destroy()
        self.param_widgets = {}
        params = metadata.get("params", [])
        if not params:
            ttk.Label(self.params_container, text="No parameters defined for this template").pack(anchor="w")
            return
        for p in params:
            frame = ttk.Frame(self.params_container)
            frame.pack(fill="x", pady=2)
            label = p.get("label", p["name"])
            ttk.Label(frame, text=label, width=20).pack(side="left")
            ptype = p.get("type", "string")
            default = p.get("default", "")
            if ptype == "string":
                e = ttk.Entry(frame)
                e.insert(0, default)
                e.pack(side="left", fill="x", expand=True)
                self.param_widgets[p["name"]] = ("string", e)
            elif ptype == "int":
                e = ttk.Entry(frame)
                e.insert(0, str(default))
                e.pack(side="left", fill="x", expand=True)
                self.param_widgets[p["name"]] = ("int", e)
            elif ptype == "choice":
                opts = p.get("options", [])
                cb = ttk.Combobox(frame, values=opts, state="readonly")
                cb.set(default if default in opts else (opts[0] if opts else ""))
                cb.pack(side="left", fill="x", expand=True)
                self.param_widgets[p["name"]] = ("choice", cb)
            elif ptype == "file":
                ent = ttk.Entry(frame)
                ent.insert(0, default)
                ent.pack(side="left", fill="x", expand=True)
                def browse(entry=ent):
                    f = filedialog.askopenfilename()
                    if f:
                        entry.delete(0, tk.END)
                        entry.insert(0, f)
                ttk.Button(frame, text="Browse", command=browse).pack(side="left")
                self.param_widgets[p["name"]] = ("file", ent)
            else:
                e = ttk.Entry(frame)
                e.insert(0, default)
                e.pack(side="left", fill="x", expand=True)
                self.param_widgets[p["name"]] = ("string", e)

    def read_params(self):
        params = {}
        for name, (ptype, widget) in self.param_widgets.items():
            val = widget.get().strip()
            if ptype == "int":
                if val == "":
                    raise ValueError(f"Parameter '{name}' required and must be integer.")
                if not val.isdigit():
                    raise ValueError(f"Parameter '{name}' must be integer.")
                params[name] = int(val)
            else:
                params[name] = val
        return params

    def add_template(self):
        if not self.current_user:
            messagebox.showwarning("Login required", "Please login to add templates.")
            return
        dlg = TemplateEditorDialog(self, None)
        self.wait_window(dlg.top)
        if not getattr(dlg, "result", None):
            return
        name, pattern, metadata, desc = dlg.result
        dangerous, token = looks_dangerous(pattern)
        if dangerous:
            if not messagebox.askyesno("Dangerous token", f"Template pattern contains token '{token}'. Save anyway?"):
                return
        try:
            save_template(name, pattern, metadata, desc, self.current_user, approved=False)
            self.load_templates()
            messagebox.showinfo("Saved", "Template saved (pending admin approval).")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def edit_template(self):
        if not self.selected_template:
            messagebox.showwarning("Select", "Select a template to edit first.")
            return
        # only creator or admin may edit
        if not (self.selected_template.get("created_by") == self.current_user or get_user_role(self.current_user) == "admin"):
            messagebox.showerror("Permission denied", "Only the template author or an admin can edit this template.")
            return
        dlg = TemplateEditorDialog(self, self.selected_template)
        self.wait_window(dlg.top)
        if not getattr(dlg, "result", None):
            return
        name, pattern, metadata, desc = dlg.result
        try:
            save_template(name, pattern, metadata, desc, self.current_user, approved=self.selected_template["approved"])
            self.load_templates()
            messagebox.showinfo("Saved", "Template updated.")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def delete_template(self):
        if not self.selected_template:
            messagebox.showwarning("Select", "Select a template to delete.")
            return
        if not messagebox.askyesno("Confirm", f"Delete template '{self.selected_template['name']}'?"):
            return
        try:
            delete_template(self.selected_template["id"])
            self.selected_template = None
            self.load_templates()
        except Exception as e:
            messagebox.showerror("Delete error", str(e))

    def approve_template(self):
        if not self.current_user or get_user_role(self.current_user) != "admin":
            messagebox.showerror("Admin required", "Only admins can approve templates.")
            return
        if not self.selected_template:
            messagebox.showwarning("Select", "Select template to approve.")
            return
        approve_template(self.selected_template["id"])
        self.load_templates()
        messagebox.showinfo("Approved", "Template approved.")

    # -------------------------
    # Preview / Run / Schedule
    # -------------------------
    def preview_command(self):
        try:
            params = self.read_params() if self.param_widgets else {}
        except Exception as e:
            messagebox.showerror("Params error", str(e)); return
        if not self.selected_template:
            messagebox.showwarning("Select", "Select a template first."); return
        try:
            cmd = build_command(self.selected_template["pattern"], params)
            self.preview_box.delete("1.0", tk.END)
            self.preview_box.insert("1.0", cmd)
        except Exception as e:
            messagebox.showerror("Preview error", str(e))

    def run_template(self):
        if not self.current_user:
            messagebox.showwarning("Login required", "Please login before running jobs."); return
        if not self.selected_template:
            messagebox.showwarning("Select", "Select a template first."); return
        if not self.selected_template["approved"]:
            messagebox.showwarning("Not approved", "This template is not approved for execution."); return
        try:
            params = self.read_params() if self.param_widgets else {}
        except Exception as e:
            messagebox.showerror("Params error", str(e)); return
        dry = bool(self.dry_run_var.get())
        as_root = bool(self.as_root_var.get())
        sandbox = bool(self.sandbox_var.get())
        if as_root and get_user_role(self.current_user) != "admin":
            messagebox.showerror("Admin only", "Only admins may request root execution."); return
        # queue job
        def on_update(info):
            def ui():
                self.output_box.insert(tk.END, f"[{now_iso()}] {json.dumps(info, default=str)}\n")
                self.output_box.see("end")
            self.after(1, ui)
        JOB_QUEUE.put({
            "template": self.selected_template,
            "params": params,
            "user": self.current_user,
            "dry_run": dry,
            "as_root": as_root,
            "sandbox": sandbox,
            "on_update": on_update
        })
        self.output_box.insert(tk.END, f"[{now_iso()}] Queued: {self.selected_template['name']} (dry={dry} as_root={as_root} sandbox={sandbox})\n")
        self.output_box.see("end")

    def schedule_template(self):
        if not self.current_user:
            messagebox.showwarning("Login required", "Please login to schedule jobs."); return
        if not self.selected_template:
            messagebox.showwarning("Select", "Select a template first."); return
        s = simpledialog.askstring("Schedule", "Enter UTC datetime (YYYY-MM-DD HH:MM:SS) or +seconds (e.g. +60):")
        if not s:
            return
        try:
            if s.startswith("+"):
                run_at = time.time() + int(s[1:])
            else:
                dt = datetime.datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
                run_at = dt.replace(tzinfo=datetime.timezone.utc).timestamp()
        except Exception as e:
            messagebox.showerror("Invalid", str(e)); return
        try:
            params = self.read_params() if self.param_widgets else {}
        except Exception as e:
            messagebox.showerror("Params error", str(e)); return
        jid = add_scheduled_job(self.selected_template["id"], params, run_at, self.current_user)
        messagebox.showinfo("Scheduled", f"Job scheduled (id={jid}) for {datetime.datetime.utcfromtimestamp(run_at).isoformat()}Z")

    # -------------------------
    # Users / Settings / Import / Export / Logs
    # -------------------------
    def open_users(self):
        if not self.current_user or get_user_role(self.current_user) != "admin":
            messagebox.showerror("Admin required", "Only admins can manage users.")
            return
        UsersDialog(self)

    def open_settings(self):
        if not self.current_user or get_user_role(self.current_user) != "admin":
            messagebox.showerror("Admin required", "Only admins can change settings.")
            return
        SettingsDialog(self)

    def import_templates(self):
        p = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if not p:
            return
        try:
            with open(p, "r") as f:
                data = json.load(f)
            count = 0
            for tpl in data:
                try:
                    save_template(tpl["name"], tpl["pattern"], tpl.get("metadata", {}), tpl.get("description",""), self.current_user or "imported", approved=bool(tpl.get("approved", False)))
                    count += 1
                except Exception:
                    pass
            self.load_templates()
            messagebox.showinfo("Imported", f"Imported {count} templates.")
        except Exception as e:
            messagebox.showerror("Import failed", str(e))

    def export_templates(self):
        p = filedialog.asksaveasfilename(defaultextension=".json")
        if not p:
            return
        try:
            tpls = list_templates()
            out = []
            for t in tpls:
                out.append({"name": t["name"], "pattern": t["pattern"], "metadata": t.get("metadata", {}), "description": t.get("description","")})
            with open(p, "w") as f:
                json.dump(out, f, indent=2)
            messagebox.showinfo("Exported", f"Exported {len(out)} templates.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def open_logs(self):
        LogsDialog(self)

    # -------------------------
    # Login, help, theme
    # -------------------------
    def open_login(self):
        dlg = LoginDialog(self)
        self.wait_window(dlg.top)
        if getattr(dlg, "result", None):
            username, password = dlg.result
            if authenticate(username, password):
                self.current_user = username
                self.user_label.config(text=f"User: {username} ({get_user_role(username)})")
                messagebox.showinfo("Login", f"Welcome, {username}")
            else:
                messagebox.showerror("Login failed", "Invalid credentials")

    def open_help(self):
        help_text = ("Advanced Kali Automator (Safe)\n\n"
                     "This application is safe-by-default. Execution of real commands is disabled until an admin enables it in Settings.\n\n"
                     "Rules:\n"
                     "- Templates must be created and approved by an admin before they can run.\n"
                     "- The whitelist restricts which command names may be executed.\n"
                     "- Do NOT use this tool against systems you do not own or have explicit written permission to test.\n")
        messagebox.showinfo("Help", help_text)

    def toggle_theme(self):
        current = get_theme()
        set_theme("dark" if current == "light" else "light")
        self.apply_theme()

    def apply_theme(self):
        t = get_theme()
        style = ttk.Style()
        if t == "dark":
            style.theme_use("clam")
            self.configure(bg="#2e2e2e")
            style.configure(".", background="#2e2e2e", foreground="white", fieldbackground="#3a3a3a")
            self.preview_box.configure(bg="#2b2b2b", fg="white")
            self.output_box.configure(bg="#2b2b2b", fg="white")
        else:
            style.theme_use("default")
            self.configure(bg=None)
            self.preview_box.configure(bg="white", fg="black")
            self.output_box.configure(bg="white", fg="black")

    # -------------------------
    # Embedded / External Terminal helpers
    # -------------------------
    def open_embedded_terminal(self):
        """Start an xterm embedded into self.term_container (using -into <winid>)."""
        if which("xterm") is None:
            messagebox.showerror("xterm missing", "xterm not found. Install with: sudo apt install xterm\nFalling back to external terminal.")
            return

        # If already running, do nothing
        if self.embedded_term_proc and self.embedded_term_proc.poll() is None:
            messagebox.showinfo("Embedded terminal", "Embedded terminal already running.")
            return

        try:
            winid = self.term_container.winfo_id()
        except Exception as e:
            messagebox.showerror("Window error", f"Failed to get container window id: {e}")
            return

        # Launch xterm embedded with interactive shell
        cmd = ["xterm", "-sb", "-into", str(winid), "-bg", "black", "-fg", "white", "-title", "Embedded-Terminal", "-e", "bash", "-l"]
        try:
            self.embedded_term_proc = subprocess.Popen(cmd)
            self.embedded_term_winid = winid
            self.after(300, lambda: self.output_box.insert("end", f"[{now_iso()}] Embedded xterm started (pid={self.embedded_term_proc.pid}).\n"))
        except Exception as e:
            messagebox.showerror("Failed to start xterm", str(e))
            self.embedded_term_proc = None
            self.embedded_term_winid = None

    def kill_embedded_terminal(self):
        """Kill the embedded xterm if running."""
        try:
            if self.embedded_term_proc and self.embedded_term_proc.poll() is None:
                self.embedded_term_proc.terminate()
                def _kill_wait():
                    time.sleep(1)
                    if self.embedded_term_proc and self.embedded_term_proc.poll() is None:
                        try:
                            self.embedded_term_proc.kill()
                        except Exception:
                            pass
                threading.Thread(target=_kill_wait, daemon=True).start()
                self.output_box.insert("end", f"[{now_iso()}] Terminating embedded xterm (pid={self.embedded_term_proc.pid}).\n")
            else:
                self.output_box.insert("end", f"[{now_iso()}] No embedded terminal running.\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.embedded_term_proc = None
            self.embedded_term_winid = None

    def run_preview_in_terminal(self, embedded=True):
        """
        Run the current preview command in embedded or external terminal.
        If embedded=True, starts an embedded xterm running the command and leaves a shell.
        """
        cmd_text = self.preview_box.get("1.0", "end").strip()
        if not cmd_text:
            messagebox.showwarning("No command", "Preview is empty. Hit Preview to format the command first.")
            return

        try:
            safe_check_text(cmd_text)
        except Exception as e:
            if not messagebox.askyesno("Unsafe characters", f"Preview includes characters flagged as unsafe: {e}\nRun anyway?"):
                return

        if embedded and which("xterm"):
            # kill existing embedded xterm so we can start a new one into same frame
            try:
                if self.embedded_term_proc and self.embedded_term_proc.poll() is None:
                    try:
                        self.embedded_term_proc.terminate()
                        time.sleep(0.3)
                        if self.embedded_term_proc.poll() is None:
                            self.embedded_term_proc.kill()
                    except Exception:
                        pass
                winid = self.term_container.winfo_id()
                # Construct command to run the command and keep a shell
                # Use bash -lc "<cmd>; echo; echo '---done---'; exec bash"
                bash_cmd = f"bash -lc \"{cmd_text}; echo; echo '--- command finished ---'; exec bash\""
                xterm_cmd = ["xterm", "-sb", "-into", str(winid), "-bg", "black", "-fg", "white", "-title", "Embedded-Terminal", "-e", bash_cmd]
                self.embedded_term_proc = subprocess.Popen(xterm_cmd)
                self.output_box.insert("end", f"[{now_iso()}] Running in embedded terminal (pid={self.embedded_term_proc.pid})\n")
                self.output_box.see("end")
            except Exception as e:
                messagebox.showerror("Embedded terminal failed", f"Failed to start embedded terminal: {e}\nWill try external terminal instead.")
                self.run_in_external_terminal(cmd_text)
            return

        # Fallback: run in external terminal emulator
        self.run_in_external_terminal(cmd_text)

    def run_in_external_terminal(self, full_command):
        """
        Launch an interactive external terminal emulator executing the given command and leaving a shell.
        Tries several common terminal emulators with compatible flags.
        """
        candidates = []
        candidates.append(("gnome-terminal", lambda c: ["gnome-terminal", "--", "bash", "-lc", f"{c}; exec bash"]))
        candidates.append(("xterm", lambda c: ["xterm", "-hold", "-e", f"bash -lc \"{c}; exec bash\""]))
        candidates.append(("xfce4-terminal", lambda c: ["xfce4-terminal", "--command", f"bash -lc \"{c}; exec bash\""]))
        candidates.append(("konsole", lambda c: ["konsole", "-e", f"bash -lc \"{c}; exec bash\""]))
        candidates.append(("x-terminal-emulator", lambda c: ["x-terminal-emulator", "-e", f"bash -lc \"{c}; exec bash\""]))

        for name, builder in candidates:
            if which(name):
                try:
                    args = builder(full_command)
                    subprocess.Popen(args)
                    self.output_box.insert("end", f"[{now_iso()}] Launched external terminal ({name}).\n")
                    return
                except Exception:
                    continue

        messagebox.showerror("No terminal found", "No supported external terminal emulator found (tried gnome-terminal, xterm, konsole, xfce4-terminal). Install one or use embedded xterm.")

    # -------------------------
    # Exit
    # -------------------------
    def on_exit(self):
        try:
            JOB_QUEUE.put(None)
        except Exception:
            pass
        try:
            if self.embedded_term_proc and self.embedded_term_proc.poll() is None:
                self.embedded_term_proc.terminate()
        except Exception:
            pass
        self.destroy()

# -------------------------
# Dialog classes
# -------------------------
class LoginDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Login")
        self.result = None
        ttk.Label(self.top, text="Username").pack(padx=6, pady=2)
        self.user_e = ttk.Entry(self.top)
        self.user_e.pack(padx=6, pady=2)
        ttk.Label(self.top, text="Password").pack(padx=6, pady=2)
        self.pw_e = ttk.Entry(self.top, show="*")
        self.pw_e.pack(padx=6, pady=2)
        ttk.Button(self.top, text="Login", command=self.on_ok).pack(pady=8)

    def on_ok(self):
        u = self.user_e.get().strip(); p = self.pw_e.get().strip()
        if not u or not p:
            messagebox.showerror("Missing", "Provide username and password"); return
        self.result = (u, p)
        self.top.destroy()

class UsersDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Users (admin)")
        self.parent = parent
        cols = ("username","role")
        self.tree = ttk.Treeview(self.top, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True)
        btnf = ttk.Frame(self.top)
        btnf.pack(fill="x")
        ttk.Button(btnf, text="Add", command=self.add_user).pack(side="left")
        ttk.Button(btnf, text="Delete", command=self.delete_user).pack(side="left")
        ttk.Button(btnf, text="Change PW", command=self.change_pw).pack(side="left")
        self.refresh()

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for u, role in list_users():
            self.tree.insert("", "end", values=(u, role))

    def add_user(self):
        u = simpledialog.askstring("Username", "Username:", parent=self.top)
        if not u: return
        p = simpledialog.askstring("Password", "Password:", parent=self.top, show="*")
        if not p: return
        role = simpledialog.askstring("Role", "Role (admin/operator/viewer):", parent=self.top, initialvalue="operator")
        if role not in ("admin","operator","viewer"):
            messagebox.showerror("Invalid", "Role must be admin/operator/viewer"); return
        try:
            add_user(u, p, role)
            self.refresh()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_user(self):
        sel = self.tree.selection()
        if not sel: return
        u = self.tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Confirm", f"Delete user {u}?"):
            delete_user(u)
            self.refresh()

    def change_pw(self):
        sel = self.tree.selection()
        if not sel: return
        u = self.tree.item(sel[0])["values"][0]
        p = simpledialog.askstring("Password", f"New password for {u}:", parent=self.top, show="*")
        if not p: return
        update_password(u, p)
        messagebox.showinfo("OK", "Password updated")

def update_password(username, newpw):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_pw(newpw), username))
        DB.commit()

class SettingsDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Settings (admin)")
        self.parent = parent
        ttk.Label(self.top, text="Whitelist (one token per line)").pack(anchor="w")
        self.whitelist_text = tk.Text(self.top, height=8)
        self.whitelist_text.pack(fill="both")
        self.whitelist_text.insert("1.0", "\n".join(get_whitelist()))
        self.exec_var = tk.BooleanVar(value=execution_enabled())
        ttk.Checkbutton(self.top, text="Enable real command execution (dangerous)", variable=self.exec_var).pack(anchor="w", pady=4)
        ttk.Label(self.top, text="Theme").pack(anchor="w")
        self.theme_var = tk.StringVar(value=get_theme())
        ttk.Radiobutton(self.top, text="Light", variable=self.theme_var, value="light").pack(anchor="w")
        ttk.Radiobutton(self.top, text="Dark", variable=self.theme_var, value="dark").pack(anchor="w")
        ttk.Button(self.top, text="Save", command=self.on_save).pack(pady=6)

    def on_save(self):
        wl = [l.strip() for l in self.whitelist_text.get("1.0", tk.END).splitlines() if l.strip()]
        set_whitelist(wl)
        set_execution_enabled(bool(self.exec_var.get()))
        set_theme(self.theme_var.get())
        messagebox.showinfo("Saved", "Settings saved")
        self.top.destroy()

class TemplateEditorDialog:
    def __init__(self, parent, existing):
        self.top = tk.Toplevel(parent)
        self.top.title("Template Editor")
        self.result = None
        ttk.Label(self.top, text="Name").grid(row=0, column=0, sticky="w")
        self.name_entry = ttk.Entry(self.top, width=70); self.name_entry.grid(row=0, column=1)
        ttk.Label(self.top, text="Pattern (use {param} placeholders)").grid(row=1, column=0, sticky="w")
        self.pattern_entry = ttk.Entry(self.top, width=70); self.pattern_entry.grid(row=1, column=1)
        ttk.Label(self.top, text="Description").grid(row=2, column=0, sticky="w")
        self.desc_entry = ttk.Entry(self.top, width=70); self.desc_entry.grid(row=2, column=1)
        ttk.Label(self.top, text="Metadata JSON (params list)").grid(row=3, column=0, sticky="nw")
        self.meta_text = tk.Text(self.top, width=70, height=10); self.meta_text.grid(row=3, column=1)
        ttk.Label(self.top, text="Example metadata:\n{\"params\":[{\"name\":\"file\",\"type\":\"file\",\"label\":\"Input file\"},{\"name\":\"mode\",\"type\":\"choice\",\"options\":[\"a\",\"b\"],\"default\":\"a\"}]}").grid(row=4, column=1, sticky="w")
        ttk.Button(self.top, text="Save", command=self.on_save).grid(row=5, column=0, columnspan=2, pady=6)
        if existing:
            self.name_entry.insert(0, existing["name"])
            self.pattern_entry.insert(0, existing["pattern"])
            self.desc_entry.insert(0, existing.get("description",""))
            self.meta_text.insert("1.0", json.dumps(existing.get("metadata", {}), indent=2))

    def on_save(self):
        name = self.name_entry.get().strip()
        pattern = self.pattern_entry.get().strip()
        desc = self.desc_entry.get().strip()
        try:
            metadata = json.loads(self.meta_text.get("1.0", tk.END) or "{}")
        except Exception as e:
            messagebox.showerror("Metadata error", str(e)); return
        if not name or not pattern:
            messagebox.showerror("Missing", "Name and pattern are required"); return
        if DISALLOWED_CHARS_RE.search(pattern):
            if not messagebox.askyesno("Warning", "Pattern contains special shell characters. Save anyway?"):
                return
        self.result = (name, pattern, metadata, desc)
        self.top.destroy()

class LogsDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Logs")
        cols = ("id","template_name","user","started","finished","rc")
        self.tree = ttk.Treeview(self.top, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True)
        btnf = ttk.Frame(self.top); btnf.pack(fill="x")
        ttk.Button(btnf, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(btnf, text="View", command=self.view).pack(side="left")
        ttk.Button(btnf, text="Export CSV", command=self.export_csv).pack(side="left")
        self.refresh()

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for row in get_logs():
            self.tree.insert("", "end", values=row)

    def view(self):
        sel = self.tree.selection()
        if not sel: return
        lid = self.tree.item(sel[0])["values"][0]
        r = get_log_detail(lid)
        if not r:
            messagebox.showerror("Not found", "Log not found"); return
        txt = f"Template: {r[0]}\nUser: {r[1]}\nParams: {r[2]}\nCommand: {r[3]}\n\nSTDOUT:\n{r[4]}\n\nSTDERR:\n{r[5]}\n\nRC: {r[6]}\nStarted: {r[7]}\nFinished: {r[8]}"
        ViewWindow(self.top, "Log Detail", txt)

    def export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension=".csv")
        if not p: return
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id,template_name,user,params_json,command,stdout,stderr,rc,started_at,finished_at FROM logs ORDER BY id DESC")
            rows = cur.fetchall()
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id","template","user","params","command","stdout","stderr","rc","started","finished"])
            for r in rows:
                w.writerow(r)
        messagebox.showinfo("Exported", f"Exported {len(rows)} logs to {p}")

class ViewWindow:
    def __init__(self, parent, title, text):
        top = tk.Toplevel(parent); top.title(title)
        t = tk.Text(top); t.pack(fill="both", expand=True)
        t.insert("1.0", text)

# -------------------------
# Add a couple safe example templates (if none exist)
# -------------------------
def ensure_samples():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT COUNT(*) FROM templates")
        if cur.fetchone()[0] == 0:
            sample1 = {
                "name": "Show uptime",
                "pattern": "uptime",
                "metadata": {"params": []},
                "description": "Show system uptime",
                "approved": 1
            }
            sample2 = {
                "name": "Echo",
                "pattern": "echo {msg}",
                "metadata": {"params":[{"name":"msg","type":"string","label":"Message","default":"hello"}]},
                "description": "Echo message (safe example)",
                "approved": 1
            }
            sample3 ={
                "name": "Nmap",
                "pattern": "nmap {target}",
                "metadata": {"params": [{"name":"target","type":"string","label":"Target Ip Or Hostanme","default":"127.0.0.1" }]},
                "description": "Simple Nmap target scan ",
                "approved": 1

            }
            sample4 = {
                "name": "Nmap Ping Sweep",
                "pattern": "nmap -sn {target} ",
                "metadata": {"params": [{"name":"targets","type":"string","label":"Targets (CIDR, range or comma-separated)","default":""}]},
                "description": "Ping sweep / host discovery for network (use CIDR or range).",
                "approved": 1
            }
            sample5 = {

            }

            for s in (sample1, sample2,sample3,sample4,sample5):
                cur.execute("INSERT OR REPLACE INTO templates (name,pattern,metadata_json,description,approved,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
                            (s["name"], s["pattern"], json.dumps(s["metadata"]), s["description"], int(s["approved"]), "system", now_iso()))
            DB.commit()

ensure_samples()

# -------------------------
# Start the app
# -------------------------
def main():
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
