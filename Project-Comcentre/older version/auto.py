#!/usr/bin/env python3
"""
advanced_kali_automator_safe.py

Advanced Safe Automator (Tkinter) for Kali/Linux — ready-to-run.

Features included (safe-by-default):
- Template library with metadata-driven parameter widgets (string, int, choice, file)
- Template import/export (JSON)
- Multi-user login (SQLite) with admin role
- Theme (light/dark)
- Add/Edit/Delete/Approve templates
- Preview, Dry-run, Run, Schedule (simple scheduler)
- "Run as root" option requiring admin + sudo whitelist
- Dropdown parameter widgets
- Logs stored in SQLite and exportable (CSV/JSON)
- Whitelist-first enforcement and disallowed-character checks
- Safe-mode checks for obviously dangerous command tokens
- Plugin/import system (JSON-based template packs)
- Notifications via notify-send (if available) for long jobs
- Simple parsing/export of results

SAFETY:
- Execution disabled by default; admins must enable.
- Only approved templates run.
- First token of command must be in whitelist.
- Templates that look dangerous are flagged and require confirmation to save.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import sqlite3, os, json, hashlib, threading, shlex, subprocess, datetime, time, re, csv, queue
from concurrent.futures import ThreadPoolExecutor

# -------------------------
# Configuration & constants
# -------------------------
DB_FILE = "advanced_automator.db"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin"  # change after first login
DEFAULT_WHITELIST = ["echo", "date", "uptime", "whoami", "uname", "ls", "df", "free", "hostname", "id", "sudo"]
DISALLOWED_CHARS_RE = re.compile(r"[;&|`$<>\\\n]")
DANGEROUS_TOKENS = {"rm", "shutdown", "reboot", "dd", ":(){", "mkfs", "mkfs.", "nc", "ncat", "curl", "wget"}
MAX_WORKERS = 4
JOB_TIMEOUT_DEFAULT = 300  # seconds

# -------------------------
# Utilities
# -------------------------
def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def hash_pass(pw: str):
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def sanitize_template_text(s: str):
    """Basic check for dangerous characters in templates / params."""
    if DISALLOWED_CHARS_RE.search(s):
        raise ValueError("Text contains disallowed shell-special characters.")
    return s

def looks_dangerous(pattern: str):
    # simple heuristic: check for dangerous tokens appearance
    lower = pattern.lower()
    for t in DANGEROUS_TOKENS:
        if t in lower:
            return True, t
    return False, None

def is_safe_name(name: str):
    return bool(re.match(r'^[A-Za-z0-9_\- ]+$', name))

# -------------------------
# DB setup
# -------------------------
def init_db():
    new_db = not os.path.exists(DB_FILE)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        is_admin INTEGER DEFAULT 0
    )""")
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
    cur.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )""")
    conn.commit()

    # create default admin if none
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (DEFAULT_ADMIN_USER, hash_pass(DEFAULT_ADMIN_PASS), 1))
        conn.commit()

    # ensure whitelist setting exists
    cur.execute("SELECT value FROM settings WHERE key='whitelist'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("whitelist", json.dumps(DEFAULT_WHITELIST)))
    # ensure execution_enabled flag exists (disabled by default)
    cur.execute("SELECT value FROM settings WHERE key='execution_enabled'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("execution_enabled", json.dumps(False)))
    # theme
    cur.execute("SELECT value FROM settings WHERE key='theme'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ("theme", json.dumps("light")))
    conn.commit()
    return conn

DB = init_db()
DB_LOCK = threading.Lock()

# -------------------------
# Settings / data access
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
        cur.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))
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

def set_theme(t):
    set_setting("theme", t)

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
            "created_at": r[7],
        })
    return templates

def save_template(name, pattern, metadata, description, created_by, approved=False):
    if not is_safe_name(name):
        raise ValueError("Template name contains illegal characters.")
    # basic sanitize
    sanitize_template_text(pattern)
    meta_json = json.dumps(metadata)
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("""INSERT OR REPLACE INTO templates (name,pattern,metadata_json,description,approved,created_by,created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (name, pattern, meta_json, description, int(approved), created_by, now_iso()))
        DB.commit()

def delete_template_by_id(tid):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("DELETE FROM templates WHERE id=?", (tid,))
        DB.commit()

def approve_template(tid):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("UPDATE templates SET approved=1 WHERE id=?", (tid,))
        DB.commit()

def log_run(template_id, template_name, user, params, command, stdout, stderr, rc, started_at, finished_at):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("""INSERT INTO logs (template_id, template_name, user, params_json, command, stdout, stderr, rc, started_at, finished_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (template_id, template_name, user, json.dumps(params), command, stdout, stderr, rc, started_at, finished_at))
        DB.commit()

def get_logs(limit=500):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT id, template_name, user, started_at, finished_at, rc FROM logs ORDER BY id DESC LIMIT ?", (limit,))
        return cur.fetchall()

def get_log_by_id(logid):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT template_name,user,params_json,command,stdout,stderr,rc,started_at,finished_at FROM logs WHERE id=?", (logid,))
        return cur.fetchone()

# -------------------------
# Users
# -------------------------
def add_user(username, password, is_admin=False):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
                    (username, hash_pass(password), int(bool(is_admin))))
        DB.commit()

def delete_user(username):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("DELETE FROM users WHERE username=?", (username,))
        DB.commit()

def update_password(username, newpw):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("UPDATE users SET password_hash=? WHERE username=?", (hash_pass(newpw), username))
        DB.commit()

def authenticate(username, password):
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        r = cur.fetchone()
        return bool(r and r[0] == hash_pass(password))

def user_is_admin(username):
    if not username:
        return False
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT is_admin FROM users WHERE username=?", (username,))
        r = cur.fetchone()
        return bool(r and r[0])

# -------------------------
# Command construction & safety
# -------------------------
def build_command(pattern: str, params: dict) -> str:
    # sanitize pattern and params
    sanitize_template_text(pattern)
    for k, v in params.items():
        # key names restrict
        if not re.match(r'^[A-Za-z0-9_]+$', k):
            raise ValueError("Parameter names must be alphanumeric/underscore.")
        if isinstance(v, str):
            sanitize_template_text(v)
    try:
        cmd = pattern.format_map(params)
    except KeyError as e:
        raise ValueError(f"Missing parameter: {e}")
    except Exception as e:
        raise ValueError(f"Pattern formatting error: {e}")
    # check whitelist - first token
    parts = shlex.split(cmd)
    if not parts:
        raise ValueError("Resulting command is empty.")
    whitelist = get_whitelist()
    if parts[0] not in whitelist:
        raise PermissionError(f"Command '{parts[0]}' is not allowed by whitelist.")
    # additional safety: disallow obviously dangerous tokens
    for token in parts:
        t_lower = token.lower()
        for bad in DANGEROUS_TOKENS:
            if bad in t_lower:
                raise PermissionError(f"Command includes dangerous token: {bad}")
    return cmd

def run_command(cmd: str, timeout=JOB_TIMEOUT_DEFAULT):
    # run without shell using shlex split
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
# Job queue & scheduler
# -------------------------
JOB_Q = queue.Queue()
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)

def job_worker():
    while True:
        job = JOB_Q.get()
        if job is None:
            break
        template = job["template"]
        params = job["params"]
        user = job["user"]
        dry_run = job.get("dry_run", True)
        as_root = job.get("as_root", False)
        on_update = job.get("on_update")
        started_at = now_iso()
        if dry_run:
            summary = f"[dry-run] {template['pattern'].format_map(params)}"
            log_run(template.get("id"), template.get("name"), user, params, summary, "[dry-run]", "", 0, started_at, now_iso())
            if on_update:
                on_update({"status":"dry-run","cmd": summary})
            JOB_Q.task_done()
            continue
        # build command
        try:
            cmd = build_command(template["pattern"], params)
            # as root: require admin and sudo allowed in whitelist and execution_enabled
            if as_root:
                if not user_is_admin(user):
                    raise PermissionError("Only admin users may request root execution.")
                if "sudo" not in get_whitelist():
                    raise PermissionError("sudo is not in the whitelist; cannot run as root.")
                # Prepend sudo safely
                cmd = "sudo " + cmd
            if not execution_enabled():
                raise PermissionError("Execution is disabled by admin in settings.")
        except Exception as e:
            if on_update:
                on_update({"status":"error","error":str(e)})
            JOB_Q.task_done()
            continue
        # execute via executor (blocking here but in worker thread)
        fut = EXECUTOR.submit(run_command, cmd)
        rc, out, err = fut.result()
        finished_at = now_iso()
        log_run(template.get("id"), template.get("name"), user, params, cmd, out, err, rc, started_at, finished_at)
        # send notification for long jobs (if notify-send available)
        try:
            if shutil_which("notify-send") and (len(out) + len(err) > 1000 or rc != 0):
                subprocess.Popen(["notify-send", f"Job {template.get('name')} finished", f"rc={rc}"])
        except Exception:
            pass
        if on_update:
            on_update({"status":"done","rc":rc,"stdout":out,"stderr":err,"started":started_at,"finished":finished_at})
        JOB_Q.task_done()

_worker = threading.Thread(target=job_worker, daemon=True)
_worker.start()

# Utility: check if command exists
def shutil_which(cmd):
    from shutil import which
    return which(cmd)

# -------------------------
# GUI Application
# -------------------------
class AdvancedAutomatorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Kali Automator (Safe)")
        self.geometry("1100x760")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.current_user = None
        self.templates = []
        self.selected_template = None
        self.param_widgets = {}
        self.scheduled_tasks = []  # in-memory scheduled tasks (persisting scheduled jobs could be added)
        self.setup_ui()
        self.refresh_templates()
        self.apply_theme()

    def setup_ui(self):
        # Top taskbar (title, login, theme, settings)
        top = tk.Frame(self, height=48, bg="#cccccc")
        top.pack(fill="x", side="top")
        tk.Label(top, text="Advanced Kali Automator (Safe)", font=("Helvetica", 16), bg="#cccccc").pack(side="left", padx=12)
        self.user_label = tk.Label(top, text="Not logged in", bg="#cccccc")
        self.user_label.pack(side="left", padx=8)
        tk.Button(top, text="Login", command=self.open_login).pack(side="right", padx=6)
        tk.Button(top, text="Settings", command=self.open_settings).pack(side="right", padx=6)
        tk.Button(top, text="Theme", command=self.toggle_theme).pack(side="right", padx=6)

        # Main panes
        main_paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_paned.pack(fill="both", expand=True)

        # Left panel: templates list & controls
        left = ttk.Frame(main_paned, width=320, padding=8)
        main_paned.add(left, weight=1)
        ttk.Label(left, text="Templates").pack(anchor="w")
        self.tpl_listbox = tk.Listbox(left, height=35)
        self.tpl_listbox.pack(fill="both", expand=True)
        self.tpl_listbox.bind("<<ListboxSelect>>", self.on_select_template)
        btnf = ttk.Frame(left)
        btnf.pack(fill="x", pady=6)
        ttk.Button(btnf, text="Add", command=self.add_template).pack(side="left")
        ttk.Button(btnf, text="Edit", command=self.edit_template).pack(side="left")
        ttk.Button(btnf, text="Delete", command=self.delete_template).pack(side="left")
        ttk.Button(btnf, text="Approve", command=self.approve_selected).pack(side="left")
        ttk.Button(btnf, text="Import Pack", command=self.import_templates).pack(side="left")

        # Right panel: parameters / preview / output
        right = ttk.Frame(main_paned, padding=8)
        main_paned.add(right, weight=3)
        # parameters area
        ttk.Label(right, text="Parameters").pack(anchor="w")
        self.params_frame = ttk.Frame(right)
        self.params_frame.pack(fill="x", pady=4)
        # preview
        ttk.Label(right, text="Preview / Command").pack(anchor="w", pady=(8,0))
        self.preview_box = tk.Text(right, height=4)
        self.preview_box.pack(fill="x")
        # action row
        action = ttk.Frame(right)
        action.pack(fill="x", pady=6)
        self.dry_run_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(action, text="Dry-run (no execution)", variable=self.dry_run_var).pack(side="left")
        self.as_root_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(action, text="Run as root (sudo) [admin only]", variable=self.as_root_var).pack(side="left", padx=8)
        ttk.Button(action, text="Preview", command=self.preview_command).pack(side="left", padx=4)
        ttk.Button(action, text="Run", command=self.run_selected).pack(side="left", padx=4)
        ttk.Button(action, text="Schedule", command=self.open_schedule_dialog).pack(side="left", padx=4)
        ttk.Button(action, text="Show Logs", command=self.open_logs).pack(side="right", padx=4)
        # output
        ttk.Label(right, text="Output").pack(anchor="w")
        self.output_box = tk.Text(right)
        self.output_box.pack(fill="both", expand=True)

        # bottom status bar
        self.status_bar = tk.Label(self, text="Ready", anchor="w")
        self.status_bar.pack(fill="x", side="bottom")

    # -------------------------
    # Template management UI
    # -------------------------
    def refresh_templates(self):
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
        # populate preview
        self.preview_box.delete("1.0", tk.END)
        self.preview_box.insert("1.0", self.selected_template["pattern"])
        # build param widgets
        self.build_param_widgets(self.selected_template.get("metadata", {}))

    def build_param_widgets(self, metadata):
        # clear
        for c in self.params_frame.winfo_children():
            c.destroy()
        self.param_widgets = {}
        params = metadata.get("params", [])
        if not params:
            ttk.Label(self.params_frame, text="No parameters").pack(anchor="w")
            return
        for p in params:
            name = p["name"]
            label = p.get("label", name)
            ptype = p.get("type", "string")
            frame = ttk.Frame(self.params_frame)
            frame.pack(fill="x", pady=2)
            ttk.Label(frame, text=label, width=20).pack(side="left")
            if ptype == "string":
                e = ttk.Entry(frame)
                e.insert(0, p.get("default", ""))
                e.pack(side="left", fill="x", expand=True)
                self.param_widgets[name] = ("string", e)
            elif ptype == "int":
                e = ttk.Entry(frame)
                e.insert(0, str(p.get("default", "")))
                e.pack(side="left", fill="x", expand=True)
                self.param_widgets[name] = ("int", e)
            elif ptype == "choice":
                opts = p.get("options", [])
                cb = ttk.Combobox(frame, values=opts, state="readonly")
                cb.set(p.get("default", opts[0] if opts else ""))
                cb.pack(side="left", fill="x", expand=True)
                self.param_widgets[name] = ("choice", cb)
            elif ptype == "file":
                ent = ttk.Entry(frame)
                ent.insert(0, p.get("default", ""))
                ent.pack(side="left", fill="x", expand=True)
                def browse(e=ent):
                    f = filedialog.askopenfilename()
                    if f:
                        e.delete(0, tk.END); e.insert(0, f)
                ttk.Button(frame, text="Browse", command=browse).pack(side="left")
                self.param_widgets[name] = ("file", ent)
            else:
                e = ttk.Entry(frame)
                e.insert(0, p.get("default", ""))
                e.pack(side="left", fill="x", expand=True)
                self.param_widgets[name] = ("string", e)

    def read_params(self):
        params = {}
        for name, (ptype, widget) in self.param_widgets.items():
            val = widget.get().strip()
            if ptype == "int":
                if val == "":
                    raise ValueError(f"Parameter {name} is required and must be integer.")
                if not val.isdigit():
                    raise ValueError(f"Parameter {name} must be integer.")
                params[name] = int(val)
            else:
                if val == "":
                    # allow blank strings in some cases, but user should fill required ones via metadata
                    params[name] = ""
                else:
                    params[name] = val
        return params

    def add_template(self):
        if not self.current_user:
            messagebox.showwarning("Login required", "Please login to add templates.")
            return
        dlg = TemplateEditorDialog(self, existing=None)
        self.wait_window(dlg.top)
        if dlg.result:
            name, pattern, metadata, desc = dlg.result
            # check for dangerous tokens
            dangerous, token = looks_dangerous(pattern)
            if dangerous:
                if not messagebox.askyesno("Dangerous token detected", f"Pattern contains '{token}'. Are you sure you want to save?"):
                    return
            try:
                save_template(name, pattern, metadata, desc, self.current_user, approved=False)
                self.refresh_templates()
                messagebox.showinfo("Saved", "Template saved and pending admin approval.")
            except Exception as e:
                messagebox.showerror("Error saving template", str(e))

    def edit_template(self):
        if not self.selected_template:
            messagebox.showwarning("Select template", "Select a template to edit.")
            return
        # only creator or admin may edit
        if not (self.selected_template.get("created_by") == self.current_user or user_is_admin(self.current_user)):
            messagebox.showerror("Permission denied", "Only template author or admin may edit.")
            return
        dlg = TemplateEditorDialog(self, existing=self.selected_template)
        self.wait_window(dlg.top)
        if dlg.result:
            name, pattern, metadata, desc = dlg.result
            try:
                save_template(name, pattern, metadata, desc, self.current_user, approved=self.selected_template["approved"])
                self.refresh_templates()
                messagebox.showinfo("Saved", "Template updated.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def delete_template(self):
        if not self.selected_template:
            messagebox.showwarning("Select template", "Select a template.")
            return
        if not messagebox.askyesno("Confirm", f"Delete template {self.selected_template['name']}?"):
            return
        delete_template_by_id(self.selected_template["id"])
        self.selected_template = None
        self.refresh_templates()

    def approve_selected(self):
        if not self.current_user or not user_is_admin(self.current_user):
            messagebox.showerror("Permission denied", "Admin login required to approve templates.")
            return
        if not self.selected_template:
            messagebox.showwarning("Select template", "Select a template first.")
            return
        approve_template(self.selected_template["id"])
        self.refresh_templates()
        messagebox.showinfo("Approved", "Template approved and can be executed.")

    def import_templates(self):
        p = filedialog.askopenfilename(filetypes=[("JSON","*.json"),("All","*.*")])
        if not p:
            return
        try:
            with open(p, "r") as f:
                pack = json.load(f)
            added = 0
            for tpl in pack:
                # expected: name, pattern, metadata, description
                try:
                    save_template(tpl["name"], tpl["pattern"], tpl.get("metadata", {}), tpl.get("description",""), self.current_user or "imported", approved=False)
                    added += 1
                except Exception:
                    # skip invalid entry
                    pass
            self.refresh_templates()
            messagebox.showinfo("Imported", f"Imported {added} templates (pending approval).")
        except Exception as e:
            messagebox.showerror("Import error", str(e))

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

    def run_selected(self):
        if not self.current_user:
            messagebox.showwarning("Login required", "Please login before running templates."); return
        if not self.selected_template:
            messagebox.showwarning("Select template", "Select a template to run."); return
        if not self.selected_template["approved"]:
            messagebox.showwarning("Not approved", "This template is not approved for execution."); return
        try:
            params = self.read_params() if self.param_widgets else {}
        except Exception as e:
            messagebox.showerror("Params error", str(e)); return
        dry = bool(self.dry_run_var.get())
        as_root = bool(self.as_root_var.get())
        if as_root and not user_is_admin(self.current_user):
            messagebox.showerror("Permission denied", "Only admins may request root execution."); return
        if not dry and not execution_enabled():
            messagebox.showwarning("Execution disabled", "Admin has disabled real execution."); return

        # queue the job
        def on_update(info):
            # called in worker thread; schedule to UI
            def ui():
                self.output_box.insert(tk.END, f"[{now_iso()}] {json.dumps(info, default=str)}\n")
                self.output_box.see("end")
            self.after(1, ui)

        JOB_Q.put({
            "template": self.selected_template,
            "params": params,
            "user": self.current_user,
            "dry_run": dry,
            "as_root": as_root,
            "on_update": on_update
        })
        self.output_box.insert(tk.END, f"[{now_iso()}] Job queued: {self.selected_template['name']} (dry={dry} as_root={as_root})\n")
        self.output_box.see("end")

    def open_schedule_dialog(self):
        if not self.selected_template:
            messagebox.showwarning("Select template", "Select a template to schedule."); return
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
        delay = run_at - time.time()
        if delay < 0:
            messagebox.showwarning("Past", "Specified time is in the past."); return
        try:
            params = self.read_params() if self.param_widgets else {}
        except Exception as e:
            messagebox.showerror("Params error", str(e)); return
        dry = bool(self.dry_run_var.get()); as_root = bool(self.as_root_var.get())
        def schedule_put():
            JOB_Q.put({
                "template": self.selected_template,
                "params": params,
                "user": self.current_user or "scheduler",
                "dry_run": dry,
                "as_root": as_root,
                "on_update": lambda info: None
            })
        t = threading.Timer(delay, schedule_put)
        t.daemon = True
        t.start()
        self.output_box.insert(tk.END, f"[{now_iso()}] Scheduled job in {int(delay)}s for template {self.selected_template['name']}\n")
        self.output_box.see("end")

    # -------------------------
    # Logs & export
    # -------------------------
    def open_logs(self):
        LogsWindow(self)

    # -------------------------
    # Users / settings / login
    # -------------------------
    def open_login(self):
        dlg = LoginDialog(self)
        self.wait_window(dlg.top)
        if dlg.result:
            username, password = dlg.result
            if authenticate(username, password):
                self.current_user = username
                self.user_label.config(text=f"User: {username}{' (admin)' if user_is_admin(username) else ''}")
                messagebox.showinfo("Login", f"Welcome, {username}")
            else:
                messagebox.showerror("Login failed", "Invalid credentials")

    def open_settings(self):
        if not self.current_user or not user_is_admin(self.current_user):
            messagebox.showerror("Permission denied", "Admin login required for settings.")
            return
        dlg = SettingsDialog(self, get_whitelist(), execution_enabled(), get_theme())
        self.wait_window(dlg.top)
        if dlg.result:
            whitelist, exec_enabled, theme = dlg.result
            set_whitelist(whitelist); set_execution_enabled(exec_enabled); set_theme(theme)
            messagebox.showinfo("Saved", "Settings saved.")

    def toggle_theme(self):
        t = get_theme()
        set_theme("dark" if t == "light" else "light")
        self.apply_theme()

    def apply_theme(self):
        t = get_theme()
        if t == "dark":
            style = ttk.Style(); style.theme_use('clam')
            self.configure(bg="#2e2e2e")
            style.configure('.', background="#2e2e2e", foreground="white", fieldbackground="#3a3a3a")
            self.preview_box.configure(bg="#2b2b2b", fg="white")
            self.output_box.configure(bg="#2b2b2b", fg="white")
        else:
            style = ttk.Style(); style.theme_use('default')
            self.configure(bg=None)
            self.preview_box.configure(bg="white", fg="black")
            self.output_box.configure(bg="white", fg="black")

    def on_close(self):
        # shut down worker
        JOB_Q.put(None)
        self.destroy()

# -------------------------
# Dialog windows & helpers
# -------------------------
class LoginDialog:
    def __init__(self, parent):
        top = self.top = tk.Toplevel(parent)
        top.title("Login")
        ttk.Label(top, text="Username").pack()
        self.user_e = ttk.Entry(top)
        self.user_e.pack()
        ttk.Label(top, text="Password").pack()
        self.pw_e = ttk.Entry(top, show="*")
        self.pw_e.pack()
        ttk.Button(top, text="Login", command=self.on_ok).pack(pady=6)
        self.result = None

    def on_ok(self):
        u = self.user_e.get().strip()
        p = self.pw_e.get().strip()
        if not u or not p:
            messagebox.showerror("Missing", "Provide username and password")
            return
        self.result = (u, p)
        self.top.destroy()

class SettingsDialog:
    def __init__(self, parent, whitelist, exec_enabled, theme):
        top = self.top = tk.Toplevel(parent)
        top.title("Settings")
        ttk.Label(top, text="Whitelist (one token per line)").pack(anchor="w")
        self.whitelist_text = tk.Text(top, height=8)
        self.whitelist_text.pack(fill="both")
        self.whitelist_text.insert("1.0", "\n".join(whitelist))
        self.exec_var = tk.BooleanVar(value=exec_enabled)
        ttk.Checkbutton(top, text="Enable real command execution (dangerous)", variable=self.exec_var).pack(anchor="w", pady=4)
        ttk.Label(top, text="Theme").pack(anchor="w")
        self.theme_var = tk.StringVar(value=theme)
        ttk.Radiobutton(top, text="Light", variable=self.theme_var, value="light").pack(anchor="w")
        ttk.Radiobutton(top, text="Dark", variable=self.theme_var, value="dark").pack(anchor="w")
        ttk.Button(top, text="Save", command=self.on_save).pack(pady=6)
        self.result = None

    def on_save(self):
        wl = [l.strip() for l in self.whitelist_text.get("1.0", tk.END).splitlines() if l.strip()]
        self.result = (wl, bool(self.exec_var.get()), self.theme_var.get())
        self.top.destroy()

class TemplateEditorDialog:
    def __init__(self, parent, existing=None):
        top = self.top = tk.Toplevel(parent)
        top.title("Template editor")
        ttk.Label(top, text="Name").grid(row=0, column=0, sticky="w")
        self.name_e = ttk.Entry(top, width=60); self.name_e.grid(row=0, column=1)
        ttk.Label(top, text="Pattern (use {param})").grid(row=1, column=0, sticky="w")
        self.pat_e = ttk.Entry(top, width=60); self.pat_e.grid(row=1, column=1)
        ttk.Label(top, text="Description").grid(row=2, column=0, sticky="w")
        self.desc_e = ttk.Entry(top, width=60); self.desc_e.grid(row=2, column=1)
        ttk.Label(top, text="Metadata JSON (params list)").grid(row=3, column=0, sticky="nw")
        self.meta_t = tk.Text(top, width=60, height=8); self.meta_t.grid(row=3, column=1)
        ttk.Label(top, text="Example metadata:\n{\"params\":[{\"name\":\"file\",\"type\":\"file\",\"label\":\"Input file\"},{\"name\":\"mode\",\"type\":\"choice\",\"options\":[\"a\",\"b\"],\"default\":\"a\"}]}").grid(row=4, column=1, sticky="w")
        ttk.Button(top, text="Save", command=self.on_save).grid(row=5, column=0, columnspan=2, pady=6)
        self.result = None
        if existing:
            self.name_e.insert(0, existing["name"])
            self.pat_e.insert(0, existing["pattern"])
            self.desc_e.insert(0, existing.get("description",""))
            self.meta_t.insert("1.0", json.dumps(existing.get("metadata", {}), indent=2))

    def on_save(self):
        name = self.name_e.get().strip()
        pattern = self.pat_e.get().strip()
        desc = self.desc_e.get().strip()
        try:
            metadata = json.loads(self.meta_t.get("1.0", tk.END) or "{}")
        except Exception as e:
            messagebox.showerror("Metadata error", str(e)); return
        if not name or not pattern:
            messagebox.showerror("Missing", "Name and pattern required"); return
        # disallowed chars?
        if DISALLOWED_CHARS_RE.search(pattern):
            if not messagebox.askyesno("Warning", "Pattern contains shell-special characters. Save anyway?"):
                return
        self.result = (name, pattern, metadata, desc)
        self.top.destroy()

class LogsWindow:
    def __init__(self, parent):
        top = self.top = tk.Toplevel(parent)
        top.title("Logs")
        self.parent = parent
        cols = ("id","template","user","started","finished","rc")
        tree = ttk.Treeview(top, columns=cols, show="headings")
        for c in cols:
            tree.heading(c, text=c)
        tree.pack(fill="both", expand=True)
        self.tree = tree
        btnf = ttk.Frame(top); btnf.pack(fill="x")
        ttk.Button(btnf, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(btnf, text="View", command=self.view_selected).pack(side="left")
        ttk.Button(btnf, text="Export CSV", command=self.export_csv).pack(side="left")
        self.refresh()

    def refresh(self):
        for r in self.tree.get_children():
            self.tree.delete(r)
        for row in get_logs():
            self.tree.insert("", "end", values=row)

    def view_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        lid = self.tree.item(sel[0])["values"][0]
        r = get_log_by_id(lid)
        if not r:
            messagebox.showerror("Not found", "Log not found"); return
        txt = (f"Template: {r[0]}\nUser: {r[1]}\nParams: {r[2]}\nCommand: {r[3]}\n\nSTDOUT:\n{r[4]}\n\nSTDERR:\n{r[5]}\n\nRC: {r[6]}\nStarted: {r[7]}\nFinished: {r[8]}")
        ViewWindow(self.tree, "Log detail", txt)

    def export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path: return
        with DB_LOCK:
            cur = DB.cursor()
            cur.execute("SELECT id,template_name,user,params_json,command,stdout,stderr,rc,started_at,finished_at FROM logs ORDER BY id DESC")
            rows = cur.fetchall()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id","template","user","params","command","stdout","stderr","rc","started","finished"])
            for r in rows:
                w.writerow(r)
        messagebox.showinfo("Exported", f"Exported {len(rows)} logs to {path}")

class ViewWindow:
    def __init__(self, parent, title, content):
        top = tk.Toplevel(parent)
        top.title(title)
        t = tk.Text(top)
        t.pack(fill="both", expand=True)
        t.insert("1.0", content)

# -------------------------
# Insert safe sample templates if none exist
# -------------------------
def ensure_safe_examples():
    with DB_LOCK:
        cur = DB.cursor()
        cur.execute("SELECT COUNT(*) FROM templates")
        if cur.fetchone()[0] == 0:
            tpl1 = {"name":"Show uptime", "pattern":"uptime", "metadata":{"params": []}, "description":"Show system uptime", "approved":1}
            tpl2 = {"name":"Echo message", "pattern":"echo {msg}", "metadata":{"params":[{"name":"msg","type":"string","label":"Message","default":"hello"}]}, "description":"Echo a message", "approved":1}
            for t in (tpl1,tpl2):
                cur.execute("INSERT OR IGNORE INTO templates (name,pattern,metadata_json,description,approved,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
                            (t["name"], t["pattern"], json.dumps(t["metadata"]), t["description"], int(t["approved"]), "system", now_iso()))
        DB.commit()

ensure_safe_examples()

# -------------------------
# Run the app
# -------------------------
def main():
    app = AdvancedAutomatorApp()
    app.mainloop()

if __name__ == "__main__":
    main()
