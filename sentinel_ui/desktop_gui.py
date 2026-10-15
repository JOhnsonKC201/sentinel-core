"""
Native Windows Desktop Security GUI for SentinelCore
Clean Windows Security / Enterprise endpoint UI styling without generic AI aesthetics.
"""

import argparse
import os
import queue
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Optional

from PIL import ImageTk

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_scanner.engine import SentinelScanner
from sentinel_vault.vault import QuarantineVault
from sentinel_guard.process_monitor import ProcessMonitor
from sentinel_guard.network_monitor import NetworkMonitor
from sentinel_guard.integrity_guard import IntegrityGuard
from sentinel_guard.protection import ProtectionService
from sentinel_scanner.persistence import PersistenceScanner
from sentinel_ui import tray as tray_commands
from sentinel_ui.audit_tabs import build_network_tab, build_persistence_tab, build_process_tab
from sentinel_ui.notifications import log_threat
from sentinel_ui.protection_tab import ProtectionTab
from sentinel_ui.single_instance import SingleInstance
from sentinel_ui.status import LEVEL_COLORS, PROTECTED, summarize
from sentinel_ui.tray import SentinelTray, draw_shield

POLL_MS = 250
REFRESH_EVERY_POLLS = 8  # about every two seconds
MAX_SCAN_FILES = 1500
HOME = os.path.expanduser("~")


class SentinelDesktopApp:
    def __init__(self, root: tk.Tk, start_hidden: bool = False,
                 instance: Optional[SingleInstance] = None, use_tray: bool = True):
        self.root = root
        self.instance = instance
        self.root.title("SentinelCore Security")
        self.root.geometry("1080x730")
        self.root.minsize(920, 620)
        self.root.configure(bg="#0E121A")
        self._window_icon = ImageTk.PhotoImage(draw_shield(PROTECTED))  # keep a reference: Tk does not
        self.root.iconphoto(True, self._window_icon)

        # Engines
        self.vault = QuarantineVault()
        self.scanner = SentinelScanner()
        self.proc_monitor = ProcessMonitor(scanner=self.scanner, vault=self.vault)
        self.net_monitor = NetworkMonitor()
        self.integrity_guard = IntegrityGuard()
        self.integrity_ok: Optional[bool] = None

        # Shield callbacks fire on watcher threads; Tk is only touched from
        # the poll loop, which drains these queues.
        self.ui_events: "queue.Queue[tuple]" = queue.Queue()
        self.tray_queue: "queue.Queue[str]" = queue.Queue()
        self.protection = ProtectionService(
            self.scanner, self.vault,
            on_file_threat=lambda path, verdict, vault_id: self.ui_events.put(
                ("threat", f"Malware quarantined: {verdict.reason}", os.path.basename(path), path)),
            on_process_threat=lambda pid, name, verdict, vault_id: self.ui_events.put(
                ("threat", f"Malicious process stopped: {name}", f"PID {pid}, {verdict.reason}", f"PID {pid}")),
        )
        self.tray = SentinelTray(self.tray_queue) if use_tray else None
        self._told_about_tray = False
        self._polls = 0

        self._apply_native_style()
        self._build_header()
        self._build_status_banner()
        self._build_tabs()
        self._build_footer()

        self.protection.start()
        if self.tray is not None:
            self.tray.start()
        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray if self.tray else self.quit)
        if start_hidden and self.tray is not None:
            self.root.withdraw()
        else:
            self.show_window()

        self.refresh_quarantine()
        self.refresh_metrics()
        threading.Thread(target=self._check_integrity, daemon=True).start()
        self.root.after(POLL_MS, self._poll)

    def _apply_native_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        bg_main = "#0E121A"
        bg_surface = "#161B26"
        text_light = "#F8FAFC"
        blue_accent = "#2563EB"

        style.configure(".", background=bg_main, foreground=text_light, font=("Segoe UI", 9))
        style.configure("TFrame", background=bg_main)
        
        # Tabs / Notebook
        style.configure("TNotebook", background=bg_main, borderwidth=0)
        style.configure("TNotebook.Tab", background="#181F2C", foreground="#94A3B8", padding=[14, 8], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", bg_surface), ("active", "#202838")],
                  foreground=[("selected", "#60A5FA"), ("active", text_light)])

        # Buttons
        style.configure("Primary.TButton", background=blue_accent, foreground="#FFFFFF", font=("Segoe UI", 9, "bold"), padding=[12, 5])
        style.map("Primary.TButton", background=[("active", "#1D4ED8"), ("pressed", "#1E40AF")])

        style.configure("Secondary.TButton", background="#1F2839", foreground=text_light, font=("Segoe UI", 9), padding=[10, 5])
        style.map("Secondary.TButton", background=[("active", "#2B374E")])

        style.configure("Danger.TButton", background="#E11D48", foreground="#FFFFFF", font=("Segoe UI", 9, "bold"), padding=[10, 5])
        style.map("Danger.TButton", background=[("active", "#BE123C")])

        # Treeview (Data grid)
        style.configure("Treeview", background="#121620", foreground=text_light, fieldbackground="#121620", rowheight=26, borderwidth=0)
        style.configure("Treeview.Heading", background="#1B2230", foreground="#94A3B8", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1E3A8A")])

        # Progressbar
        style.configure("Horizontal.TProgressbar", background=blue_accent, troughcolor="#1A202C", borderwidth=0)

    def _build_header(self):
        header = tk.Frame(self.root, bg="#141824", height=54, padx=22, pady=10)
        header.pack(fill="x", side="top")

        left = tk.Frame(header, bg="#141824")
        left.pack(side="left")

        title = tk.Label(left, text="SentinelCore Security", font=("Segoe UI", 12, "bold"), fg="#FFFFFF", bg="#141824")
        title.pack(side="left")

        sub = tk.Label(left, text=" • Personal Endpoint Protection Suite", font=("Segoe UI", 9), fg="#64748B", bg="#141824")
        sub.pack(side="left", padx=(4, 0))

        self.status_pill = tk.Label(header, text="● Checking...", font=("Segoe UI", 9, "bold"),
                                    fg="#94A3B8", bg="#1E293B", padx=10, pady=3)
        self.status_pill.pack(side="right")

    def _build_status_banner(self):
        banner = tk.Frame(self.root, bg="#141824", bd=1, relief="solid", padx=20, pady=12)
        banner.pack(fill="x", padx=20, pady=(12, 8))

        # Right action buttons are packed first: Tk hands out space in packing
        # order, so they always get their full width and the text wraps instead.
        actions_frame = tk.Frame(banner, bg="#141824")
        actions_frame.pack(side="right")

        self.btn_protection = ttk.Button(actions_frame, text="Turn protection off", style="Secondary.TButton", command=self._toggle_all_protection)
        self.btn_protection.pack(side="left", padx=4)
        ttk.Button(actions_frame, text="Verify Integrity", style="Secondary.TButton", command=self._verify_core_integrity).pack(side="left", padx=4)
        ttk.Button(actions_frame, text="Quick Scan", style="Primary.TButton", command=lambda: self._quick_scan("Downloads")).pack(side="left", padx=4)

        # Left Info
        info_frame = tk.Frame(banner, bg="#141824")
        info_frame.pack(side="left", fill="both", expand=True)

        self.lbl_headline = tk.Label(info_frame, text="Checking protection...", font=("Segoe UI", 11, "bold"), fg="#FFFFFF", bg="#141824")
        self.lbl_headline.pack(anchor="w")

        self.lbl_detail = tk.Label(info_frame, text="", font=("Segoe UI", 9), fg="#94A3B8", bg="#141824", justify="left")
        self.lbl_detail.pack(anchor="w", pady=(1, 5))

        meta_frame = tk.Frame(info_frame, bg="#141824")
        meta_frame.pack(anchor="w")

        self.lbl_cache = tk.Label(meta_frame, text="Cache: Loading...", font=("Segoe UI", 8), fg="#64748B", bg="#141824")
        self.lbl_cache.pack(side="left", padx=(0, 16))

        self.lbl_threats = tk.Label(meta_frame, text="Quarantined: 0 items", font=("Segoe UI", 8), fg="#F59E0B", bg="#141824")
        self.lbl_threats.pack(side="left", padx=(0, 16))

        rule_count = self.scanner.get_signatures_summary().get("tier3_signatures_count", 0)
        tk.Label(meta_frame, text=f"Signature rules: {rule_count}", font=("Segoe UI", 8), fg="#64748B", bg="#141824").pack(side="left", padx=(0, 16))

        self.lbl_activity = tk.Label(info_frame, text="", font=("Segoe UI", 8), fg="#64748B", bg="#141824")
        self.lbl_activity.pack(anchor="w", pady=(2, 0))

    def _build_tabs(self):
        container = tk.Frame(self.root, bg="#0E121A", padx=20, pady=2)
        container.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True)

        # Tab 0: Live protection
        self.tab_protection = tk.Frame(self.notebook, bg="#141824", padx=16, pady=14)
        self.notebook.add(self.tab_protection, text=" Protection ")
        self.protection_tab = ProtectionTab(self.tab_protection, on_toggle=self._toggle_shield)

        # Tab 1: Scanner
        self.tab_scan = tk.Frame(self.notebook, bg="#141824", padx=16, pady=14)
        self.notebook.add(self.tab_scan, text=" Threat Scan ")
        self._setup_scan_tab()

        # Tab 2: Quarantine
        self.tab_vault = tk.Frame(self.notebook, bg="#141824", padx=16, pady=14)
        self.notebook.add(self.tab_vault, text=" Quarantine Vault ")
        self._setup_quarantine_tab()

        # Tabs 3-5: on-demand audits
        post = lambda fn: self.ui_events.put(("call", fn))
        for title, build, source in (
                (" Process Guard ", build_process_tab, self.proc_monitor),
                (" Startup & AutoRun ", build_persistence_tab, PersistenceScanner(self.scanner)),
                (" Network & C2 ", build_network_tab, self.net_monitor)):
            frame = tk.Frame(self.notebook, bg="#141824", padx=16, pady=14)
            self.notebook.add(frame, text=title)
            build(frame, post, source)

        # Tab 6: Exclusions
        self.tab_exclusions = tk.Frame(self.notebook, bg="#141824", padx=16, pady=14)
        self.notebook.add(self.tab_exclusions, text=" Exclusions ")
        self._setup_exclusions_tab()

    # --- TAB 1: SCANNER ---
    def _setup_scan_tab(self):
        top = tk.Frame(self.tab_scan, bg="#141824")
        top.pack(fill="x", pady=(0, 10))

        tk.Label(top, text="Target Path:", font=("Segoe UI", 9, "bold"), fg="#FFFFFF", bg="#141824").pack(side="left", padx=(0, 8))

        self.path_var = tk.StringVar(value=os.path.join(HOME, "Downloads"))
        self.entry_path = tk.Entry(top, textvariable=self.path_var, font=("Segoe UI", 9), bg="#0E121A", fg="#F8FAFC", insertbackground="#3B82F6", bd=1, relief="solid")
        self.entry_path.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(top, text="Browse Folder", style="Secondary.TButton", command=self._browse_folder).pack(side="left", padx=2)
        ttk.Button(top, text="Browse File", style="Secondary.TButton", command=self._browse_file).pack(side="left", padx=2)
        self.btn_run_scan = ttk.Button(top, text="Scan Now", style="Primary.TButton", command=self._start_scan)
        self.btn_run_scan.pack(side="left", padx=2)

        # Presets
        presets = tk.Frame(self.tab_scan, bg="#141824")
        presets.pack(fill="x", pady=(0, 8))

        tk.Label(presets, text="Quick Presets:", font=("Segoe UI", 8), fg="#64748B", bg="#141824").pack(side="left", padx=(0, 8))
        ttk.Button(presets, text="Downloads", style="Secondary.TButton", command=lambda: self._set_path("Downloads")).pack(side="left", padx=2)
        ttk.Button(presets, text="Desktop", style="Secondary.TButton", command=lambda: self._set_path("Desktop")).pack(side="left", padx=2)
        ttk.Button(presets, text="Temp Folder", style="Secondary.TButton", command=lambda: self._set_path("Temp")).pack(side="left", padx=2)

        # Progress
        self.prog_bar = ttk.Progressbar(self.tab_scan, style="Horizontal.TProgressbar", mode="determinate")
        self.prog_bar.pack(fill="x", pady=(0, 4))

        self.lbl_scan_info = tk.Label(self.tab_scan, text="Ready to scan", font=("Segoe UI", 8), fg="#64748B", bg="#141824")
        self.lbl_scan_info.pack(anchor="w", pady=(0, 6))

        # Grid
        grid_frame = tk.Frame(self.tab_scan, bg="#141824")
        grid_frame.pack(fill="both", expand=True)

        cols = ("file", "verdict", "threat", "tier", "latency")
        self.tree_scan = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_scan.heading("file", text="File")
        self.tree_scan.heading("verdict", text="Verdict")
        self.tree_scan.heading("threat", text="Threat Description")
        self.tree_scan.heading("tier", text="Tier")
        self.tree_scan.heading("latency", text="Latency")

        self.tree_scan.column("file", width=420)
        self.tree_scan.column("verdict", width=95, anchor="center")
        self.tree_scan.column("threat", width=240)
        self.tree_scan.column("tier", width=60, anchor="center")
        self.tree_scan.column("latency", width=80, anchor="center")

        scroll = ttk.Scrollbar(grid_frame, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=scroll.set)
        self.tree_scan.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    # --- TAB 2: QUARANTINE ---
    def _setup_quarantine_tab(self):
        top = tk.Frame(self.tab_vault, bg="#141824")
        top.pack(fill="x", pady=(0, 8))

        tk.Label(top, text="Cryptographic Vault (AES-256-GCM Encrypted):", font=("Segoe UI", 9, "bold"), fg="#FFFFFF", bg="#141824").pack(side="left")

        ttk.Button(top, text="Refresh", style="Secondary.TButton", command=self.refresh_quarantine).pack(side="right", padx=2)
        ttk.Button(top, text="Purge All", style="Danger.TButton", command=self._purge_vault).pack(side="right", padx=2)
        ttk.Button(top, text="Delete File", style="Secondary.TButton", command=self._delete_threat).pack(side="right", padx=2)
        ttk.Button(top, text="Restore File", style="Primary.TButton", command=self._restore_threat).pack(side="right", padx=2)

        grid_frame = tk.Frame(self.tab_vault, bg="#141824")
        grid_frame.pack(fill="both", expand=True)

        cols = ("status", "vault_id", "threat", "path", "date")
        self.tree_vault = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_vault.heading("status", text="Status")
        self.tree_vault.heading("vault_id", text="Vault ID")
        self.tree_vault.heading("threat", text="Threat Description")
        self.tree_vault.heading("path", text="Original Location")
        self.tree_vault.heading("date", text="Date Isolated")

        self.tree_vault.column("status", width=85, anchor="center")
        self.tree_vault.column("vault_id", width=110)
        self.tree_vault.column("threat", width=220)
        self.tree_vault.column("path", width=380)
        self.tree_vault.column("date", width=130, anchor="center")

        scroll = ttk.Scrollbar(grid_frame, orient="vertical", command=self.tree_vault.yview)
        self.tree_vault.configure(yscrollcommand=scroll.set)
        self.tree_vault.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    # --- TAB 6: EXCLUSIONS ---
    def _setup_exclusions_tab(self):
        top = tk.Frame(self.tab_exclusions, bg="#141824")
        top.pack(fill="x", pady=(0, 8))

        tk.Label(top, text="Configured Whitelists & Path Exclusions:", font=("Segoe UI", 9, "bold"), fg="#FFFFFF", bg="#141824").pack(side="left")

        ttk.Button(top, text="Add Folder Exclusion", style="Primary.TButton", command=self._add_folder_exclusion).pack(side="right", padx=2)
        ttk.Button(top, text="Remove Selected", style="Danger.TButton", command=self._remove_selected_exclusion).pack(side="right", padx=2)
        ttk.Button(top, text="Refresh", style="Secondary.TButton", command=self._refresh_exclusions).pack(side="right", padx=2)

        grid_frame = tk.Frame(self.tab_exclusions, bg="#141824")
        grid_frame.pack(fill="both", expand=True)

        cols = ("type", "value")
        self.tree_exclusions = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_exclusions.heading("type", text="Exclusion Type")
        self.tree_exclusions.heading("value", text="Path or Hash Value")

        self.tree_exclusions.column("type", width=140, anchor="center")
        self.tree_exclusions.column("value", width=750)

        scroll = ttk.Scrollbar(grid_frame, orient="vertical", command=self.tree_exclusions.yview)
        self.tree_exclusions.configure(yscrollcommand=scroll.set)
        self.tree_exclusions.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self._refresh_exclusions()

    def _build_footer(self):
        foot = tk.Frame(self.root, bg="#141824", height=24, padx=20, pady=3)
        foot.pack(fill="x", side="bottom")

        tk.Label(
            foot,
            text="SentinelCore Endpoint Security",
            font=("Segoe UI", 8),
            fg="#64748B",
            bg="#141824"
        ).pack(side="left")

    # --- ACTIONS & HANDLERS ---
    def _verify_core_integrity(self):
        report = self.integrity_guard.verify_integrity()
        if report["is_intact"]:
            messagebox.showinfo(
                "Integrity Guard: Valid",
                f"SentinelCore Self-Defense Check: PASSED\n\n"
                f"• Verified Components: {report['verified_count']}/{report['total_monitored']} files\n"
                f"• Zero Tampering Detected\n"
                f"• Timestamp: {report['timestamp']}"
            )
        else:
            msg = f"WARNING: Potential Tamper Event Detected!\n\n"
            for t in report["tampered_files"]:
                msg += f"Modified: {t['file']}\n"
            for m in report["missing_files"]:
                msg += f"Missing: {m}\n"
            messagebox.showwarning("Integrity Guard: Tamper Detected", msg)

    def _refresh_exclusions(self):
        self.tree_exclusions.delete(*self.tree_exclusions.get_children())
        summary = self.scanner.exclusions.get_summary()
        for p in summary.get("paths", []):
            self.tree_exclusions.insert("", "end", values=("Folder / Path", p))
        for h in summary.get("hashes", []):
            self.tree_exclusions.insert("", "end", values=("SHA-256 Hash", h))

    def _add_folder_exclusion(self):
        d = filedialog.askdirectory(title="Select Folder to Whitelist / Exclude")
        if d:
            self.scanner.exclusions.add_path_exclusion(d)
            self._refresh_exclusions()
            messagebox.showinfo("Exclusion Added", f"Folder excluded from scanning:\n{d}")

    def _remove_selected_exclusion(self):
        sel = self.tree_exclusions.selection()
        if not sel:
            messagebox.showinfo("Select Exclusion", "Please select an exclusion from the list.")
            return
        item = self.tree_exclusions.item(sel[0])
        val = item["values"][1]
        typ = item["values"][0]
        if "Path" in typ:
            self.scanner.exclusions.remove_path_exclusion(val)
        else:
            self.scanner.exclusions.remove_hash_exclusion(val)
        self._refresh_exclusions()

    def _browse_folder(self):
        d = filedialog.askdirectory(title="Select Folder to Scan")
        if d:
            self.path_var.set(d)

    def _browse_file(self):
        f = filedialog.askopenfilename(title="Select File to Scan")
        if f:
            self.path_var.set(f)

    def _set_path(self, preset: str):
        if preset == "Temp":
            p = os.environ.get("TEMP", os.path.join(HOME, "AppData", "Local", "Temp"))
        else:
            p = os.path.join(HOME, preset)
        self.path_var.set(p)

    def _quick_scan(self, preset: str):
        self._set_path(preset)
        self.notebook.select(self.tab_scan)
        self._start_scan()

    def _start_scan(self):
        path = self.path_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Scan Error", f"Path does not exist:\n{path}")
            return

        self.btn_run_scan.configure(state="disabled")
        self.prog_bar["value"] = 0
        self.tree_scan.delete(*self.tree_scan.get_children())
        self.lbl_scan_info.config(text=f"Scanning: {path}...")

        threading.Thread(target=self._scan_worker, args=(path,), daemon=True).start()

    def _scan_worker(self, path: str):
        # Runs on a worker thread: it only posts to ui_events, never touches Tk.
        t0 = time.time()
        files: List[str] = []
        if os.path.isfile(path):
            files = [path]
        else:
            for root, _, fs in os.walk(path):
                files.extend(os.path.join(root, f) for f in fs)
                if len(files) >= MAX_SCAN_FILES:
                    files = files[:MAX_SCAN_FILES]
                    break

        total = len(files)
        threats = 0
        errors = 0
        progress_step = max(total // 100, 1)

        for scanned, fp in enumerate(files, start=1):
            try:
                verdict = self.scanner.scan_file(fp)
            except Exception:
                errors += 1
                continue
            if verdict.is_malicious():
                threats += 1
                self.vault.isolate_file(fp, reason=verdict.reason)
                self.ui_events.put(("scan_row", fp, "MALICIOUS", verdict.reason, verdict.tier, verdict.scan_time_ms))
            elif scanned <= 8 or scanned % 40 == 0:
                self.ui_events.put(("scan_row", fp, "CLEAN", "Clean", verdict.tier, verdict.scan_time_ms))
            if scanned % progress_step == 0 or scanned == total:
                pct = int(scanned / max(total, 1) * 100)
                self.ui_events.put(("scan_progress", pct, f"Inspected {scanned}/{total} files..."))

        elapsed = round(time.time() - t0, 2)
        summary = f"Scan complete: {total - errors} files inspected in {elapsed}s • {threats} threats found."
        if errors:
            summary += f" • {errors} could not be read"
        if total >= MAX_SCAN_FILES:
            summary += f" • stopped at the first {MAX_SCAN_FILES} files"
        self.ui_events.put(("scan_done", summary))

    def _add_scan_row(self, fp: str, verdict: str, threat: str, tier: int, latency: float):
        row = self.tree_scan.insert("", "end", values=(fp, verdict, threat, f"Tier {tier}", f"{latency:.3f} ms"))
        if verdict == "MALICIOUS":
            self.tree_scan.tag_configure("threat", foreground="#F43F5E")
            self.tree_scan.item(row, tags=("threat",))

    def _update_progress(self, pct: int, text: str):
        self.prog_bar["value"] = pct
        self.lbl_scan_info.config(text=text)

    def _scan_done(self, summary: str):
        self.prog_bar["value"] = 100
        self.lbl_scan_info.config(text=summary)
        self.btn_run_scan.configure(state="normal")
        self.refresh_quarantine()
        self.refresh_metrics()

    def refresh_quarantine(self):
        self.tree_vault.delete(*self.tree_vault.get_children())
        items = self.vault.list_quarantined()
        for item in items:
            status = "Restored" if item.get("is_restored") else "Isolated"
            vid = item["vault_id"][:10] + "..."
            self.tree_vault.insert(
                "",
                "end",
                iid=item["vault_id"],
                values=(status, vid, item["reason"], item["original_path"], item["quarantine_time"])
            )

    def refresh_metrics(self):
        items = self.vault.list_quarantined()
        active = sum(1 for i in items if not i.get("is_restored"))
        self.lbl_cache.config(text=f"Reputation cache: {len(self.scanner.cache):,} files")
        self.lbl_threats.config(text=f"Quarantined: {active} item(s)")

    # --- LIVE PROTECTION, TRAY & EVENT LOOP ---
    def _poll(self):
        try:
            self._drain_ui_events()
            self._drain_tray_commands()
            if self.instance is not None and self.instance.show_requested():
                self.show_window()
            self._polls += 1
            if self._polls % REFRESH_EVERY_POLLS == 1:
                self.refresh_protection()
                self.refresh_metrics()
        finally:
            self.root.after(POLL_MS, self._poll)

    def _drain_ui_events(self):
        while True:
            try:
                event = self.ui_events.get_nowait()
            except queue.Empty:
                return
            kind, args = event[0], event[1:]
            if kind == "threat":
                self._on_threat(*args)
            elif kind == "scan_row":
                self._add_scan_row(*args)
            elif kind == "scan_progress":
                self._update_progress(*args)
            elif kind == "scan_done":
                self._scan_done(*args)
            elif kind == "call":
                args[0]()

    def _drain_tray_commands(self):
        while True:
            try:
                command = self.tray_queue.get_nowait()
            except queue.Empty:
                return
            if command == tray_commands.OPEN:
                self.show_window()
            elif command == tray_commands.TOGGLE_PROTECTION:
                self._toggle_all_protection()
            elif command == tray_commands.SCAN_DOWNLOADS:
                self.show_window()
                self._quick_scan("Downloads")
            elif command == tray_commands.QUIT:
                self.quit()

    def _on_threat(self, title: str, message: str, where: str):
        log_threat(title, message, where)
        if self.tray is not None:
            self.tray.notify(title, message)
        self.refresh_quarantine()
        self.refresh_metrics()

    def _check_integrity(self):
        ok = self.integrity_guard.verify_integrity().get("is_intact")
        self.integrity_ok = bool(ok)

    def refresh_protection(self):
        states = self.protection.states()
        summary = summarize(states, self.integrity_ok)
        fg, bg = LEVEL_COLORS[summary.level]
        self.status_pill.config(text=f"● {summary.pill}", fg=fg, bg=bg)
        self.lbl_headline.config(text=summary.headline)
        self.lbl_detail.config(text=summary.detail)
        any_on = any(s.running for s in states)
        self.btn_protection.config(text="Turn protection off" if any_on else "Turn protection on")
        counters = self.protection.counters()
        self.lbl_activity.config(
            text=f"Since launch: {counters['files_inspected']:,} files and "
                 f"{counters['processes_inspected']:,} processes checked")
        self.protection_tab.update_shields(states)
        self.protection_tab.update_events(self.protection.recent_events())
        if self.tray is not None:
            self.tray.update(summary.level, f"SentinelCore: {summary.pill}", any_on)

    def _toggle_shield(self, name: str, turn_on: bool):
        if turn_on:
            self.protection.start(name)
        else:
            self.protection.stop(name)
        self.refresh_protection()

    def _toggle_all_protection(self):
        if any(s.running for s in self.protection.states()):
            if not messagebox.askyesno(
                    "Turn off protection",
                    "Stop scanning new files and processes until you turn protection back on?"):
                return
            self.protection.stop()
        else:
            self.protection.start()
        self.refresh_protection()

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(400, lambda: self.root.attributes("-topmost", False))
        self.root.focus_force()

    def hide_to_tray(self):
        self.root.withdraw()
        if not self._told_about_tray and self.tray is not None:
            self._told_about_tray = True
            self.tray.notify("SentinelCore is still protecting you",
                             "It keeps running in the system tray. Right-click the shield icon to quit.")

    def quit(self):
        self.protection.stop()
        if self.tray is not None:
            self.tray.stop()
        if self.instance is not None:
            self.instance.release()
        self.root.destroy()

    def _restore_threat(self):
        sel = self.tree_vault.selection()
        if not sel:
            messagebox.showinfo("Select Threat", "Please select a threat from the quarantine table.")
            return
        vid = sel[0]
        try:
            self.vault.restore_file(vid)
            messagebox.showinfo("Restored", f"Threat {vid} restored successfully.")
            self.refresh_quarantine()
            self.refresh_metrics()
        except Exception as e:
            messagebox.showerror("Restoration Error", str(e))

    def _delete_threat(self):
        sel = self.tree_vault.selection()
        if not sel:
            messagebox.showinfo("Select Threat", "Please select a threat to delete.")
            return
        vid = sel[0]
        if messagebox.askyesno("Confirm Deletion", f"Permanently shred and delete threat {vid}?"):
            try:
                self.vault.delete_quarantined(vid)
                self.refresh_quarantine()
                self.refresh_metrics()
            except Exception as e:
                messagebox.showerror("Deletion Error", str(e))

    def _purge_vault(self):
        if messagebox.askyesno("Confirm Purge", "Permanently shred all files in the quarantine vault?"):
            purged = self.vault.purge_all()
            messagebox.showinfo("Purge Complete", f"Purged {purged} threat files from vault.")
            self.refresh_quarantine()
            self.refresh_metrics()

def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(description="SentinelCore desktop app")
    parser.add_argument("--minimized", action="store_true",
                        help="Start in the system tray without opening the window (used at login)")
    args = parser.parse_args(argv)

    instance = SingleInstance()
    if not instance.is_primary:
        instance.ask_primary_to_show()
        instance.release()
        return

    root = tk.Tk()
    SentinelDesktopApp(root, start_hidden=args.minimized, instance=instance)
    root.mainloop()

if __name__ == "__main__":
    main()
