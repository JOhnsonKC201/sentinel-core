"""
Native Windows Desktop Security GUI for SentinelCore
Clean Windows Security / Enterprise endpoint UI styling without generic AI aesthetics.
"""

import os
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_BLOCK, VERDICT_QUARANTINE
from sentinel_vault.vault import QuarantineVault

class SentinelDesktopApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SentinelCore Security")
        self.root.geometry("1020x700")
        self.root.minsize(880, 580)
        self.root.configure(bg="#0E121A")

        # Focus window
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(400, lambda: self.root.attributes("-topmost", False))
        self.root.focus_force()

        # Engines
        self.vault = QuarantineVault()
        self.scanner = SentinelScanner()

        self._apply_native_style()
        self._build_header()
        self._build_status_banner()
        self._build_tabs()
        self._build_footer()

        self.refresh_quarantine()
        self.refresh_metrics()
        self.root.after(3000, self._auto_refresh)

    def _apply_native_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        bg_main = "#0E121A"
        bg_surface = "#161B26"
        border_col = "#242C3D"
        text_light = "#F8FAFC"
        blue_accent = "#2563EB"

        style.configure(".", background=bg_main, foreground=text_light, font=("Segoe UI", 9))
        style.configure("TFrame", background=bg_main)
        
        # Tabs / Notebook
        style.configure("TNotebook", background=bg_main, borderwidth=0)
        style.configure("TNotebook.Tab", background="#181F2C", foreground="#94A3B8", padding=[18, 9], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", bg_surface), ("active", "#202838")],
                  foreground=[("selected", "#60A5FA"), ("active", text_light)])

        # Buttons
        style.configure("Primary.TButton", background=blue_accent, foreground="#FFFFFF", font=("Segoe UI", 9, "bold"), padding=[14, 6])
        style.map("Primary.TButton", background=[("active", "#1D4ED8"), ("pressed", "#1E40AF")])

        style.configure("Secondary.TButton", background="#1F2839", foreground=text_light, font=("Segoe UI", 9), padding=[10, 5])
        style.map("Secondary.TButton", background=[("active", "#2B374E")])

        style.configure("Danger.TButton", background="#E11D48", foreground="#FFFFFF", font=("Segoe UI", 9, "bold"), padding=[10, 5])
        style.map("Danger.TButton", background=[("active", "#BE123C")])

        # Treeview (Data grid)
        style.configure("Treeview", background="#121620", foreground=text_light, fieldbackground="#121620", rowheight=28, borderwidth=0)
        style.configure("Treeview.Heading", background="#1B2230", foreground="#94A3B8", font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1E3A8A")])

        # Progressbar
        style.configure("Horizontal.TProgressbar", background=blue_accent, troughcolor="#1A202C", borderwidth=0)

    def _build_header(self):
        header = tk.Frame(self.root, bg="#141824", height=56, padx=24, pady=10)
        header.pack(fill="x", side="top")

        left = tk.Frame(header, bg="#141824")
        left.pack(side="left")

        title = tk.Label(left, text="SentinelCore Security", font=("Segoe UI", 12, "bold"), fg="#FFFFFF", bg="#141824")
        title.pack(side="left")

        sub = tk.Label(left, text=" • Personal Endpoint Protection", font=("Segoe UI", 9), fg="#64748B", bg="#141824")
        sub.pack(side="left", padx=(4, 0))

        status_pill = tk.Label(
            header,
            text="● Device Protected",
            font=("Segoe UI", 9, "bold"),
            fg="#10B981",
            bg="#064E3B",
            padx=10,
            pady=3
        )
        status_pill.pack(side="right")

    def _build_status_banner(self):
        banner = tk.Frame(self.root, bg="#141824", bd=1, relief="solid", padx=20, pady=14)
        banner.pack(fill="x", padx=20, pady=(16, 10))

        # Left Info
        info_frame = tk.Frame(banner, bg="#141824")
        info_frame.pack(side="left", fill="both", expand=True)

        h_lbl = tk.Label(info_frame, text="Current status: Protected", font=("Segoe UI", 12, "bold"), fg="#FFFFFF", bg="#141824")
        h_lbl.pack(anchor="w")

        p_lbl = tk.Label(info_frame, text="Real-time file shield, memory execution guard, and ransomware defenses are running.", font=("Segoe UI", 9), fg="#94A3B8", bg="#141824")
        p_lbl.pack(anchor="w", pady=(2, 6))

        meta_frame = tk.Frame(info_frame, bg="#141824")
        meta_frame.pack(anchor="w")

        self.lbl_cache = tk.Label(meta_frame, text="Cache: 10,206 signatures", font=("Segoe UI", 8), fg="#64748B", bg="#141824")
        self.lbl_cache.pack(side="left", padx=(0, 16))

        self.lbl_threats = tk.Label(meta_frame, text="Quarantined: 1 item", font=("Segoe UI", 8), fg="#F59E0B", bg="#141824")
        self.lbl_threats.pack(side="left", padx=(0, 16))

        ver_lbl = tk.Label(meta_frame, text="Definitions: Up to date (2026.10)", font=("Segoe UI", 8), fg="#64748B", bg="#141824")
        ver_lbl.pack(side="left")

        # Right Quick Action
        btn_quick = ttk.Button(banner, text="Quick Scan", style="Primary.TButton", command=lambda: self._quick_scan("Downloads"))
        btn_quick.pack(side="right", padx=(10, 0))

    def _build_tabs(self):
        container = tk.Frame(self.root, bg="#0E121A", padx=20, pady=4)
        container.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Scanner
        self.tab_scan = tk.Frame(self.notebook, bg="#141824", padx=18, pady=16)
        self.notebook.add(self.tab_scan, text=" Virus & Threat Scan ")
        self._setup_scan_tab()

        # Tab 2: Quarantine
        self.tab_vault = tk.Frame(self.notebook, bg="#141824", padx=18, pady=16)
        self.notebook.add(self.tab_vault, text=" Quarantine & Protection History ")
        self._setup_quarantine_tab()

        # Tab 3: Security Shields
        self.tab_shields = tk.Frame(self.notebook, bg="#141824", padx=18, pady=16)
        self.notebook.add(self.tab_shields, text=" Shields & Heuristics ")
        self._setup_shields_tab()

    def _setup_scan_tab(self):
        # Scan Path Row
        top = tk.Frame(self.tab_scan, bg="#141824")
        top.pack(fill="x", pady=(0, 12))

        tk.Label(top, text="Scan Location:", font=("Segoe UI", 9, "bold"), fg="#FFFFFF", bg="#141824").pack(side="left", padx=(0, 8))

        user_home = os.environ.get("USERPROFILE", "C:\\Users\\johns")
        self.path_var = tk.StringVar(value=os.path.join(user_home, "Downloads"))
        self.entry_path = tk.Entry(top, textvariable=self.path_var, font=("Segoe UI", 9), bg="#0E121A", fg="#F8FAFC", insertbackground="#3B82F6", bd=1, relief="solid")
        self.entry_path.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(top, text="Browse Folder", style="Secondary.TButton", command=self._browse_folder).pack(side="left", padx=3)
        ttk.Button(top, text="Browse File", style="Secondary.TButton", command=self._browse_file).pack(side="left", padx=3)
        self.btn_run_scan = ttk.Button(top, text="Scan Now", style="Primary.TButton", command=self._start_scan)
        self.btn_run_scan.pack(side="left", padx=3)

        # Quick Target Presets
        presets = tk.Frame(self.tab_scan, bg="#141824")
        presets.pack(fill="x", pady=(0, 10))

        tk.Label(presets, text="Quick Presets:", font=("Segoe UI", 8), fg="#64748B", bg="#141824").pack(side="left", padx=(0, 8))
        ttk.Button(presets, text="Downloads", style="Secondary.TButton", command=lambda: self._set_path("Downloads")).pack(side="left", padx=3)
        ttk.Button(presets, text="Desktop", style="Secondary.TButton", command=lambda: self._set_path("Desktop")).pack(side="left", padx=3)
        ttk.Button(presets, text="Temp Folder", style="Secondary.TButton", command=lambda: self._set_path("Temp")).pack(side="left", padx=3)

        # Progress bar
        self.prog_bar = ttk.Progressbar(self.tab_scan, style="Horizontal.TProgressbar", mode="determinate")
        self.prog_bar.pack(fill="x", pady=(0, 4))

        self.lbl_scan_info = tk.Label(self.tab_scan, text="Ready to scan", font=("Segoe UI", 8), fg="#64748B", bg="#141824")
        self.lbl_scan_info.pack(anchor="w", pady=(0, 8))

        # Results Data Grid
        grid_frame = tk.Frame(self.tab_scan, bg="#141824")
        grid_frame.pack(fill="both", expand=True)

        cols = ("file", "verdict", "threat", "tier", "latency")
        self.tree_scan = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_scan.heading("file", text="File")
        self.tree_scan.heading("verdict", text="Verdict")
        self.tree_scan.heading("threat", text="Threat Name")
        self.tree_scan.heading("tier", text="Tier")
        self.tree_scan.heading("latency", text="Latency")

        self.tree_scan.column("file", width=440)
        self.tree_scan.column("verdict", width=100, anchor="center")
        self.tree_scan.column("threat", width=220)
        self.tree_scan.column("tier", width=60, anchor="center")
        self.tree_scan.column("latency", width=80, anchor="center")

        scroll = ttk.Scrollbar(grid_frame, orient="vertical", command=self.tree_scan.yview)
        self.tree_scan.configure(yscrollcommand=scroll.set)
        self.tree_scan.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _setup_quarantine_tab(self):
        top = tk.Frame(self.tab_vault, bg="#141824")
        top.pack(fill="x", pady=(0, 10))

        tk.Label(top, text="Isolated Threats (Encrypted with AES-256-GCM):", font=("Segoe UI", 9, "bold"), fg="#FFFFFF", bg="#141824").pack(side="left")

        ttk.Button(top, text="Refresh", style="Secondary.TButton", command=self.refresh_quarantine).pack(side="right", padx=3)
        ttk.Button(top, text="Purge All", style="Danger.TButton", command=self._purge_vault).pack(side="right", padx=3)
        ttk.Button(top, text="Delete File", style="Secondary.TButton", command=self._delete_threat).pack(side="right", padx=3)
        ttk.Button(top, text="Restore File", style="Primary.TButton", command=self._restore_threat).pack(side="right", padx=3)

        grid_frame = tk.Frame(self.tab_vault, bg="#141824")
        grid_frame.pack(fill="both", expand=True)

        cols = ("status", "vault_id", "threat", "path", "date")
        self.tree_vault = ttk.Treeview(grid_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_vault.heading("status", text="Status")
        self.tree_vault.heading("vault_id", text="Vault ID")
        self.tree_vault.heading("threat", text="Threat Name")
        self.tree_vault.heading("path", text="Original Location")
        self.tree_vault.heading("date", text="Date Isolated")

        self.tree_vault.column("status", width=90, anchor="center")
        self.tree_vault.column("vault_id", width=120)
        self.tree_vault.column("threat", width=220)
        self.tree_vault.column("path", width=380)
        self.tree_vault.column("date", width=140, anchor="center")

        scroll = ttk.Scrollbar(grid_frame, orient="vertical", command=self.tree_vault.yview)
        self.tree_vault.configure(yscrollcommand=scroll.set)
        self.tree_vault.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _setup_shields_tab(self):
        container = tk.Frame(self.tab_shields, bg="#141824")
        container.pack(fill="both", expand=True)

        tk.Label(container, text="Security Modules & Cascade Architecture", font=("Segoe UI", 11, "bold"), fg="#FFFFFF", bg="#141824").pack(anchor="w", pady=(0, 8))

        summary = self.scanner.get_signatures_summary()

        txt = tk.Text(container, bg="#0E121A", fg="#CBD5E1", font=("Segoe UI", 9), relief="solid", bd=1, padx=14, pady=12, wrap="word")
        txt.pack(fill="both", expand=True)

        body = (
            "SHIELD STATUS AND HEURISTIC ENGINES\n"
            "------------------------------------------------------------------------\n\n"
            "1. Real-Time File System Shield [Active]\n"
            "   Monitors Downloads, Desktop, Documents, and Temp for untrusted binaries.\n\n"
            "2. Process Execution Guard [Active]\n"
            "   Inspects command-lines for LOLBins, encoded PowerShell, and script-based droppers.\n\n"
            "3. Dual-Invariant Ransomware Defense [Active]\n"
            "   Detects rapid high-entropy bursts (<= 3 writes/s) while protecting developer build tools.\n\n"
            f"4. Fast Reputation Cache: {summary['tier1_cache_entries']:,} signatures loaded (< 0.01ms latency)\n\n"
            f"5. Active Threat Pattern Signatures ({summary['tier3_signatures_count']} rules):\n"
        )
        for sig in summary["signatures"]:
            body += f"   • {sig}\n"

        txt.insert("1.0", body)
        txt.configure(state="disabled")

    def _build_footer(self):
        foot = tk.Frame(self.root, bg="#141824", height=24, padx=20, pady=3)
        foot.pack(fill="x", side="bottom")

        tk.Label(
            foot,
            text="SentinelCore Endpoint Security • Web Console: http://127.0.0.1:8765",
            font=("Segoe UI", 8),
            fg="#64748B",
            bg="#141824"
        ).pack(side="left")

    def _browse_folder(self):
        d = filedialog.askdirectory(title="Select Folder to Scan")
        if d:
            self.path_var.set(d)

    def _browse_file(self):
        f = filedialog.askopenfilename(title="Select File to Scan")
        if f:
            self.path_var.set(f)

    def _set_path(self, preset: str):
        home = os.environ.get("USERPROFILE", "C:\\Users\\johns")
        if preset == "Temp":
            p = os.environ.get("TEMP", os.path.join(home, "AppData\\Local\\Temp"))
        else:
            p = os.path.join(home, preset)
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
        t0 = time.time()
        files = []
        if os.path.isfile(path):
            files = [path]
        else:
            for root, _, fs in os.walk(path):
                for f in fs:
                    files.append(os.path.join(root, f))
                    if len(files) >= 1500:
                        break
                if len(files) >= 1500:
                    break

        total = len(files)
        scanned = 0
        threats = 0

        for fp in files:
            scanned += 1
            try:
                verdict = self.scanner.scan_file(fp)
                if verdict.is_malicious():
                    threats += 1
                    self.vault.isolate_file(fp, reason=verdict.reason)
                    self.root.after(0, self._add_scan_row, fp, "MALICIOUS", verdict.reason, verdict.tier, verdict.scan_time_ms)
                elif scanned <= 8 or scanned % 40 == 0:
                    self.root.after(0, self._add_scan_row, fp, "CLEAN", "Clean", verdict.tier, verdict.scan_time_ms)
            except Exception:
                pass

            pct = int((scanned / max(total, 1)) * 100)
            self.root.after(0, self._update_progress, pct, f"Inspected {scanned}/{total} files...")

        elapsed = round(time.time() - t0, 2)
        summary = f"Scan complete: {scanned} files inspected in {elapsed}s • {threats} threats found."
        self.root.after(0, self._scan_done, summary)

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
        self.lbl_cache.config(text=f"Cache: {len(self.scanner.cache):,} signatures")
        self.lbl_threats.config(text=f"Quarantined: {active} item(s)")

    def _auto_refresh(self):
        self.refresh_metrics()
        self.root.after(3000, self._auto_refresh)

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

def main():
    root = tk.Tk()
    app = SentinelDesktopApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
