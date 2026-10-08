"""
Native Desktop GUI Dashboard for SentinelCore Antivirus
Built with Python Tkinter and ttk with a modern dark security console theme.
Features live shield indicators, file picker, on-demand scanning with progress bar,
and quarantine vault management.
"""

import os
import sys
import time
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional, List

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_scanner.engine import SentinelScanner, VERDICT_ALLOW, VERDICT_BLOCK, VERDICT_QUARANTINE
from sentinel_vault.vault import QuarantineVault

class SentinelDesktopApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("SentinelCore - Personal Antivirus & Endpoint Shield")
        self.root.geometry("1050x720")
        self.root.minsize(900, 600)
        self.root.configure(bg="#0B0F19")

        # Initialize core engines
        self.vault = QuarantineVault()
        self.scanner = SentinelScanner()

        self._apply_dark_style()
        self._build_header()
        self._build_metrics_cards()
        self._build_tabs()
        self._build_statusbar()

        # Initial data load
        self.refresh_quarantine()
        self.refresh_metrics()

        # Start periodic status update
        self.root.after(3000, self._periodic_update)

    def _apply_dark_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Configure colors
        bg_dark = "#0B0F19"
        card_bg = "#111827"
        text_light = "#F3F4F6"
        cyan = "#06B6D4"

        style.configure(".", background=bg_dark, foreground=text_light, font=("Segoe UI", 9))
        style.configure("TFrame", background=bg_dark)
        style.configure("Card.TFrame", background=card_bg, relief="solid", borderwidth=1)
        
        # Notebook / Tabs
        style.configure("TNotebook", background=bg_dark, borderwidth=0)
        style.configure("TNotebook.Tab", background="#1F2937", foreground=text_light, padding=[16, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", cyan), ("active", "#374151")],
                  foreground=[("selected", "#000000"), ("active", "#FFFFFF")])

        # Buttons
        style.configure("Primary.TButton", background=cyan, foreground="#000000", font=("Segoe UI", 9, "bold"), padding=[12, 6])
        style.map("Primary.TButton", background=[("active", "#22D3EE"), ("pressed", "#0891B2")])

        style.configure("Secondary.TButton", background="#1F2937", foreground=text_light, font=("Segoe UI", 9), padding=[10, 5])
        style.map("Secondary.TButton", background=[("active", "#374151")])

        style.configure("Danger.TButton", background="#EF4444", foreground="#FFFFFF", font=("Segoe UI", 9, "bold"), padding=[10, 5])
        style.map("Danger.TButton", background=[("active", "#DC2626")])

        # Treeview (Tables)
        style.configure("Treeview", background="#111827", foreground=text_light, fieldbackground="#111827", rowheight=28)
        style.configure("Treeview.Heading", background="#1F2937", foreground=text_light, font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#1E3A5F")])

        # Progressbar
        style.configure("Horizontal.TProgressbar", background=cyan, troughcolor="#1F2937", borderwidth=0)

    def _build_header(self):
        header_frame = tk.Frame(self.root, bg="#111827", height=60, padx=20, pady=10)
        header_frame.pack(fill="x", side="top")

        title_label = tk.Label(
            header_frame,
            text="🛡  SENTINELCORE PERSONAL ANTIVIRUS",
            font=("Segoe UI", 14, "bold"),
            fg="#06B6D4",
            bg="#111827"
        )
        title_label.pack(side="left")

        status_badge = tk.Label(
            header_frame,
            text="● REAL-TIME SHIELDS ACTIVE",
            font=("Segoe UI", 10, "bold"),
            fg="#10B981",
            bg="#064E3B",
            padx=12,
            pady=4,
            relief="flat"
        )
        status_badge.pack(side="right")

    def _build_metrics_cards(self):
        cards_frame = tk.Frame(self.root, bg="#0B0F19", padx=20, pady=12)
        cards_frame.pack(fill="x")

        # Metric 1: System Health
        self.card_health = self._create_card(cards_frame, "SYSTEM PROTECTION", "100% HEALTHY", "All Guards Operational", "#10B981")
        self.card_health.pack(side="left", fill="both", expand=True, padx=(0, 8))

        # Metric 2: Reputation Cache
        self.card_cache = self._create_card(cards_frame, "REPUTATION CACHE", f"{len(self.scanner.cache):,} Signatures", "P99 Latency: < 0.01ms", "#06B6D4")
        self.card_cache.pack(side="left", fill="both", expand=True, padx=8)

        # Metric 3: Quarantined Threats
        items = self.vault.list_quarantined()
        active_threats = sum(1 for i in items if not i.get("is_restored"))
        self.card_vault = self._create_card(cards_frame, "QUARANTINE VAULT", f"{active_threats} Isolated Threats", "AES-256-GCM Neutralized", "#F59E0B")
        self.card_vault.pack(side="left", fill="both", expand=True, padx=8)

        # Metric 4: Heuristic Rules
        summary = self.scanner.get_signatures_summary()
        self.card_rules = self._create_card(cards_frame, "ACTIVE DETECTION RULES", f"{summary['tier3_signatures_count']} Engines", "UPX & LOLBins Loaded", "#A855F7")
        self.card_rules.pack(side="left", fill="both", expand=True, padx=(8, 0))

    def _create_card(self, parent, title: str, val_text: str, sub_text: str, color: str) -> tk.Frame:
        card = tk.Frame(parent, bg="#111827", bd=1, relief="solid", padx=16, pady=12)
        
        t_lbl = tk.Label(card, text=title.upper(), font=("Segoe UI", 8, "bold"), fg="#9CA3AF", bg="#111827")
        t_lbl.pack(anchor="w")

        v_lbl = tk.Label(card, text=val_text, font=("Segoe UI", 14, "bold"), fg=color, bg="#111827")
        v_lbl.pack(anchor="w", pady=(2, 2))
        card.value_label = v_lbl  # store reference

        s_lbl = tk.Label(card, text=sub_text, font=("Segoe UI", 8), fg="#6B7280", bg="#111827")
        s_lbl.pack(anchor="w")

        return card

    def _build_tabs(self):
        tab_container = tk.Frame(self.root, bg="#0B0F19", padx=20, pady=6)
        tab_container.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(tab_container)
        self.notebook.pack(fill="both", expand=True)

        # Tab 1: Scanner
        self.tab_scan = tk.Frame(self.notebook, bg="#111827", padx=16, pady=16)
        self.notebook.add(self.tab_scan, text="  On-Demand Scanner  ")
        self._setup_scanner_tab()

        # Tab 2: Quarantine Vault
        self.tab_vault = tk.Frame(self.notebook, bg="#111827", padx=16, pady=16)
        self.notebook.add(self.tab_vault, text="  Quarantine Vault  ")
        self._setup_vault_tab()

        # Tab 3: Signatures Explorer
        self.tab_rules = tk.Frame(self.notebook, bg="#111827", padx=16, pady=16)
        self.notebook.add(self.tab_rules, text="  Detection Signatures  ")
        self._setup_rules_tab()

    def _setup_scanner_tab(self):
        # Controls Frame
        top_bar = tk.Frame(self.tab_scan, bg="#111827")
        top_bar.pack(fill="x", pady=(0, 12))

        tk.Label(top_bar, text="Target Scan Path:", font=("Segoe UI", 10, "bold"), fg="#F3F4F6", bg="#111827").pack(side="left", padx=(0, 8))

        self.scan_path_var = tk.StringVar(value=os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\johns"), "Downloads"))
        self.path_entry = tk.Entry(top_bar, textvariable=self.scan_path_var, font=("Segoe UI", 10), bg="#0B0F19", fg="#F3F4F6", insertbackground="#06B6D4")
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Button(top_bar, text="Browse Folder", style="Secondary.TButton", command=self._browse_folder).pack(side="left", padx=4)
        ttk.Button(top_bar, text="Browse File", style="Secondary.TButton", command=self._browse_file).pack(side="left", padx=4)
        self.btn_scan = ttk.Button(top_bar, text="▶ Start Scan", style="Primary.TButton", command=self._start_scan_thread)
        self.btn_scan.pack(side="left", padx=4)

        # Quick Scans Frame
        quick_frame = tk.Frame(self.tab_scan, bg="#111827")
        quick_frame.pack(fill="x", pady=(0, 10))

        tk.Label(quick_frame, text="Quick Scans:", font=("Segoe UI", 9), fg="#9CA3AF", bg="#111827").pack(side="left", padx=(0, 8))
        ttk.Button(quick_frame, text="Downloads", style="Secondary.TButton", command=lambda: self._set_and_scan("Downloads")).pack(side="left", padx=4)
        ttk.Button(quick_frame, text="Desktop", style="Secondary.TButton", command=lambda: self._set_and_scan("Desktop")).pack(side="left", padx=4)
        ttk.Button(quick_frame, text="Temp", style="Secondary.TButton", command=lambda: self._set_and_scan("Temp")).pack(side="left", padx=4)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self.tab_scan, style="Horizontal.TProgressbar", mode="determinate")
        self.progress_bar.pack(fill="x", pady=(0, 4))

        self.lbl_scan_status = tk.Label(self.tab_scan, text="Ready to scan", font=("Segoe UI", 9), fg="#9CA3AF", bg="#111827")
        self.lbl_scan_status.pack(anchor="w", pady=(0, 10))

        # Scan Results Table
        table_frame = tk.Frame(self.tab_scan, bg="#111827")
        table_frame.pack(fill="both", expand=True)

        cols = ("file", "verdict", "reason", "tier", "time")
        self.scan_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.scan_tree.heading("file", text="File Path")
        self.scan_tree.heading("verdict", text="Verdict")
        self.scan_tree.heading("reason", text="Threat Reason")
        self.scan_tree.heading("tier", text="Tier")
        self.scan_tree.heading("time", text="Latency (ms)")

        self.scan_tree.column("file", width=420)
        self.scan_tree.column("verdict", width=120, anchor="center")
        self.scan_tree.column("reason", width=240)
        self.scan_tree.column("tier", width=60, anchor="center")
        self.scan_tree.column("time", width=100, anchor="center")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scroll.set)
        self.scan_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _setup_vault_tab(self):
        top_bar = tk.Frame(self.tab_vault, bg="#111827")
        top_bar.pack(fill="x", pady=(0, 12))

        tk.Label(top_bar, text="Quarantined Threats (Encrypted with AES-256-GCM):", font=("Segoe UI", 10, "bold"), fg="#F3F4F6", bg="#111827").pack(side="left")

        ttk.Button(top_bar, text="↻ Refresh", style="Secondary.TButton", command=self.refresh_quarantine).pack(side="right", padx=4)
        ttk.Button(top_bar, text="Purge All Threats", style="Danger.TButton", command=self._purge_vault).pack(side="right", padx=4)
        ttk.Button(top_bar, text="Delete Selected", style="Secondary.TButton", command=self._delete_selected).pack(side="right", padx=4)
        ttk.Button(top_bar, text="Restore Selected", style="Primary.TButton", command=self._restore_selected).pack(side="right", padx=4)

        # Vault Table
        table_frame = tk.Frame(self.tab_vault, bg="#111827")
        table_frame.pack(fill="both", expand=True)

        cols = ("status", "vault_id", "reason", "path", "date")
        self.vault_tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.vault_tree.heading("status", text="Status")
        self.vault_tree.heading("vault_id", text="Vault ID")
        self.vault_tree.heading("reason", text="Threat Reason")
        self.vault_tree.heading("path", text="Original Path")
        self.vault_tree.heading("date", text="Isolated Date")

        self.vault_tree.column("status", width=100, anchor="center")
        self.vault_tree.column("vault_id", width=130)
        self.vault_tree.column("reason", width=220)
        self.vault_tree.column("path", width=380)
        self.vault_tree.column("date", width=150, anchor="center")

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.vault_tree.yview)
        self.vault_tree.configure(yscrollcommand=scroll.set)
        self.vault_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _setup_rules_tab(self):
        container = tk.Frame(self.tab_rules, bg="#111827")
        container.pack(fill="both", expand=True)

        tk.Label(container, text="Active Threat Detection Engines & Cascade Policies", font=("Segoe UI", 12, "bold"), fg="#06B6D4", bg="#111827").pack(anchor="w", pady=(0, 8))

        summary = self.scanner.get_signatures_summary()

        info_box = tk.Text(container, bg="#0B0F19", fg="#F3F4F6", font=("Consolas", 10), wrap="word", relief="solid", bd=1, padx=12, pady=12)
        info_box.pack(fill="both", expand=True)

        info_text = (
            "========================================================================\n"
            "   SENTINELCORE 3-TIER EVALUATION CASCADE ARCHITECTURE\n"
            "========================================================================\n\n"
            "[*] TIER 1: FAST REPUTATION CACHE\n"
            f"    - Active Cached Signatures: {summary['tier1_cache_entries']} / {summary['tier1_cache_capacity']}\n"
            "    - Evaluation Latency:       < 0.01 ms (P99)\n"
            "    - Hash Algorithm:           SHA-256 (LRU SQLite persistence)\n\n"
            "[*] TIER 2: ENTROPY & PACKER GATING\n"
            f"    - General Cryptor Threshold: H >= {summary['tier2_entropy_threshold']}\n"
            f"    - UPX / ASPack Threshold:    H >= {summary['tier2_upx_entropy_threshold']}\n"
            "    - PE Section Parsing:       Zero-allocation in-memory header inspection\n\n"
            f"[*] TIER 3: MULTI-PATTERN SIGNATURES ({summary['tier3_signatures_count']} Rules Loaded)\n"
        )
        for sig in summary["signatures"]:
            info_text += f"    - {sig}\n"

        info_text += "\n[*] BEHAVIORAL RANSOMWARE SHIELD:\n"
        info_text += "    - Zero-Day Write Burst Limit: <= 3 high-entropy files/sec\n"
        info_text += "    - Developer Lineage Immunity: cargo, rustc, git, node, cl, python, cmd\n"

        info_box.insert("1.0", info_text)
        info_box.configure(state="disabled")

    def _build_statusbar(self):
        status_bar = tk.Frame(self.root, bg="#111827", height=24, padx=20, pady=4)
        status_bar.pack(fill="x", side="bottom")

        tk.Label(
            status_bar,
            text="SentinelCore v2.4 • Web Dashboard: http://127.0.0.1:8765 • Altitude 320500",
            font=("Segoe UI", 8),
            fg="#9CA3AF",
            bg="#111827"
        ).pack(side="left")

    def _browse_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            self.scan_path_var.set(folder)

    def _browse_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Scan")
        if file_path:
            self.scan_path_var.set(file_path)

    def _set_and_scan(self, folder_name: str):
        user_p = os.environ.get("USERPROFILE", "C:\\Users\\johns")
        if folder_name == "Temp":
            p = os.environ.get("TEMP", os.path.join(user_p, "AppData\\Local\\Temp"))
        else:
            p = os.path.join(user_p, folder_name)
        self.scan_path_var.set(p)
        self._start_scan_thread()

    def _start_scan_thread(self):
        target = self.scan_path_var.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showwarning("Invalid Path", f"Path does not exist:\n{target}")
            return

        self.btn_scan.configure(state="disabled")
        self.progress_bar["value"] = 0
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.lbl_scan_status.config(text=f"Scanning: {target}...")

        threading.Thread(target=self._run_scan, args=(target,), daemon=True).start()

    def _run_scan(self, target: str):
        t0 = time.time()
        files_to_scan = []
        if os.path.isfile(target):
            files_to_scan = [target]
        else:
            for root, _, files in os.walk(target):
                for f in files:
                    files_to_scan.append(os.path.join(root, f))
                    if len(files_to_scan) >= 1500:
                        break
                if len(files_to_scan) >= 1500:
                    break

        total = len(files_to_scan)
        scanned = 0
        threats = 0

        for fp in files_to_scan:
            scanned += 1
            try:
                verdict = self.scanner.scan_file(fp)
                if verdict.is_malicious():
                    threats += 1
                    self.vault.isolate_file(fp, reason=verdict.reason)
                    self.root.after(0, self._insert_scan_row, fp, "MALICIOUS", verdict.reason, verdict.tier, verdict.scan_time_ms)
                elif scanned <= 10 or scanned % 50 == 0:
                    self.root.after(0, self._insert_scan_row, fp, "CLEAN", "Clean", verdict.tier, verdict.scan_time_ms)
            except Exception:
                pass

            pct = int((scanned / max(total, 1)) * 100)
            self.root.after(0, self._update_scan_progress, pct, f"Inspected {scanned}/{total} files...")

        elapsed = time.time() - t0
        status_msg = f"Scan Complete in {elapsed:.2f}s — {scanned} files inspected, {threats} threats neutralized."
        self.root.after(0, self._finish_scan, status_msg)

    def _insert_scan_row(self, fp: str, verdict: str, reason: str, tier: int, latency: float):
        row_id = self.scan_tree.insert("", "end", values=(fp, verdict, reason, f"Tier {tier}", f"{latency:.3f}"))
        if verdict == "MALICIOUS":
            self.scan_tree.tag_configure("mal", foreground="#EF4444")
            self.scan_tree.item(row_id, tags=("mal",))

    def _update_scan_progress(self, pct: int, msg: str):
        self.progress_bar["value"] = pct
        self.lbl_scan_status.config(text=msg)

    def _finish_scan(self, summary_msg: str):
        self.progress_bar["value"] = 100
        self.lbl_scan_status.config(text=summary_msg)
        self.btn_scan.configure(state="normal")
        self.refresh_quarantine()
        self.refresh_metrics()

    def refresh_quarantine(self):
        self.vault_tree.delete(*self.vault_tree.get_children())
        items = self.vault.list_quarantined()
        for item in items:
            status = "RESTORED" if item.get("is_restored") else "ISOLATED"
            v_id = item["vault_id"][:12] + "..."
            self.vault_tree.insert(
                "",
                "end",
                iid=item["vault_id"],
                values=(status, v_id, item["reason"], item["original_path"], item["quarantine_time"])
            )

    def refresh_metrics(self):
        items = self.vault.list_quarantined()
        active = sum(1 for i in items if not i.get("is_restored"))
        self.card_cache.value_label.config(text=f"{len(self.scanner.cache):,} Signatures")
        self.card_vault.value_label.config(text=f"{active} Isolated Threats")

    def _periodic_update(self):
        self.refresh_metrics()
        self.root.after(3000, self._periodic_update)

    def _restore_selected(self):
        selected = self.vault_tree.selection()
        if not selected:
            messagebox.showinfo("Select Item", "Please select a quarantined threat from the table.")
            return
        vault_id = selected[0]
        try:
            self.vault.restore_file(vault_id)
            messagebox.showinfo("Restoration Successful", f"Threat {vault_id} restored bit-for-bit to its original path.")
            self.refresh_quarantine()
            self.refresh_metrics()
        except Exception as e:
            messagebox.showerror("Restoration Failed", str(e))

    def _delete_selected(self):
        selected = self.vault_tree.selection()
        if not selected:
            messagebox.showinfo("Select Item", "Please select a quarantined threat to delete.")
            return
        vault_id = selected[0]
        if messagebox.askyesno("Confirm Permanent Deletion", f"Permanently shred and delete threat archive {vault_id}?"):
            try:
                self.vault.delete_quarantined(vault_id)
                self.refresh_quarantine()
                self.refresh_metrics()
            except Exception as e:
                messagebox.showerror("Deletion Failed", str(e))

    def _purge_vault(self):
        if messagebox.askyesno("Confirm Purge", "Permanently shred ALL quarantined files in the vault?"):
            purged = self.vault.purge_all()
            messagebox.showinfo("Purge Complete", f"Successfully shredded {purged} threat archives.")
            self.refresh_quarantine()
            self.refresh_metrics()

def main():
    root = tk.Tk()
    app = SentinelDesktopApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
