"""
On-demand audit tabs: running processes, startup entries and network sockets.
Each one runs its audit on a worker thread and hands the result back through
`post`, which must run the callable on the Tk thread (Tk is not thread safe).
"""

import threading
import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Dict, List, Sequence, Tuple

SURFACE = "#141824"
LEVEL_COLORS = {"HIGH_RISK": "#F43F5E", "THREAT": "#F43F5E", "SUSPICIOUS": "#F59E0B"}

Column = Tuple[str, str, int, str]  # key, heading, width, anchor


class AuditTab:
    def __init__(self, parent: tk.Frame, post: Callable[[Callable[[], None]], None], title: str, button_text: str,
                 columns: Sequence[Column], fetch: Callable[[], List[Dict[str, Any]]],
                 to_row: Callable[[Dict[str, Any]], Tuple[str, tuple]]):
        self.post = post
        self.fetch = fetch
        self.to_row = to_row
        self.rows: Dict[str, Dict[str, Any]] = {}

        self.top = tk.Frame(parent, bg=SURFACE)
        self.top.pack(fill="x", pady=(0, 8))
        tk.Label(self.top, text=title, font=("Segoe UI", 9, "bold"), fg="#FFFFFF", bg=SURFACE).pack(side="left")
        self.status = tk.Label(self.top, text="", font=("Segoe UI", 8), fg="#64748B", bg=SURFACE)
        self.status.pack(side="left", padx=(10, 0))
        self.run_button = ttk.Button(self.top, text=button_text, style="Primary.TButton", command=self.run)
        self.run_button.pack(side="right", padx=2)

        grid = tk.Frame(parent, bg=SURFACE)
        grid.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(grid, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for key, heading, width, anchor in columns:
            self.tree.heading(key, text=heading)
            self.tree.column(key, width=width, anchor=anchor)
        for level, color in LEVEL_COLORS.items():
            self.tree.tag_configure(level, foreground=color)
        scroll = ttk.Scrollbar(grid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def run(self):
        self.run_button.configure(state="disabled")
        self.status.config(text="Auditing...")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            items, error = self.fetch(), None
        except Exception as err:  # surfaced in the tab, never swallowed
            items, error = [], str(err)
        self.post(lambda: self._populate(items, error))

    def _populate(self, items: List[Dict[str, Any]], error):
        self.run_button.configure(state="normal")
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        if error:
            self.status.config(text=f"Audit failed: {error}")
            return
        flagged = 0
        for item in items:
            level, values = self.to_row(item)
            iid = self.tree.insert("", "end", values=values, tags=(level,) if level in LEVEL_COLORS else ())
            self.rows[iid] = item
            flagged += level in LEVEL_COLORS
        self.status.config(text=f"{len(items)} checked, {flagged} flagged")

    def selected(self):
        sel = self.tree.selection()
        return self.rows.get(sel[0]) if sel else None


def build_process_tab(parent, post, proc_monitor) -> AuditTab:
    def to_row(p):
        indicators = ", ".join(p["indicators"]) if p["indicators"] else "Normal behavior"
        return p["threat_level"], (p["threat_level"], f"{p['risk_score']}/100", p["pid"], p["name"],
                                   p["parent"] or "-", p["memory_mb"], indicators)

    tab = AuditTab(parent, post, "Active Processes & Execution Behavior:", "Audit Processes", (
        ("threat", "Status", 85, "center"), ("score", "Risk Score", 75, "center"),
        ("pid", "PID", 65, "center"), ("name", "Process Name", 140, "w"),
        ("parent", "Parent Process", 120, "w"), ("memory", "RAM (MB)", 75, "center"),
        ("indicators", "Behavioral Indicators", 360, "w"),
    ), lambda: proc_monitor.audit_running_processes(limit=80), to_row)

    def terminate():
        proc = tab.selected()
        if proc is None:
            messagebox.showinfo("Select Process", "Please select a process from the table to terminate.")
            return
        pid = int(proc["pid"])
        if messagebox.askyesno("Confirm Termination", f"Terminate {proc['name']} (PID {pid})?"):
            if proc_monitor.terminate_process(pid):
                messagebox.showinfo("Process Terminated", f"Terminated PID {pid}.")
                tab.run()
            else:
                messagebox.showerror("Error", f"Could not terminate PID {pid} (access denied or already exited).")

    ttk.Button(tab.top, text="Terminate Process", style="Danger.TButton", command=terminate).pack(side="right", padx=2)
    return tab


def build_persistence_tab(parent, post, persistence_scanner) -> AuditTab:
    def to_row(it):
        level = "THREAT" if it.get("is_threat") else "CLEAN"
        return level, (level, it.get("location", ""), it.get("name", ""),
                       it.get("target_path", ""), it.get("command", "") or "-")

    return AuditTab(parent, post, "Windows Startup & AutoRun Audit:", "Scan AutoRun Items", (
        ("status", "Verdict", 90, "center"), ("source", "Location", 130, "w"),
        ("name", "Item Name", 140, "w"), ("target", "Target Path", 350, "w"),
        ("args", "Arguments / Flags", 220, "w"),
    ), persistence_scanner.audit_all, to_row)


def build_network_tab(parent, post, net_monitor) -> AuditTab:
    def to_row(c):
        return c["threat_level"], (c["threat_level"], c["process"], c["pid"], c["protocol"],
                                   c["local_address"], c["remote_address"] or "*", c["status"])

    return AuditTab(parent, post, "Active Process Sockets & C2 Detection:", "Audit Sockets", (
        ("risk", "Risk", 85, "center"), ("process", "Process", 140, "w"),
        ("pid", "PID", 65, "center"), ("proto", "Proto", 60, "center"),
        ("local", "Local Address", 220, "w"), ("remote", "Remote Address", 220, "w"),
        ("status", "Socket Status", 120, "center"),
    ), net_monitor.audit_connections, to_row)
