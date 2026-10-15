"""
Protection tab: one row per shield with its live state and an on/off switch,
plus the merged event log from the running shields.
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List

from sentinel_guard.protection import ShieldState

SURFACE = "#141824"
STATE_COLORS = {"on": "#10B981", "off": "#F59E0B", "unavailable": "#64748B"}
EVENT_LIMIT = 60


class ProtectionTab:
    def __init__(self, parent: tk.Frame, on_toggle: Callable[[str, bool], None]):
        self.on_toggle = on_toggle
        self._rows: Dict[str, Dict[str, tk.Widget]] = {}

        tk.Label(parent, text="Real-time shields", font=("Segoe UI", 11, "bold"),
                 fg="#FFFFFF", bg=SURFACE).pack(anchor="w", pady=(0, 6))
        self.rows_frame = tk.Frame(parent, bg=SURFACE)
        self.rows_frame.pack(fill="x", pady=(0, 12))

        tk.Label(parent, text="Recent activity", font=("Segoe UI", 11, "bold"),
                 fg="#FFFFFF", bg=SURFACE).pack(anchor="w", pady=(0, 6))
        grid = tk.Frame(parent, bg=SURFACE)
        grid.pack(fill="both", expand=True)
        cols = ("time", "event", "detail")
        self.tree_events = ttk.Treeview(grid, columns=cols, show="headings", selectmode="none")
        for col, title, width in (("time", "Time", 150), ("event", "Event", 220), ("detail", "Detail", 520)):
            self.tree_events.heading(col, text=title)
            self.tree_events.column(col, width=width)
        self.tree_events.tag_configure("threat", foreground="#F43F5E")
        scroll = ttk.Scrollbar(grid, orient="vertical", command=self.tree_events.yview)
        self.tree_events.configure(yscrollcommand=scroll.set)
        self.tree_events.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _build_row(self, state: ShieldState) -> Dict[str, tk.Widget]:
        row = tk.Frame(self.rows_frame, bg="#0E121A", padx=14, pady=10)
        row.pack(fill="x", pady=3)
        text = tk.Frame(row, bg="#0E121A")
        text.pack(side="left", fill="x", expand=True)
        tk.Label(text, text=state.label, font=("Segoe UI", 10, "bold"),
                 fg="#F8FAFC", bg="#0E121A").pack(anchor="w")
        detail = tk.Label(text, font=("Segoe UI", 9), fg="#94A3B8", bg="#0E121A")
        detail.pack(anchor="w")
        badge = tk.Label(row, font=("Segoe UI", 9, "bold"), bg="#0E121A", width=12)
        badge.pack(side="right", padx=(8, 0))
        button = ttk.Button(row, style="Secondary.TButton")
        if state.available:
            button.pack(side="right")
        return {"detail": detail, "badge": badge, "button": button}

    def update_shields(self, states: List[ShieldState]):
        for state in states:
            widgets = self._rows.get(state.name) or self._rows.setdefault(state.name, self._build_row(state))
            if not state.available:
                key, badge_text = "unavailable", "UNAVAILABLE"
            elif state.running:
                key, badge_text = "on", "ON"
            else:
                key, badge_text = "off", "OFF"
            widgets["detail"].config(text=state.detail)
            widgets["badge"].config(text=badge_text, fg=STATE_COLORS[key])
            widgets["button"].config(
                text="Turn off" if state.running else "Turn on",
                command=lambda n=state.name, on=not state.running: self.on_toggle(n, on))

    def update_events(self, events: List[dict]):
        self.tree_events.delete(*self.tree_events.get_children())
        for ev in events[:EVENT_LIMIT]:
            kind = str(ev.get("type", "EVENT"))
            detail = f"{ev.get('reason') or ''} {ev.get('path') or ev.get('details') or ev.get('process') or ''}".strip()
            tags = ("threat",) if ("THREAT" in kind or "BLOCKED" in kind) else ()
            self.tree_events.insert("", "end", values=(ev.get("timestamp", ""), kind, detail), tags=tags)
