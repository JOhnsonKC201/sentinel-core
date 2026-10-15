"""
System tray icon for the SentinelCore desktop app.

pystray runs its own message loop on a background thread and Tk is not thread
safe, so menu clicks are only queued here. The Tk side drains the queue.
"""

import queue
from typing import Optional

from PIL import Image, ImageDraw

from sentinel_ui.status import LEVEL_COLORS, PROTECTED

OPEN = "open"
TOGGLE_PROTECTION = "toggle_protection"
SCAN_DOWNLOADS = "scan_downloads"
QUIT = "quit"
ICON_SIZE = 64


def draw_shield(level: str) -> Image.Image:
    """A filled shield in the status colour, so the tray shows state at a glance."""
    fg, _ = LEVEL_COLORS.get(level, LEVEL_COLORS[PROTECTED])
    img = Image.new("RGBA", (ICON_SIZE, ICON_SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = ICON_SIZE
    outline = [(s * 0.5, s * 0.06), (s * 0.9, s * 0.2), (s * 0.86, s * 0.56),
               (s * 0.5, s * 0.94), (s * 0.14, s * 0.56), (s * 0.1, s * 0.2)]
    d.polygon(outline, fill=fg)
    # ImageDraw replaces pixels instead of blending, so the highlight is drawn
    # on its own layer and composited over the shield.
    highlight = Image.new("RGBA", img.size, (0, 0, 0, 0))
    inner = [(s * 0.5, s * 0.2), (s * 0.76, s * 0.29), (s * 0.73, s * 0.54),
             (s * 0.5, s * 0.8), (s * 0.5, s * 0.2)]
    ImageDraw.Draw(highlight).polygon(inner, fill=(255, 255, 255, 90))
    return Image.alpha_composite(img, highlight)


class SentinelTray:
    def __init__(self, commands: "queue.Queue[str]"):
        self.commands = commands
        self.protection_on = False
        self.level = PROTECTED
        self._icon = None

    def _menu(self):
        import pystray
        item = pystray.MenuItem
        return pystray.Menu(
            item("Open SentinelCore", lambda: self.commands.put(OPEN), default=True),
            item("Real-time protection", lambda: self.commands.put(TOGGLE_PROTECTION),
                 checked=lambda _: self.protection_on),
            item("Scan Downloads", lambda: self.commands.put(SCAN_DOWNLOADS)),
            pystray.Menu.SEPARATOR,
            item("Quit SentinelCore", lambda: self.commands.put(QUIT)),
        )

    def start(self):
        import pystray
        self._icon = pystray.Icon("SentinelCore", draw_shield(self.level), "SentinelCore", self._menu())
        self._icon.run_detached()

    def update(self, level: str, tooltip: str, protection_on: bool):
        self.protection_on = protection_on
        if self._icon is None:
            return
        if level != self.level:
            self.level = level
            self._icon.icon = draw_shield(level)
        self._icon.title = tooltip[:127]  # Windows caps tray tooltips at 128 chars
        self._icon.update_menu()

    def notify(self, title: str, message: str):
        if self._icon is not None:
            self._icon.notify(message[:255], title[:63])

    def stop(self):
        icon: Optional[object] = self._icon
        self._icon = None
        if icon is not None:
            icon.stop()
