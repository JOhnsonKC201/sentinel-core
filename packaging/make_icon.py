"""Writes the app icon (.ico) from the same shield the tray draws, so they always match."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_ui.status import PROTECTED
from sentinel_ui.tray import draw_shield

ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main(out_path: str):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    draw_shield(PROTECTED).resize((256, 256)).save(out_path, sizes=ICO_SIZES)
    print(f"[+] Icon written: {out_path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "SentinelCore.ico"))
