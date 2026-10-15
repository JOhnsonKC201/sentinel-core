# PyInstaller spec for the SentinelCore desktop app. Build with scripts/build-installer.ps1.
#
# SentinelCore's own packages are collected as .py source files, not bytecode
# inside the archive: the engine fingerprints its own source to invalidate
# stale cached verdicts, and the integrity guard hashes these same files.

import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
OWN_PACKAGES = ["sentinel_scanner", "sentinel_guard", "sentinel_vault", "sentinel_behavior", "sentinel_ui"]

a = Analysis(
    [os.path.join(ROOT, "packaging", "sentinel_app.py")],
    pathex=[ROOT],
    datas=[(os.path.join(ROOT, "build", "integrity_manifest.json"), "data")],
    hiddenimports=["pystray._win32", "PIL._tkinter_finder"] + OWN_PACKAGES,
    excludes=["pytest", "PyInstaller"],
    module_collection_mode={name: "py" for name in OWN_PACKAGES},
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelCore",
    icon=os.path.join(ROOT, "build", "SentinelCore.ico"),
    console=False,
    upx=False,  # UPX-packed binaries look exactly like what Tier 2 flags
)
coll = COLLECT(exe, a.binaries, a.datas, name="SentinelCore", upx=False)
