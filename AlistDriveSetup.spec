# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Administrator\\.qoderworkcn\\workspace\\mqt2z86ndtrl45hv\\AlistDriveAuth\\installer\\installer.py'],
    pathex=[],
    binaries=[],
    datas=[('MorongDisk.exe', '.'), ('rclone.exe', '.'), ('winfsp-2.0.23075.msi', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MorongDiskSetup',
    icon='morong.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
