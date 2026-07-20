# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['installer.py'],
    pathex=[],
    binaries=[],
    datas=[('MorongDisk.exe', '.'), ('rclone.exe', '.'), ('winfsp-2.0.23075.msi', '.'), ('AddWhitelist.bat', '.'), ('CleanMorongDisk.bat', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['unittest', 'xmlrpc', 'pydoc', 'doctest', 'distutils', 'lib2to3', 'setuptools', 'pip', 'pkg_resources', 'email', 'html', 'gzip', 'bz2', 'lzma', 'zipfile', 'http.cookiejar', 'http.cookies', 'http.client', 'multiprocessing', 'concurrent', 'asyncio', 'xml.dom', 'xml.sax', 'xml.etree', 'sqlite3', 'dbm', 'curses', 'tty', 'pty', 'venv', 'ensurepip', 'zoneinfo', 'IPython', 'numpy', 'pandas', 'matplotlib', 'scipy', 'PIL', 'cv2', 'tornado', 'gevent', 'zmq', 'requests', 'urllib3', 'charset_normalizer', 'certifi', 'idna', 'cryptography', 'bcrypt', 'cffi', 'watchdog', 'flask', 'werkzeug', 'jinja2', 'click', 'itsdangerous', 'markupsafe'],
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
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_setup.txt',
    icon=['morong.ico'],
    manifest='MorongDiskSetup.manifest',
)
