# -*- mode: python ; coding: utf-8 -*-

excludes = [
    'tkinter', 'unittest', 'xmlrpc', 'pydoc', 'doctest',
    'distutils', 'lib2to3', 'setuptools', 'pip', 'pkg_resources',
    'bz2', 'lzma',
    'multiprocessing', 'concurrent', 'asyncio',
    'xml.dom', 'xml.sax', 'xml.etree',
    'curses', 'tty', 'pty',
    'venv', 'ensurepip', 'zoneinfo',
    'test', 'tests', 'idlelib', 'pydoc_data',
    'IPython', 'jupyter', 'notebook',
    'numpy', 'pandas', 'matplotlib', 'scipy',
    'PIL', 'cv2', 'requests_oauthlib',
    'sphinx', 'docutils', 'pygments',
    'win32com', 'pythoncom', 'pywintypes',
    'tornado', 'gevent', 'zmq',
    'watchdog', 'watchdog.observers', 'watchdog.events',
]

a = Analysis(
    ['auth_server.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['cryptography.hazmat.primitives.asymmetric.rsa', 'cryptography.hazmat.primitives.asymmetric.padding', 'cryptography.hazmat.primitives.hashes', 'cryptography.hazmat.primitives.serialization', 'cryptography.hazmat.primitives.ciphers', 'cryptography.hazmat.primitives.ciphers.algorithms', 'cryptography.hazmat.primitives.ciphers.modes', 'cryptography.hazmat.primitives.kdf.pbkdf2', 'cryptography.hazmat.decrepit.ciphers.modes'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=2,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AuthServer',
    icon='morong.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_server.txt',
    manifest='AuthServer.manifest',
)
