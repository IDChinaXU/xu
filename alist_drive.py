#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MorongDisk Client v1.16.0
远程磁盘挂载客户端 (原生托盘图标 + 自动重连 + 卸载保护 + 心跳上报 + 自动更新)
"""

CLIENT_VERSION = "1.16.0"

import os
import re
import sys
import json
import time
import base64
import ctypes
import ctypes.wintypes as wt
import struct
import shutil
import subprocess
import threading
import queue
import hashlib
import tkinter as tk
from tkinter import simpledialog, messagebox
import winreg

import requests

HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives.asymmetric import padding as _crypto_padding
    from cryptography.hazmat.primitives import hashes as _crypto_hashes, serialization as _crypto_serial
    HAS_CRYPTOGRAPHY = True
except ImportError:
    pass

# 可选依赖：文件监控
HAS_WATCHDOG = False
PollingObserver = None
FileSystemEventHandler = object
try:
    from watchdog.observers.polling import PollingObserver as _PollingObserver
    from watchdog.events import FileSystemEventHandler as _FileSystemEventHandler
    HAS_WATCHDOG = True
    PollingObserver = _PollingObserver
    FileSystemEventHandler = _FileSystemEventHandler
except ImportError:
    pass

# ============================================================
# Paths & Config
# ============================================================

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
    IS_FROZEN = True
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    IS_FROZEN = False

DATA_DIR = os.path.join(os.environ.get("APPDATA", ""), "AlistDrive")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
RCLONE_EXE = os.path.join(BASE_DIR, "rclone.exe")
WINFSP_MSI = os.path.join(BASE_DIR, "winfsp-2.0.23075.msi")
PID_FILE = os.path.join(DATA_DIR, "rclone.pid")

DEFAULT_CONFIG = {
    "server": "http://192.168.100.242:9800",
    "username": "",
    "password": "",
    "remember_password": False,
    "auto_login": False,
    "drive": "Z:",
    "label": "远程磁盘",
    "drives": [],
}

# 全局状态
_rclone_procs = {}  # drive_letter -> subprocess
_rclone_lock = threading.Lock()  # 保护 _rclone_procs 的线程安全
_obscured_pwd_cache = {}  # 缓存 rclone obscure 结果
_app_state = {"tray": None, "monitor": None, "root": None, "on_login_success": None}
_auto_retry_count = 0
_main_thread_queue = queue.Queue()

def _pwd_cache_key(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]
_obscured_pwd_cache_lock = threading.Lock()


def _ensure_auto_reconnect_tray():

    if _app_state.get("tray") is not None:
        return
    root = _app_state.get("root")
    if not root:
        return

    def on_exit_reconnect():
        global _file_log_observer, _all_file_log_observers, _file_log_uploader_stop
        if _file_log_uploader_stop:
            _file_log_uploader_stop.set()
        for obs in _all_file_log_observers:
            stop_file_log_monitor(obs)
        _all_file_log_observers.clear()
        _file_log_observer = None
        if _app_state.get("monitor"):
            _app_state["monitor"].stop()
            _app_state["monitor"] = None
        if _app_state.get("tray"):
            _app_state["tray"].stop()
            _app_state["tray"] = None
        try:
            root.destroy()
        except Exception:
            pass

    tray = NativeTrayIcon(
        "morong远程磁盘 - 重连中...",
        on_unmount=lambda: None,
        on_exit=on_exit_reconnect,
        on_open=lambda: None,
        root_ref=root)
    tray.start()
    _app_state["tray"] = tray


def _schedule_auto_background_retry():
    global _auto_retry_count

    root = _app_state.get("root")
    if not root:
        return
    _auto_retry_count += 1
    n = _auto_retry_count
    if n > 20:
        _auto_retry_count = 0
        n = 1
    delay = min(10 + 5 * n, 120)
    tray = _app_state.get("tray")
    if tray:
        tray.update_tooltip(f"morong远程磁盘 - {delay}s后第{n}次重连")
    print(f"[AutoRetry] 第{n}次后台重连 ({delay}s后)")


    def _do():
        cfg = load_config()
        server = cfg.get("server", "")
        username = cfg.get("username", "")
        password = cfg.get("password", "")
        if not server or not username or not password:
            _main_thread_queue.put(("schedule_retry", delay))
            return
        for _ in range(12):
            if is_network_available(server):
                break
            time.sleep(5)
        else:
            print(f"[AutoRetry] 第{n}次重连失败: 网络不可达")
            _main_thread_queue.put(("schedule_retry", delay))
            return
        try:
            enc_pwd, encrypted = _rsa_encrypt_password(server, password)
            r = requests.post(
                f"{server}/api/auth/login",
                json={"username": username, "password": enc_pwd, "encrypted": encrypted},
                timeout=10)
            if r.status_code != 200:
                raise Exception("认证失败")
            data = r.json()
            if not data.get("success"):
                raise Exception(data.get("error", "认证失败"))
            print(f"[AutoRetry] 第{n}次重连成功!")
            _auto_retry_count = 0
            on_success = _app_state.get("on_login_success")
            if on_success:
                _main_thread_queue.put(("auto_retry_success", data, password))
        except Exception as e:
            print(f"[AutoRetry] 第{n}次重连失败: {e}")
            if tray:
                try:
                    tray.update_tooltip(f"morong远程磁盘 - 重连失败，{delay}s后重试")
                except Exception:
                    pass
            _main_thread_queue.put(("schedule_retry", delay))

    threading.Thread(target=_do, daemon=True).start()


def load_config():
    config = DEFAULT_CONFIG.copy()
    if not os.path.exists(CONFIG_PATH):
        return config
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw_text = f.read().strip()
        if not raw_text:
            return config
        # 尝试 DPAPI 解密（新格式）
        try:
            decrypted = _dpapi_decrypt(raw_text)
            if decrypted:
                data = json.loads(decrypted)
                config.update(data)
                # 内层密码仍是 DPAPI 加密的，解密
                if config.get("password"):
                    p = config["password"]
                    for _ in range(3):
                        if p.startswith(("aes:", "dpapi:", "b64:")):
                            p = _decrypt_password(p)
                        else:
                            break
                    config["password"] = p
                # 迁移：保存为新的全量加密格式
                save_config(config)
                return config
        except (json.JSONDecodeError, Exception):
            pass
        # 回退：尝试明文 JSON（旧格式，向后兼容）
        try:
            data = json.loads(raw_text)
            config.update(data)
            if config.get("password"):
                p = config["password"]
                for _ in range(3):
                    if p.startswith(("aes:", "dpapi:", "b64:")):
                        p = _decrypt_password(p)
                    else:
                        break
                config["password"] = p
            # 迁移：保存为新的全量加密格式
            save_config(config)
            return config
        except (json.JSONDecodeError, Exception):
            pass
        # DPAPI 解密失败且非明文 JSON → 配置文件损坏，备份后返回默认
        try:
            backup_path = CONFIG_PATH + ".bak"
            shutil.copy2(CONFIG_PATH, backup_path)
            print(f"[Config] 配置文件损坏，已备份到 {backup_path}")
        except Exception:
            pass
    except Exception:
        pass
    return config


def save_config(config):
    os.makedirs(DATA_DIR, exist_ok=True)
    save_data = config.copy()
    # 内层密码 DPAPI 加密
    if save_data.get("password"):
        save_data["password"] = _encrypt_password(save_data["password"])
    json_text = json.dumps(save_data, indent=2, ensure_ascii=False)
    # 外层：整个 JSON 用 DPAPI 加密
    encrypted = _dpapi_encrypt(json_text)
    if encrypted:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(encrypted)
    else:
        # DPAPI 失败时的回退：至少密码是加密的
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            f.write(json_text)


# ============================================================
# Password Encryption (Windows DPAPI)
# ============================================================

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _aes_local_encrypt(plaintext):
    """使用 AES-GCM 加密本地密码（替代 DPAPI，避免杀软误报）"""
    if not HAS_CRYPTOGRAPHY:
        return ""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        machine_id = os.environ.get("COMPUTERNAME", "default") + os.environ.get("USERNAME", "user")
        salt = b"morong-local-v2"
        kdf = PBKDF2HMAC(algorithm=_crypto_hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(machine_id.encode("utf-8"))
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
        return base64.b64encode(iv + encryptor.tag + ct).decode("ascii")
    except Exception:
        return ""


def _aes_local_decrypt(b64_encrypted):
    """使用 AES-GCM 解密本地密码"""
    if not HAS_CRYPTOGRAPHY:
        return ""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        machine_id = os.environ.get("COMPUTERNAME", "default") + os.environ.get("USERNAME", "user")
        salt = b"morong-local-v2"
        kdf = PBKDF2HMAC(algorithm=_crypto_hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(machine_id.encode("utf-8"))
        raw = base64.b64decode(b64_encrypted)
        iv = raw[:12]
        tag = raw[12:28]
        ct = raw[28:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ct) + decryptor.finalize()
        return plaintext.decode("utf-8")
    except Exception:
        return ""


def _dpapi_encrypt(plaintext):
    try:
        blob_in = _DATA_BLOB()
        blob_out = _DATA_BLOB()
        data = plaintext.encode("utf-8")
        blob_in.cbData = len(data)
        blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_char))
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None,
            0x01, ctypes.byref(blob_out))
        if not ok:
            return ""
        encrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return base64.b64encode(encrypted).decode("ascii")
    except Exception:
        return ""


def _dpapi_decrypt(b64_encrypted):
    try:
        encrypted = base64.b64decode(b64_encrypted)
        blob_in = _DATA_BLOB()
        blob_out = _DATA_BLOB()
        blob_in.cbData = len(encrypted)
        blob_in.pbData = ctypes.cast(ctypes.create_string_buffer(encrypted), ctypes.POINTER(ctypes.c_char))
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None,
            0x01, ctypes.byref(blob_out))
        if not ok:
            return ""
        decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return decrypted.decode("utf-8")
    except Exception:
        return ""


def _encrypt_password(password):
    aes = _aes_local_encrypt(password)
    if aes:
        return "aes:" + aes
    dpapi = _dpapi_encrypt(password)
    if dpapi:
        return "dpapi:" + dpapi
    print("[Security] AES 和 DPAPI 均不可用，拒绝存储密码")
    return ""


def _decrypt_password(stored):
    if not stored:
        return ""
    if stored.startswith("aes:"):
        result = _aes_local_decrypt(stored[4:])
        if result:
            return result
        return ""
    if stored.startswith("dpapi:"):
        return _dpapi_decrypt(stored[6:])
    if stored.startswith("b64:"):
        try:
            return base64.b64decode(stored[4:]).decode("utf-8")
        except Exception:
            return ""
    return ""


# ============================================================
# Input Sanitization
# ============================================================

def sanitize_label(label):
    safe = re.sub(r'[^\w\u4e00-\u9fff\s\-]', '', label).strip()
    return safe or "远程磁盘"


def sanitize_drive_letter(drive):
    if re.match(r'^[A-Za-z]:$', drive):
        return drive.upper()
    return "Z:"


_rsa_public_key_cache = {"key": None, "fetched": 0}
_rsa_cache_lock = threading.Lock()

def _rsa_encrypt_password(server, password):
    if not HAS_CRYPTOGRAPHY:
        return password, False
    try:
        now = time.time()
        with _rsa_cache_lock:
            need_fetch = _rsa_public_key_cache["key"] is None or now - _rsa_public_key_cache["fetched"] > 3600
        if need_fetch:
            r = requests.get(f"{server}/api/auth/public-key", timeout=5)
            if r.status_code != 200:
                with _rsa_cache_lock:
                    _rsa_public_key_cache["key"] = None
                return password, False
            pem = r.json().get("public_key", "")
            if not pem:
                with _rsa_cache_lock:
                    _rsa_public_key_cache["key"] = None
                return password, False
            pub_key = _crypto_serial.load_pem_public_key(pem.encode())
            with _rsa_cache_lock:
                _rsa_public_key_cache["key"] = pub_key
                _rsa_public_key_cache["fetched"] = now
        with _rsa_cache_lock:
            pub_key = _rsa_public_key_cache["key"]
        ciphertext = pub_key.encrypt(
            password.encode("utf-8"),
            _crypto_padding.OAEP(
                mgf=_crypto_padding.MGF1(algorithm=_crypto_hashes.SHA256()),
                algorithm=_crypto_hashes.SHA256(),
                label=None))
        return base64.b64encode(ciphertext).decode("ascii"), True
    except Exception:
        with _rsa_cache_lock:
            _rsa_public_key_cache["key"] = None
            _rsa_public_key_cache["fetched"] = 0
        return password, False


# ============================================================
# WinFsp
# ============================================================

_winfsp_checked = False
_winfsp_result = False


def is_winfsp_installed():
    global _winfsp_checked, _winfsp_result
    if _winfsp_checked:
        return _winfsp_result
    # 检查 System32 驱动（WinFsp 2.0 及更早版本）
    if os.path.exists(r"C:\Windows\System32\drivers\winfsp-x64.sys"):
        _winfsp_checked = True
        _winfsp_result = True
        return True
    # 检查 WinFsp 2.1+ SxS 安装目录
    for base in [r"C:\Program Files\WinFsp", r"C:\Program Files (x86)\WinFsp"]:
        sxs_dir = os.path.join(base, "SxS")
        if os.path.isdir(sxs_dir):
            for entry in os.listdir(sxs_dir):
                bin_dir = os.path.join(sxs_dir, entry, "bin")
                if os.path.exists(os.path.join(bin_dir, "winfsp-x64.sys")):
                    _winfsp_checked = True
                    _winfsp_result = True
                    return True
        bin_dir = os.path.join(base, "bin")
        if os.path.exists(os.path.join(bin_dir, "winfsp-x64.sys")):
            _winfsp_checked = True
            _winfsp_result = True
            return True
    # 检查注册表
    try:

        for path in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            if "winfsp" in name.lower():
                                winreg.CloseKey(subkey)
                                winreg.CloseKey(key)
                                _winfsp_checked = True
                                _winfsp_result = True
                                return True
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(subkey)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                continue
    except Exception:
        pass
    _winfsp_checked = True
    _winfsp_result = False
    return False


def install_winfsp():
    global _winfsp_checked, _winfsp_result
    if is_winfsp_installed():
        return True, "已安装"
    if not os.path.exists(WINFSP_MSI):
        return False, "找不到 winfsp-2.0.23075.msi"
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "msiexec.exe",
            f'/i "{WINFSP_MSI}" /qn /norestart', None, 1)
        for _ in range(30):
            time.sleep(1)
            _winfsp_checked = False  # 重置缓存，允许重新检测
            if is_winfsp_installed():
                return True, "安装完成"
        return True, "安装已启动（可能需要重启生效）"
    except Exception as e:
        return False, str(e)


# ============================================================
# rclone Process Management
# ============================================================

def obscure_password(password):
    """获取 rclone obscure 密码（带缓存，线程安全）"""
    cache_key = _pwd_cache_key(password)
    with _obscured_pwd_cache_lock:
        if cache_key in _obscured_pwd_cache:
            return _obscured_pwd_cache[cache_key]
    try:
        proc = subprocess.Popen(
            [RCLONE_EXE, "obscure", "-"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000))
        try:
            stdout, _ = proc.communicate(input=password.encode("utf-8"), timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return ""
        obscured = stdout.decode("utf-8", errors="replace").strip()
        if obscured:
            with _obscured_pwd_cache_lock:
                _obscured_pwd_cache[cache_key] = obscured
        return obscured
    except Exception:
        return ""


def _kill_own_rclone(drive_letter=None):
    global _rclone_procs
    with _rclone_lock:
        if drive_letter:
            dl = drive_letter.upper()
            proc = _rclone_procs.pop(dl, None)
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                if os.path.exists(PID_FILE):
                    with open(PID_FILE, "r") as f:
                        pid_data = json.load(f)
                    pid_data.pop(dl, None)
                    if pid_data:
                        with open(PID_FILE, "w") as f:
                            json.dump(pid_data, f)
                    else:
                        os.remove(PID_FILE)
            except Exception:
                pass
        else:
            for dl, proc in list(_rclone_procs.items()):
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
            _rclone_procs.clear()
            if os.path.exists(PID_FILE):
                try:
                    with open(PID_FILE, "r") as f:
                        pid_data = json.load(f)
                    CNW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
                    for dl_key, pid in pid_data.items():
                        try:
                            check_proc = subprocess.Popen(
                                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=CNW)
                            check_out, _ = check_proc.communicate(timeout=5)
                            if b"rclone" in check_out.lower():
                                subprocess.Popen(
                                    ["taskkill", "/f", "/pid", str(pid)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    creationflags=CNW).communicate(timeout=5)
                        except Exception:
                            pass
                    os.remove(PID_FILE)
                except Exception:
                    try:
                        os.remove(PID_FILE)
                    except Exception:
                        pass


def _is_drive_ready(drive):
    try:
        os.listdir(drive + "\\")
        return True
    except Exception:
        return False


_rclone_health_running = False

def _rclone_health_check_loop():
    global _rclone_health_running, _rclone_procs
    _rclone_health_running = True
    while _rclone_health_running:
        time.sleep(60)
        if not _rclone_health_running:
            break
        with _rclone_lock:
            drives_to_check = list(_rclone_procs.items())
        for dl, proc in drives_to_check:
            try:
                if proc.poll() is not None:
                    continue
                if not _is_drive_ready(dl):
                    logging.warning(f"[rclone健康检查] 盘符 {dl} 不可访问，检查 rclone 进程")
                    try:
                        import psutil
                        p = psutil.Process(proc.pid)
                        cpu = p.cpu_percent(interval=2)
                        if cpu > 80:
                            logging.warning(f"[rclone健康检查] rclone PID={proc.pid} CPU={cpu}%，终止重启")
                            _kill_own_rclone(dl)
                            continue
                    except Exception:
                        pass
                    try:
                        test_path = dl + "\\"
                        if not os.path.exists(test_path):
                            logging.warning(f"[rclone健康检查] 盘符 {dl} 挂载丢失，终止 rclone")
                            _kill_own_rclone(dl)
                    except Exception:
                        logging.warning(f"[rclone健康检查] 盘符 {dl} 访问异常，终止 rclone")
                        _kill_own_rclone(dl)
            except Exception:
                pass


def start_rclone_health_check():
    global _rclone_health_running
    if not _rclone_health_running:
        t = threading.Thread(target=_rclone_health_check_loop, daemon=True, name="rclone-health")
        t.start()


def mount_webdav(url, user, password, drive, label, config_name="ALIST_DRIVE"):
    global _rclone_procs
    drive = sanitize_drive_letter(drive)
    _kill_own_rclone(drive)
    CNW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
    try:
        proc = subprocess.Popen(
            ["net", "use", drive, "/delete", "/y"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CNW)
        proc.communicate(timeout=5)
    except Exception:
        pass

    for _ in range(5):
        if not os.path.exists(drive + "\\"):
            break
        time.sleep(1)

    obscured = obscure_password(password)
    if not obscured:
        return False, "无法加密密码，请检查 rclone.exe"

    from urllib.parse import quote, urlsplit, urlunsplit
    parsed = urlsplit(url)
    encoded_path = quote(parsed.path)
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, encoded_path, parsed.query, parsed.fragment))

    cfg_path = os.path.join(DATA_DIR, f"rclone_{drive.rstrip(':').lower()}.conf")
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(f"[{config_name}]\n")
            f.write("type = webdav\n")
            f.write(f"url = {safe_url}\n")
            f.write("vendor = other\n")
            f.write(f"user = {user}\n")
            f.write(f"pass = {obscured}\n")
    except Exception:
        return False, "无法创建 rclone 配置文件"

    env = os.environ.copy()
    env["RCLONE_CONFIG"] = cfg_path

    cmd = [
        RCLONE_EXE, "mount", f"{config_name}:", drive,
        "--vfs-cache-mode", "full",
        "--vfs-cache-max-size", "2G",
        "--vfs-write-back", "5s",
        "--no-check-certificate",
        "--links",
        "--header", "Referer:",
        "--vfs-cache-max-age", "24h",
        "--vfs-read-wait", "200ms",
        "--vfs-read-chunk-size", "64M",
        "--vfs-read-chunk-size-limit", "256M",
        "--buffer-size", "16M",
        "--attr-timeout", "10s",
        "--use-server-modtime",
        "--transfers", "2",
        "--checkers", "4",
        "--retries", "3",
        "--retries-sleep", "1s",
        "--low-level-retries", "3",
        "--timeout", "30s",
        "--contimeout", "10s",

        "--volname", sanitize_label(label),
        "-o", "FileSecurity=D:P(A;;FA;;;WD)",
    ]

    log_path = os.path.join(DATA_DIR, f"rclone_stderr_{drive.rstrip(':').lower()}.log")
    log_file = None
    try:
        log_file = open(log_path, "a", encoding="utf-8")
    except Exception:
        pass

    try:
        with _rclone_lock:
            BELOW_NORMAL = 0x40000000
            proc = subprocess.Popen(
                cmd, env=env,
                stdout=subprocess.DEVNULL,
                stderr=log_file if log_file else subprocess.DEVNULL,
                creationflags=CNW | BELOW_NORMAL)
            _rclone_procs[drive.upper()] = proc
            my_proc = proc

        try:
            with _rclone_lock:
                pid_data = {}
                if os.path.exists(PID_FILE):
                    try:
                        with open(PID_FILE, "r") as f:
                            pid_data = json.load(f)
                    except Exception:
                        pass
                pid_data[drive.upper()] = my_proc.pid
                with open(PID_FILE, "w") as f:
                    json.dump(pid_data, f)
        except Exception:
            pass

        def _close_log():
            nonlocal log_file
            if log_file:
                try:
                    log_file.close()
                except Exception:
                    pass
                log_file = None

        time.sleep(0.5)
        if os.path.exists(drive + "\\") and _is_drive_ready(drive):
            _close_log()
            return True, "挂载成功"

        for _ in range(30):
            time.sleep(1)
            if os.path.exists(drive + "\\") and _is_drive_ready(drive):
                _close_log()
                return True, "挂载成功"
            if my_proc.poll() is not None:
                err_info = ""
                try:
                    _close_log()
                    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                        err_info = "".join(lines[-3:]).strip()
                except Exception:
                    pass
                if err_info:
                    return False, f"rclone 退出 (code={my_proc.returncode}): {err_info[:200]}"
                return False, f"rclone 进程异常退出 (code={my_proc.returncode})"
        _close_log()
        return False, "挂载超时，请检查网络和服务器"
    finally:
        if log_file:
            try:
                log_file.close()
            except Exception:
                pass


def is_drive_accessible(drive):
    try:
        return os.path.exists(drive + "\\")
    except Exception:
        return False


def is_network_available(server_url):
    try:
        requests.get(f"{server_url}/api/auth/verify", timeout=5,
                     headers={"Authorization": "Bearer invalid"})
        return True
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return False
    except Exception:
        return False


# ============================================================
# System Hardware Info Collection
# ============================================================

_PS_INFO_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

# Win7-compatible WMI wrapper (Get-WmiObject works on PS2+)
function Gw($cls) { Get-WmiObject -Class $cls }

$info = @{}

# Hostname + OS
$info.hostname = $env:COMPUTERNAME
try { $info.hostname = (hostname).Trim() } catch {}
$os = Gw Win32_OperatingSystem
$info.os_name = ($os.Caption -replace 'Microsoft ', '').Trim()
$info.os_version = "$($os.Version) (Build $($os.BuildNumber))"
$info.os_arch = $os.OSArchitecture
try { $info.os_install_date = $os.ConvertToDateTime($os.InstallDate).ToString('yyyy-MM-dd') } catch { $info.os_install_date = '' }

# BIOS
$bios = Gw Win32_BIOS
$info.bios_sn = $bios.SerialNumber.Trim()
$info.bios_vendor = $bios.Manufacturer
$info.bios_ver = $bios.SMBIOSBIOSVersion
try {
    $snDec = [long]0
    foreach ($ch in $info.bios_sn.ToUpper().ToCharArray()) {
        if ($ch -ge '0' -and $ch -le '9') { $v = [int]$ch - [int][char]'0' }
        elseif ($ch -ge 'A' -and $ch -le 'Z') { $v = [int]$ch - [int][char]'A' + 10 }
        else { throw }
        $snDec = $snDec * 36 + $v
    }
    $info.bios_sn_dec = $snDec
} catch { $info.bios_sn_dec = '' }

# CPU
$cpus = @(Gw Win32_Processor)
$cpu = $cpus[0]
$info.cpu_model = ($cpu.Name -replace '\s+', ' ').Trim()
$totalCores = 0; $totalThreads = 0
foreach ($c in $cpus) {
    $totalCores += $c.NumberOfCores
    $totalThreads += $c.NumberOfLogicalProcessors
}
$info.cpu_cores = $totalCores
$info.cpu_threads = $totalThreads
$info.cpu_speed = "$([math]::Round($cpu.MaxClockSpeed / 1000, 2))GHz"
try {
    $caches = @(Gw Win32_CacheMemory | Where-Object { $_.InstalledSize -gt 0 })
    $l1=0; $l2=0; $l3=0
    foreach ($c in $caches) {
        switch ([int]$c.Level) {
            3 { $l1 += $c.InstalledSize }
            4 { $l2 += $c.InstalledSize }
            5 { $l3 += $c.InstalledSize }
        }
    }
    $parts = @()
    if ($l1 -gt 0) { $parts += "L1=${l1}KB" }
    if ($l2 -gt 0) { if ($l2 -ge 1024) { $parts += "L2=$([math]::Round($l2/1024,1))MB" } else { $parts += "L2=${l2}KB" } }
    if ($l3 -gt 0) { if ($l3 -ge 1024) { $parts += "L3=$([math]::Round($l3/1024,0))MB" } else { $parts += "L3=${l3}KB" } }
    $info.cpu_cache = $parts -join ' '
} catch { $info.cpu_cache = '' }

# RAM
$mTypes = @{0='Unknown';17='DDR';18='DDR2';24='DDR3';26='DDR4';30='LPDDR';34='LPDDR4X';35='LPDDR5'}
$mems = @(Gw Win32_PhysicalMemory)
$ramList = @()
$totalRAM = 0
foreach ($m in $mems) {
    $gb = [math]::Round($m.Capacity / 1GB, 1); $totalRAM += $gb
    $type = $mTypes[[int]$m.SMBIOSMemoryType]; if (-not $type) { $type = "Type$($m.SMBIOSMemoryType)" }
    $spd = if ($m.Speed -and $m.Speed -gt 0) { $m.Speed } else { 0 }
    $mfr = if ($m.Manufacturer) { $m.Manufacturer.Trim() } else { 'N/A' }
    $pn = if ($m.PartNumber) { $m.PartNumber.Trim() } else { '' }
    $ramList += @{gb=$gb; type=$type; speed=$spd; mfr=$mfr; pn=$pn}
}
$info.ram_total_gb = $totalRAM
$ramUsedGB = [math]::Round($os.TotalVisibleMemorySize / 1MB - $os.FreePhysicalMemory / 1MB, 2)
$info.ram_used_gb = $ramUsedGB
$info.ram_used_pct = if ($totalRAM -gt 0) { [math]::Round($ramUsedGB / $totalRAM * 100, 1) } else { 0 }
$info.ram_sticks = $ramList
$ramMaxGB = 0
try {
    $ma = Gw Win32_PhysicalMemoryArray | Select-Object -First 1
    if ($ma.MaxCapacity -and $ma.MaxCapacity -gt 0) { $ramMaxGB = [math]::Round($ma.MaxCapacity / 1MB, 0) }
} catch {}
$info.ram_max_gb = $ramMaxGB

# GPU
$gpus = @(Gw Win32_VideoController)
$gpuList = @()
foreach ($g in $gpus) {
    $name = ($g.Name -replace '\s+', ' ').Trim()
    $vramGB = if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) { [math]::Round($g.AdapterRAM / 1GB, 1) } else { 0 }
    if ($vramGB -eq 0 -and ($name -match 'Idd|Virtual|Remote|Mirror|USB Display|RDP')) { continue }
    $gpuList += @{name=$name; vram_gb=$vramGB}
}
$info.gpus = $gpuList

# Disk - use WMI only (no Get-PhysicalDisk which requires Win8+)
$drives = @(Gw Win32_DiskDrive)
$diskList = @()
foreach ($d in $drives) {
    $sizeGB = [math]::Round($d.Size / 1GB, 1)
    $model = ($d.Model -replace '\s+', ' ').Trim()
    $serial = if ($d.SerialNumber) { $d.SerialNumber.Trim() } else { '' }
    $dtype = 'Unknown'
    if ($model -match 'NVMe') { $dtype = 'NVMe' }
    elseif ($model -match 'SSD|Solid') { $dtype = 'SSD' }
    elseif ($d.MediaType -match 'Fixed|hard disk' -or $d.InterfaceType -match 'SCSI|IDE|ATA') {
        try {
            $partitions = @(Gw "Win32_DiskPartition" | Where-Object { $_.DiskIndex -eq $d.Index })
            if ($partitions.Count -gt 0 -and $d.MediaType -match 'Removable') { $dtype = 'Removable' }
            else { $dtype = 'HDD' }
        } catch { $dtype = 'HDD' }
    }
    $diskList += @{model=$model; size_gb=$sizeGB; type=$dtype}
}
$info.disks = $diskList

# Network - WMI based (Win7 compatible)
$netAdapters = @(Gw Win32_NetworkAdapter | Where-Object {
    $_.MACAddress -and $_.PhysicalAdapter -eq $true -and
    ($_.AdapterTypeID -eq 0 -or $_.AdapterTypeID -eq 9)
})
$netList = @()
foreach ($a in $netAdapters) {
    $name = ($a.Name -replace '\s+', ' ').Trim()
    $typeStr = if ($a.AdapterTypeID -eq 9) { 'Wi-Fi' } else { 'Ethernet' }
    $connected = ($_.NetConnectionStatus -eq 2)
    $statusStr = if ($a.NetConnectionStatus -eq 2) { '使用中' } else { '闲置' }
    $ip = ''; $gw = ''; $linkSpl = ''
    $cfg = Gw Win32_NetworkAdapterConfiguration | Where-Object { $_.Index -eq $a.Index }
    if ($cfg) {
        if ($cfg.IPAddress) { $ip = $cfg.IPAddress[0] }
        if ($cfg.DefaultIPGateway) { $gw = $cfg.DefaultIPGateway[0] }
    }
    if ($a.Speed -and $a.Speed -gt 0) {
        if ($a.Speed -ge 1e9) { $linkSpd = "$([math]::Round($a.Speed / 1e9, 0))Gbps" }
        else { $linkSpd = "$([math]::Round($a.Speed / 1e6, 0))Mbps" }
    }
    $netList += @{mac=$a.MACAddress; name=$name; type=$typeStr; status=$statusStr; ip=$ip; gateway=$gw; speed=$linkSpd}
}
$info.networks = $netList

# Monitor - EDID优先获取真实型号和尺寸，WMI补充分辨率 (Win7 compatible)
$monList = @()
$monRes = ''; $monHz = ''
$seenHW = @{}

# 首选：注册表EDID读取真实显示器型号和尺寸
# 即使Win32_DesktopMonitor能找到显示器，其Name也往往是"Generic PnP Monitor"
# EDID注册表包含厂商写入的真实型号和物理尺寸
try {
    $displayPath = 'HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY'
    if (Test-Path $displayPath) {
        $displayKeys = Get-ChildItem $displayPath -ErrorAction SilentlyContinue
        foreach ($devKey in $displayKeys) {
            $instKeys = Get-ChildItem $devKey.PSPath -ErrorAction SilentlyContinue
            foreach ($instKey in $instKeys) {
                $paramKey = Get-ChildItem $instKey.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq 'Device Parameters' }
                if (-not $paramKey) { continue }
                $edid = $paramKey.GetValue('EDID')
                if (-not $edid -or $edid.Length -lt 128) { continue }
                $hwId = $devKey.PSChildName
                if ($hwId -eq 'Default_Monitor' -or $seenHW.ContainsKey($hwId)) { continue }
                $seenHW[$hwId] = $true
                # 从EDID descriptor blocks提取型号名称 (type 0xFC = Monitor name)
                $mName = ''
                for ($b = 0; $b -lt 4; $b++) {
                    $off = 54 + $b * 18
                    if ($edid[$off] -eq 0 -and $edid[$off+1] -eq 0 -and $edid[$off+3] -eq 0xFC) {
                        $nameBytes = $edid[($off+5)..($off+17)]
                        $mName = [Text.Encoding]::ASCII.GetString($nameBytes).Trim() -replace '\x00', '' -replace '\x0a', ''
                        break
                    }
                }
                # 若0xFC无内容，尝试0xFE描述符 (Unspecified text，有时厂商会写型号)
                if (-not $mName) {
                    for ($b = 0; $b -lt 4; $b++) {
                        $off = 54 + $b * 18
                        if ($edid[$off] -eq 0 -and $edid[$off+1] -eq 0 -and $edid[$off+3] -eq 0xFE) {
                            $nameBytes = $edid[($off+5)..($off+17)]
                            $mName = [Text.Encoding]::ASCII.GetString($nameBytes).Trim() -replace '\x00', '' -replace '\x0a', ''
                            break
                        }
                    }
                }
                # 回退：注册表中的FriendlyName
                if (-not $mName) {
                    try {
                        $friendlyName = (Get-ItemProperty $instKey.PSPath -Name 'FriendlyName' -ErrorAction SilentlyContinue).FriendlyName
                        if ($friendlyName) { $mName = $friendlyName }
                    } catch {}
                }
                if (-not $mName) { $mName = "Monitor" }
                # 尺寸从EDID物理尺寸字节计算 (字节21=水平cm, 字节22=垂直cm)
                $hCm = $edid[21]; $vCm = $edid[22]
                $mSize = ''
                if ($hCm -gt 0 -and $vCm -gt 0) {
                    $diagIn = [math]::Round([math]::Sqrt($hCm*$hCm + $vCm*$vCm) / 2.54, 1)
                    $mSize = "$($diagIn)in"
                }
                # 若EDID无尺寸，尝试WmiMonitorBasicDisplayParams(root\wmi)补充
                if (-not $mSize) {
                    try {
                        $wmiMon = @(Get-WmiObject -Namespace root\wmi -Class WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue)
                        $wmiIdx = $seenHW.Count - 1
                        if ($wmiIdx -lt $wmiMon.Count) {
                            $wm = $wmiMon[$wmiIdx]
                            if ($wm.MaxHorizontalImageSize -gt 0 -and $wm.MaxVerticalImageSize -gt 0) {
                                $hMm = $wm.MaxHorizontalImageSize; $vMm = $wm.MaxVerticalImageSize
                                $diagIn = [math]::Round([math]::Sqrt($hMm*$hMm + $vMm*$vMm) / 25.4, 1)
                                $mSize = "$($diagIn)in"
                            }
                        }
                    } catch {}
                }
                $monList += @{name=$mName; size=$mSize}
            }
        }
    }
} catch {}

# 如果EDID完全没找到（如虚拟机），回退到WMI Win32_DesktopMonitor（名称可能不准确）
if ($monList.Count -eq 0) {
    try {
        $deskMons = @(Gw Win32_DesktopMonitor | Where-Object { $_.ScreenWidth -gt 0 })
        foreach ($dm in $deskMons) {
            $mName = $dm.Name
            if (-not $mName -or $mName -match 'Generic|Plug and Play|Default') {
                $mName = 'Monitor'
            }
            $mSize = ''
            $monList += @{name=$mName; size=$mSize}
        }
    } catch {}
}

# 分辨率优先从Win32_DesktopMonitor的CurrentHorizontalResolution获取（当前实际分辨率）
try {
    $deskMons = @(Gw Win32_DesktopMonitor | Where-Object { $_.ScreenWidth -gt 0 })
    if ($deskMons.Count -gt 0) {
        $dm = $deskMons[0]
        if ($dm.CurrentHorizontalResolution -gt 0 -and $dm.CurrentVerticalResolution -gt 0) {
            $monRes = "$($dm.CurrentHorizontalResolution) x $($dm.CurrentVerticalResolution)"
        } elseif ($dm.ScreenWidth -gt 0 -and $dm.ScreenHeight -gt 0) {
            $monRes = "$($dm.ScreenWidth) x $($dm.ScreenHeight)"
        }
    }
} catch {}

# 分辨率和刷新率从显卡获取（Win7兼容，当DesktopMonitor未提供时）
foreach ($g in $gpus) {
    if (-not $monRes -and $g.CurrentHorizontalResolution -gt 0) {
        $monRes = "$($g.CurrentHorizontalResolution) x $($g.CurrentVerticalResolution)"
        if ($g.CurrentRefreshRate -gt 0) { $monHz = "$($g.CurrentRefreshRate)Hz" }
    }
}
$info.monitors = $monList
$info.monitor_resolution = $monRes
$info.monitor_refresh = $monHz

# Output as JSON
$info | ConvertTo-Json -Depth 4 -Compress
'''


def collect_system_info():
    """采集本机硬件信息，返回 dict（兼容 Win7/8/10/11）"""
    try:
        proc = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
             "-Command", _PS_INFO_SCRIPT],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
        )
        stdout, stderr = proc.communicate(timeout=45)
        output = stdout.decode("utf-8", errors="replace").strip()
        if output:
            return json.loads(output)
    except Exception as e:
        print(f"[硬件采集] 异常: {e}")
    return None


def _send_system_info(server, token):
    """将硬件信息上报到服务端，静默执行不影响登录"""
    try:
        info = collect_system_info()
        if not info:
            return
        requests.post(
            f"{server}/api/auth/hardware-info",
            json=info,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
    except Exception:
        pass  # 静默失败，不影响用户操作


# ============================================================
# Remote Disk Operations (hide / restore)
# ============================================================

_PS_HIDE_DISKS = r'''
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$tmpFile = "$env:TEMP\mdpart_tmp.txt"
$cfgDir  = Join-Path $env:ProgramData 'MorongDisk'
$cfgPath = Join-Path $cfgDir 'hidden_layout.cfg'
if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir -Force | Out-Null }

# ---- 辅助函数 ----
function Get-DiskPartStyle($diskNum) {
    $sf = "$env:TEMP\mdpart_ds_$diskNum.txt"
    @("select disk $diskNum", "detail disk") | Out-File $sf -Encoding ascii
    $out = (diskpart /s $sf 2>&1) -join "`n"
    Remove-Item $sf -Force -ErrorAction SilentlyContinue
    if ($out -match 'GPT') { return 'GPT' }
    return 'MBR'
}

function Find-PartitionForVolume($diskNum, $volNum) {
    $sf = "$env:TEMP\mdpart_lp_$diskNum.txt"
    @("select disk $diskNum", "list partition") | Out-File $sf -Encoding ascii
    $lpOut = (diskpart /s $sf 2>&1) -join "`n"
    Remove-Item $sf -Force -ErrorAction SilentlyContinue
    $pns = @()
    foreach ($l in ($lpOut -split "`n")) {
        if ($l -match 'Partition\s+(\d+)') { $pns += [int]$Matches[1] }
    }
    foreach ($pn in $pns) {
        $pf = "$env:TEMP\mdpart_dp_${diskNum}_${pn}.txt"
        @("select disk $diskNum", "select partition $pn", "detail partition") | Out-File $pf -Encoding ascii
        $dpOut = (diskpart /s $pf 2>&1) -join "`n"
        Remove-Item $pf -Force -ErrorAction SilentlyContinue
        if ($dpOut -match "Volume\s+$volNum\b") {
            $ptype = ''
            if ($dpOut -match 'Type\s*:\s*(\S+)') { $ptype = $Matches[1]; if ($ptype -match '^\{') { $ptype = $ptype.Trim('{}') } }
            return @{ PartNum=$pn; OrigType=$ptype }
        }
    }
    return $null
}

# ---- 枚举卷 ----
"list volume" | Out-File $tmpFile -Encoding ascii
$dpOut = (diskpart /s $tmpFile 2>&1) -join "`n"
Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

$saved = @()
$processedDisks = @{}

foreach ($line in ($dpOut -split "`n")) {
    if (-not ($line -match '^\s*(Volume|.{1,3})\s+(\d+)')) { continue }
    $vn = $Matches[2]
    if ($line -match '\s([A-Z])\s{2,}') { $ltr = $Matches[1] } else { continue }
    if ($ltr -eq 'C') { continue }
    $lower = $line.ToLower()
    if ($lower -match 'system|boot|removable|cd-rom|dvd') { continue }
    if ($lower -notmatch 'ntfs|fat32|exfat|refs') { continue }

    $sizeGB = 0
    $selFile = "$env:TEMP\mdpart_sel_$vn.txt"
    @("select volume $vn", "detail volume") | Out-File $selFile -Encoding ascii
    $detailOut = (diskpart /s $selFile 2>&1) -join "`n"
    Remove-Item $selFile -Force -ErrorAction SilentlyContinue
    if ($detailOut -match 'Volume Capacity\s*:\s*(\d+)\s*GB') { $sizeGB = [long]$Matches[1] }
    elseif ($detailOut -match 'Volume Capacity\s*:\s*(\d+)\s*MB') { $sizeGB = [math]::Round([long]$Matches[1] / 1024, 0) }
    elseif ($detailOut -match 'Size\s*:\s*(\d+)\s*GB') { $sizeGB = [long]$Matches[1] }
    elseif ($detailOut -match 'Size\s*:\s*(\d+)\s*MB') { $sizeGB = [math]::Round([long]$Matches[1] / 1024, 0) }
    $diskNum = -1
    if ($detailOut -match '\*\s*Disk\s+(\d+)') { $diskNum = [int]$Matches[1] }
    if ($sizeGB -lt 1 -or $diskNum -lt 0) { continue }
    if ($processedDisks.ContainsKey($diskNum)) { continue }
    $processedDisks[$diskNum] = $true

    # 方法1：尝试 offline disk（磁盘管理中显示灰色）
    $offFile = "$env:TEMP\mdpart_off_$diskNum.txt"
    @("select disk $diskNum", "offline disk") | Out-File $offFile -Encoding ascii
    $offOut = (diskpart /s $offFile 2>&1) -join "`n"
    Remove-Item $offFile -Force -ErrorAction SilentlyContinue

    if ($offOut -match 'successfully|成功|is now offline|Offline succeeded') {
        $saved += @{
            DiskNum=$diskNum; Letter=$ltr; VolNum=$vn; SizeGB=$sizeGB
            Method='Offline'
        }
        Write-Output "OFFLINE: Disk=$diskNum [$($ltr):] ${sizeGB}GB - 脱机成功"
        continue
    }

    Write-Output "FALLBACK: Disk=$diskNum offline disk 被拒绝，改用分区类型方案..."

    # 方法2回退：移除盘符 + 修改分区类型
    $partStyle = Get-DiskPartStyle $diskNum
    $partInfo = Find-PartitionForVolume $diskNum $vn
    $partNum = -1; $origType = ''
    if ($partInfo) { $partNum = $partInfo.PartNum; $origType = $partInfo.OrigType }

    # 移除盘符
    $mvResult = mountvol "$($ltr):" /D 2>&1
    if (Test-Path "$($ltr):\") {
        Write-Output "FAIL: [$($ltr):] 移除盘符失败"
        continue
    }

    # 修改分区类型
    $HIDE_GPT_GUID = 'a16abfd5-0179-4d6a-9e4e-4a6e9e18e9e9'
    if ($partNum -ge 0) {
        if ($partStyle -eq 'GPT') {
            $typeCmds = @("select disk $diskNum", "select partition $partNum", "set id={$HIDE_GPT_GUID} override")
        } else {
            $typeCmds = @("select disk $diskNum", "select partition $partNum", "set id=17 override")
        }
        $typeCmds | Out-File $tmpFile -Encoding ascii
        diskpart /s $tmpFile 2>&1 | Out-Null
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    }

    $saved += @{
        DiskNum=$diskNum; Letter=$ltr; VolNum=$vn; SizeGB=$sizeGB
        Method='Partition'; PartStyle=$partStyle; PartNum=$partNum; OrigType=$origType
    }
    Write-Output "HIDDEN: [$($ltr):] Disk=$diskNum ${sizeGB}GB 分区类型已修改 ($partStyle)"
}

if ($saved.Count -eq 0) {
    Write-Output "NO_DISKS: 没有可隐藏的本地磁盘（除C盘外）"
    exit 0
}

# 保存配置
$json = $saved | ConvertTo-Json -Compress
$json | Out-File $cfgPath -Encoding utf8
if (-not (Test-Path $cfgPath)) {
    Write-Output "ERROR: 配置文件写入失败"
    exit 1
}

$stateFile = Join-Path $cfgDir 'disks_hidden'
"hidden" | Out-File $stateFile -Encoding utf8
$offCount = @($saved | Where-Object { $_.Method -eq 'Offline' }).Count
$partCount = @($saved | Where-Object { $_.Method -eq 'Partition' }).Count
$msg = "DONE: $offCount 个磁盘脱机(灰色)"
if ($partCount -gt 0) { $msg += ", $partCount 个磁盘隐藏(分区类型)" }
Write-Output $msg
'''

_PS_RESTORE_DISKS = r'''
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

$tmpFile = "$env:TEMP\mdpart_tmp.txt"
$cfgDir  = Join-Path $env:ProgramData 'MorongDisk'
$cfgPath = Join-Path $cfgDir 'hidden_layout.cfg'

# ---- 获取系统盘编号 ----
$sysDiskNum = 0
try {
    $sysPart = Get-WmiObject Win32_DiskPartition | Where-Object { $_.BootPartition -eq $true } | Select-Object -First 1
    if ($sysPart) { $sysDiskNum = $sysPart.DiskIndex }
} catch {}

$restoredCount = 0

# ---- 从配置文件恢复 ----
if (Test-Path $cfgPath) {
    try {
        $saved = Get-Content $cfgPath -Raw -Encoding utf8 | ConvertFrom-Json
        if ($saved -isnot [System.Array]) { $saved = @($saved) }
    } catch {
        Write-Output "ERROR: 配置文件损坏"
        $saved = $null
    }

    if ($saved) {
        # 阶段1：处理 Offline 方法的磁盘（先联机）
        foreach ($item in $saved) {
            $dn = [int]$item.DiskNum
            if ($dn -eq $sysDiskNum) { continue }
            if ($item.Method -ne 'Offline') { continue }

            $tmpF = "$env:TEMP\mdpart_on_$dn.txt"
            @("select disk $dn", "online disk") | Out-File $tmpF -Encoding ascii
            $out = (diskpart /s $tmpF 2>&1) -join "`n"
            Remove-Item $tmpF -Force -ErrorAction SilentlyContinue

            if ($out -match 'successfully|成功|online') {
                Write-Output "ONLINE: Disk=$dn 已联机"
                $restoredCount++
            } else {
                Write-Output "FAIL: Disk=$dn 联机失败: $out"
            }
        }
        if ($restoredCount -gt 0) { Start-Sleep -Seconds 2 }

        # 阶段2：处理 Partition 方法的磁盘（恢复分区类型 + 分配盘符）
        $needRescan = $false
        foreach ($item in $saved) {
            $dn = [int]$item.DiskNum
            if ($dn -eq $sysDiskNum) { continue }
            if ($item.Method -ne 'Partition') { continue }

            $pn = -1; if ($item.PartNum) { $pn = [int]$item.PartNum }
            $style = ''; if ($item.PartStyle) { $style = $item.PartStyle }
            $origType = ''; if ($item.OrigType) { $origType = $item.OrigType }
            $letter = $item.Letter

            # 恢复分区类型
            if ($pn -ge 0 -and $origType) {
                $idParam = if ($style -eq 'MBR') { $origType } else { "{$origType}" }
                @("select disk $dn", "select partition $pn", "set id=$idParam override") | Out-File $tmpFile -Encoding ascii
                $rOut = (diskpart /s $tmpFile 2>&1) -join "`n"
                Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
                if ($rOut -match 'successfully|成功') { $needRescan = $true }
            }
        }

        if ($needRescan) {
            Start-Sleep -Seconds 3
            "rescan" | Out-File $tmpFile -Encoding ascii
            diskpart /s $tmpFile 2>&1 | Out-Null
            Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }

        # 阶段3：为 Partition 方法的磁盘分配盘符
        "list volume" | Out-File $tmpFile -Encoding ascii
        $dpOut = (diskpart /s $tmpFile 2>&1) -join "`n"
        Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue

        foreach ($item in $saved) {
            if ($item.Method -ne 'Partition') { continue }
            $vn = $item.VolNum; $letter = $item.Letter; $sizeGB = 0
            if ($item.SizeGB) { $sizeGB = [long]$item.SizeGB }

            # 通过卷号或大小匹配找到当前卷
            $realVn = $null
            foreach ($ln in ($dpOut -split "`n")) {
                if (-not ($ln -match '^\s*(Volume|.{1,3})\s+(\d+)')) { continue }
                $vnum = $Matches[2]
                if ($vnum -eq $vn) { $realVn = $vnum; break }
                if ($sizeGB -gt 0) {
                    $curSz = 0
                    if ($ln -match '(\d+)\s*GB') { $curSz = [long]$Matches[1] }
                    if ($curSz -eq $sizeGB -and $ln -notmatch 'system|boot|removable') { $realVn = $vnum; break }
                }
            }

            if ($realVn) {
                @("select volume $realVn", "attributes volume clear hidden") | Out-File $tmpFile -Encoding ascii
                diskpart /s $tmpFile 2>&1 | Out-Null
                @("select volume $realVn", "assign letter=$letter") | Out-File $tmpFile -Encoding ascii
                diskpart /s $tmpFile 2>&1 | Out-Null
                Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3

                if (Test-Path "$($letter):\") {
                    Write-Output "RESTORED: [$($letter):] 已恢复 (Vol=$realVn)"
                    $restoredCount++
                } else {
                    Write-Output "FAIL: [$($letter):] 恢复盘符失败"
                }
            } else {
                Write-Output "FAIL: 无法找到 VolNum=$vn SizeGB=$sizeGB 的卷"
            }
        }
    }
}

# ---- 兜底：扫描脱机磁盘并联机 ----
if ($restoredCount -eq 0) {
    $offlineDisks = Get-WmiObject Win32_DiskDrive | Where-Object {
        $_.Index -ne $sysDiskNum -and $_.Status -ne 'OK'
    }
    foreach ($d in @($offlineDisks)) {
        $dn = $d.Index
        $tmpF = "$env:TEMP\mdpart_on_$dn.txt"
        @("select disk $dn", "online disk") | Out-File $tmpF -Encoding ascii
        $out = (diskpart /s $tmpF 2>&1) -join "`n"
        Remove-Item $tmpF -Force -ErrorAction SilentlyContinue
        if ($out -match 'successfully|成功|online') {
            Write-Output "ONLINE: Disk=$dn 已联机"
            $restoredCount++
        }
    }
}

# 清理状态文件
$stateFile = Join-Path $cfgDir 'disks_hidden'
Remove-Item $stateFile -Force -ErrorAction SilentlyContinue
Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue

if ($restoredCount -gt 0) {
    Write-Output "DONE: $restoredCount 个磁盘已恢复"
    exit 0
} else {
    Write-Output "NO_DISKS: 没有需要恢复的磁盘"
    exit 0
}
'''


def _run_ps_elevated(script, script_file, wrapper_file, out_file, BOM, timeout):
    """ShellExecuteW 提权回退：当直接 Popen 权限不足时使用"""
    try:
        for fp in [out_file, wrapper_file]:
            try:
                os.remove(fp)
            except Exception:
                pass
        wrapper_lines = (
            f'[Console]::OutputEncoding = [Text.Encoding]::UTF8\n'
            f'$OutputEncoding = [Text.Encoding]::UTF8\n'
            f'$ErrorActionPreference = "SilentlyContinue"\n'
            f'$out = & "{script_file}" 2>&1\n'
            f'$ec = $LASTEXITCODE\n'
            f'$text = ($out | Out-String).Trim()\n'
            f'[IO.File]::WriteAllText("{out_file}", '
            f'"$text`nEXITCODE:$ec", [Text.Encoding]::UTF8)\n'
        )
        with open(wrapper_file, "wb") as f:
            f.write(BOM)
            f.write(wrapper_lines.encode("utf-8"))

        cmd_arg = f'/c powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "{wrapper_file}"'
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", cmd_arg, None, 0)
        if ret <= 32:
            return False, f"提权失败 (错误码: {ret})，磁盘操作需要管理员权限"

        for _ in range(timeout):
            time.sleep(1)
            if os.path.exists(out_file):
                try:
                    with open(out_file, "r", encoding="utf-8-sig") as f:
                        content = f.read()
                    if "EXITCODE:" in content:
                        break
                except Exception:
                    pass

        if not os.path.exists(out_file):
            return False, "提权执行超时，未获取到输出"

        with open(out_file, "r", encoding="utf-8-sig") as f:
            content = f.read()
        lines = content.strip().split("\n")
        last_line = lines[-1].strip() if lines else ""
        exit_code = -1
        if last_line.startswith("EXITCODE:"):
            try:
                exit_code = int(last_line.split(":")[1])
            except (ValueError, IndexError):
                pass
            output = "\n".join(lines[:-1]).strip()
        else:
            output = content.strip()

        ok_markers = ("DONE:", "HIDDEN:", "RESTORED:", "NO_DISKS:", "NO_HIDDEN:")
        if any(m in output for m in ok_markers):
            return True, output
        if exit_code == 0 and output:
            return True, output
        return False, output or f"执行失败 (exit_code={exit_code})"
    except Exception as e:
        return False, str(e)


def _run_ps_script(script, elevated=False, timeout=60):
    """执行 PowerShell 脚本，返回 (success, output)
    elevated=True 时优先用直接 Popen（客户端已是管理员），
    若权限不足再回退到 ShellExecuteW 提权
    """
    CNW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
    BOM = b'\xef\xbb\xbf'
    if elevated:
        import tempfile
        pid = os.getpid()
        script_file = os.path.join(tempfile.gettempdir(), f"md_ps_{pid}.ps1")
        out_file = os.path.join(tempfile.gettempdir(), f"md_ps_{pid}_out.txt")
        wrapper_file = os.path.join(tempfile.gettempdir(), f"md_ps_{pid}_w.ps1")
        for fp in [out_file, script_file, wrapper_file]:
            try:
                os.remove(fp)
            except Exception:
                pass
        try:
            with open(script_file, "wb") as f:
                f.write(BOM)
                f.write(script.encode("utf-8"))

            # 方式1：直接 Popen（客户端已是管理员，mountvol 变更在同一进程树中持久化更可靠）
            try:
                proc = subprocess.Popen(
                    ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
                     "-File", script_file],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=CNW)
                stdout, stderr = proc.communicate(timeout=timeout)
                output = (stdout.decode("utf-8", errors="replace") or "") + \
                         (stderr.decode("utf-8", errors="replace") or "")
                output = output.strip()

                # 如果因权限被拒绝，回退到 ShellExecuteW
                if proc.returncode != 0 and ("denied" in output.lower() or
                                              "权限" in output or
                                              "access" in output.lower()):
                    return _run_ps_elevated(script, script_file, wrapper_file,
                                            out_file, BOM, timeout)

                ok_markers = ("DONE:", "HIDDEN:", "RESTORED:", "NO_DISKS:", "NO_HIDDEN:")
                if any(m in output for m in ok_markers):
                    return True, output
                if proc.returncode == 0 and output:
                    return True, output
                return False, output or f"执行失败 (exit_code={proc.returncode})"

            except PermissionError:
                return _run_ps_elevated(script, script_file, wrapper_file,
                                        out_file, BOM, timeout)

        except Exception as e:
            return False, str(e)
        finally:
            for fp in [script_file, wrapper_file, out_file]:
                try:
                    os.remove(fp)
                except Exception:
                    pass
    else:
        # 非提权模式：直接执行
        try:
            proc = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "RemoteSigned", "-Command", script],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=CNW
            )
            stdout, stderr = proc.communicate(timeout=timeout)
            output = (stdout.decode("utf-8", errors="replace") or "") + \
                     (stderr.decode("utf-8", errors="replace") or "")
            return proc.returncode == 0, output.strip()
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass
            return False, f"执行超时 ({timeout}s)"
        except Exception as e:
            return False, str(e)


def hide_disks():
    """使所有非系统盘脱机（diskpart offline disk），磁盘管理中显示灰色"""
    return _run_ps_script(_PS_HIDE_DISKS, elevated=True)


def restore_disks():
    """使所有脱机的磁盘联机（diskpart online disk），恢复正常显示"""
    return _run_ps_script(_PS_RESTORE_DISKS, elevated=True)


# ============================================================
# Remote Commands (one-time fetch at login)
# ============================================================

def fetch_and_execute_commands(server, username, password, token=None):
    """登录时一次性拉取并执行待处理的远程命令，不再轮询
    返回值: dict, 包含 remount (bool) 等信号"""
    result = {"remount": False}
    try:
        if not token:
            enc_pwd, encrypted = _rsa_encrypt_password(server, password)
            r = requests.post(
                f"{server}/api/auth/login",
                json={"username": username, "password": enc_pwd, "encrypted": encrypted},
                timeout=10
            )
            if r.status_code != 200:
                return result
            data = r.json()
            if not data.get("success"):
                return result
            token = data.get("token", "")
            if not token:
                return result

        # 心跳上报（含磁盘隐藏状态），并检查是否需要重新挂载
        try:
            _cfg_dir_hb = os.path.join(
                os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "MorongDisk")
            _disk_hidden = os.path.exists(os.path.join(_cfg_dir_hb, "disks_hidden"))
            hb_resp = requests.post(
                f"{server}/api/auth/heartbeat",
                headers={"Authorization": f"Bearer {token}"},
                json={"disk_hidden": _disk_hidden},
                timeout=5
            )
            if hb_resp.status_code == 200:
                hb_data = hb_resp.json()
                if hb_data.get("remount"):
                    result["remount"] = True
        except Exception:
            pass

        # 拉取待执行命令
        r = requests.get(
            f"{server}/api/auth/commands",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        if r.status_code != 200:
            return result
        commands = r.json()
        if not isinstance(commands, list):
            return result

        for cmd in commands:
            cmd_id = cmd.get("id")
            cmd_type = cmd.get("command_type", "")
            if not cmd_id or not cmd_type:
                continue

            # 上报执行中
            _report_cmd_result(server, token, cmd_id, "executing", "正在执行...")

            # 检查本地当前磁盘隐藏状态，避免重复操作
            _cfg_dir_cmd = os.path.join(
                os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "MorongDisk")
            _currently_hidden = os.path.exists(os.path.join(_cfg_dir_cmd, "disks_hidden"))

            # 执行命令（仅在状态不同时才执行）
            if cmd_type == "hide_disks":
                if _currently_hidden:
                    ok, output = True, "磁盘已处于脱机状态，无需重复操作"
                else:
                    ok, output = hide_disks()
            elif cmd_type == "restore_disks":
                if not _currently_hidden:
                    ok, output = True, "磁盘已处于联机状态，无需重复操作"
                else:
                    ok, output = restore_disks()
            else:
                ok, output = False, f"未知命令类型: {cmd_type}"

            # 上报结果
            status = "done" if ok else "failed"
            _report_cmd_result(server, token, cmd_id, status, output)
            print(f"[Commands] {cmd_type} 执行{'成功' if ok else '失败'}: {output[:100]}")

            # 命令执行后立即重新检测磁盘状态并上报心跳
            try:
                _cfg_dir_hb = os.path.join(
                    os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "MorongDisk")
                _disk_hidden = os.path.exists(os.path.join(_cfg_dir_hb, "disks_hidden"))
                requests.post(
                    f"{server}/api/auth/heartbeat",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"disk_hidden": _disk_hidden},
                    timeout=5
                )
            except Exception:
                pass

        return result

    except Exception as e:
        print(f"[Commands] 获取/执行命令异常: {e}")
        return result


def _report_cmd_result(server, token, cmd_id, status, result):
    """上报命令执行结果"""
    try:
        requests.post(
            f"{server}/api/auth/commands/{cmd_id}/result",
            json={"status": status, "result": result},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
    except Exception:
        pass


def _get_ignored_versions():
    """获取已忽略的版本列表（存储在本地配置文件旁）"""
    try:
        path = os.path.join(DATA_DIR, "ignored_versions.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _ignore_version(version):
    """记录忽略的版本"""
    try:
        path = os.path.join(DATA_DIR, "ignored_versions.json")
        ignored = _get_ignored_versions()
        ignored[version] = time.time()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ignored, f)
    except Exception:
        pass


def _is_version_ignored(version):
    """检查版本是否已被忽略（忽略7天内不再提示）"""
    ignored = _get_ignored_versions()
    ts = ignored.get(version, 0)
    if ts and time.time() - ts < 7 * 86400:
        return True
    return False


def check_and_apply_update(server):
    """检查并应用客户端更新：先询问用户，确认后再下载替换"""
    if not IS_FROZEN:
        return  # 仅打包后的 exe 支持自动更新
    try:
        r = requests.get(
            f"{server}/api/auth/check-update?type=client&current_version={CLIENT_VERSION}",
            timeout=10
        )
        if r.status_code != 200:
            return
        info = r.json()
        if not info.get("update"):
            return
        new_version = info.get("version", "")
        if not new_version:
            return
        try:
            _cur = tuple(int(x) for x in CLIENT_VERSION.split("."))
            _new = tuple(int(x) for x in new_version.split("."))
            if _new <= _cur:
                return
        except (ValueError, IndexError):
            if new_version == CLIENT_VERSION:
                return
            return

        download_url = info.get("download_url", "")
        filename = info.get("filename", "")
        changelog = info.get("changelog", "")
        expected_sha256 = info.get("sha256", "")
        if not download_url or not filename:
            return
        if not download_url.startswith("/"):
            print(f"[Update] 拒绝非本站下载地址: {download_url}")
            return
        if "//" in download_url:
            print(f"[Update] 拒绝可疑下载地址: {download_url}")
            return

        print(f"[Update] 发现新版本: {new_version} (当前: {CLIENT_VERSION})")
        if changelog:
            print(f"[Update] 更新内容: {changelog}")

        # 检查是否已忽略此版本
        if _is_version_ignored(new_version):
            print(f"[Update] 版本 {new_version} 已被用户忽略，跳过提示")
            return

        # 非静默模式：弹窗询问用户是否更新
        is_silent = "--auto" in sys.argv or "--silent" in sys.argv
        if not is_silent:
            MB_YESNO = 0x00000004
            MB_ICONQUESTION = 0x00000020
            MB_TOPMOST = 0x00040000
            IDYES = 6
            try:
                result = ctypes.windll.user32.MessageBoxW(
                    0,
                    f"发现新版本 {new_version}（当前 {CLIENT_VERSION}），是否立即更新？\n\n"
                    + (f"更新内容：{changelog}\n\n" if changelog else "")
                    + "点击“是”将自动下载并重启程序。",
                    "MorongDisk 更新",
                    MB_YESNO | MB_ICONQUESTION | MB_TOPMOST
                )
                if result != IDYES:
                    print(f"[Update] 用户选择暂不更新")
                    _ignore_version(new_version)
                    return
            except Exception:
                pass

        # 用户确认后，开始下载新版本
        current_exe = sys.executable
        temp_dir = os.environ.get("TEMP", os.path.dirname(current_exe))
        new_exe_path = os.path.join(temp_dir, filename)

        full_url = f"{server}{download_url}" if download_url.startswith("/") else download_url
        print(f"[Update] 开始下载: {full_url}")
        r = requests.get(full_url, timeout=120, stream=True)
        if r.status_code != 200:
            print(f"[Update] 下载失败: HTTP {r.status_code}")
            if not is_silent:
                ctypes.windll.user32.MessageBoxW(
                    0, f"更新下载失败 (HTTP {r.status_code})，请稍后重试。",
                    "MorongDisk 更新", 0x00000010 | 0x00040000
                )
            return

        total_size = 0
        with open(new_exe_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total_size += len(chunk)

        if not os.path.exists(new_exe_path) or os.path.getsize(new_exe_path) < 1024:
            print("[Update] 下载文件异常")
            if not is_silent:
                ctypes.windll.user32.MessageBoxW(
                    0, "更新文件下载异常，请稍后重试。",
                    "MorongDisk 更新", 0x00000010 | 0x00040000
                )
            return

        # SHA256 完整性校验
        if expected_sha256:
            import hashlib
            sha256 = hashlib.sha256()
            with open(new_exe_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            actual_sha256 = sha256.hexdigest()
            if actual_sha256 != expected_sha256:
                print(f"[Update] SHA256 校验失败: 期望 {expected_sha256}, 实际 {actual_sha256}")
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                if not is_silent:
                    ctypes.windll.user32.MessageBoxW(
                        0, "更新文件校验失败，文件可能被篡改，已取消更新。",
                        "MorongDisk 更新", 0x00000010 | 0x00040000
                    )
                return
            print(f"[Update] SHA256 校验通过")

        print(f"[Update] 下载完成: {new_exe_path} ({total_size} bytes)")

        # 下载成功，通知用户即将重启
        if not is_silent:
            ctypes.windll.user32.MessageBoxW(
                0,
                f"新版本 {new_version} 已下载完成，程序将自动重启以应用更新。",
                "MorongDisk 更新",
                0x00000000 | 0x00000040 | 0x00040000
            )

        # 创建替换脚本（bat），在当前进程退出后替换 exe 并重启
        bat_path = os.path.join(temp_dir, "morong_update.bat")
        _esc_exe = current_exe.replace("^", "^^").replace("&", "^&").replace("|", "^|").replace("<", "^<").replace(">", "^>").replace("(", "^(").replace(")", "^)")
        _esc_new = new_exe_path.replace("^", "^^").replace("&", "^&").replace("|", "^|").replace("<", "^<").replace(">", "^>").replace("(", "^(").replace(")", "^)")
        _esc_basename = os.path.basename(current_exe).replace("^", "^^").replace("&", "^&").replace("|", "^|").replace("<", "^<").replace(">", "^>").replace("(", "^(").replace(")", "^)")
        bat_content = f"""@echo off
:: 等待旧进程完全退出（通过尝试重命名 exe 文件来判断锁是否释放）
set WAIT_COUNT=0
:WAIT_LOOP
timeout /t 1 /nobreak >nul
ren "{_esc_exe}" _update_test_9x8z_ >nul 2>&1 && (ren _update_test_9x8z_ "{_esc_basename}" >nul 2>&1 & goto COPY_STEP)
set /a WAIT_COUNT+=1
if %WAIT_COUNT% LSS 15 goto WAIT_LOOP

:COPY_STEP
:: 替换 exe 文件
set RETRY=0
:RETRY_LOOP
copy /y "{_esc_new}" "{_esc_exe}" >nul 2>&1
if %errorlevel%==0 goto SUCCESS
set /a RETRY+=1
if %RETRY% LSS 5 (
    timeout /t 2 /nobreak >nul
    goto RETRY_LOOP
)
echo Update failed after 5 retries
del "{_esc_new}" 2>nul
del "%~f0"
exit /b 1

:SUCCESS
:: 清理旧的 rclone 挂载，避免新客户端挂载冲突
taskkill /f /im rclone.exe >nul 2>&1
for %%d in (Z Y X W V U T S R Q P O N M L K J I H G F E D) do net use %%d: /delete /y >nul 2>&1
timeout /t 2 /nobreak >nul

:: 启动新版本
start "" "{_esc_exe}" --auto
del "{_esc_new}" 2>nul
del "%~f0"
"""
        with open(bat_path, "w", encoding="gbk") as f:
            f.write(bat_content)

        # 启动替换脚本并退出当前进程
        subprocess.Popen(
            ["cmd.exe", "/c", bat_path],
            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
        )
        print("[Update] 更新脚本已启动，正在重启...")
        try:
            _kill_own_rclone()
        except Exception:
            pass
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass
        os._exit(0)

    except Exception as e:
        print(f"[Update] 更新检查异常: {e}")


# 文件日志相关函数... (already inserted above)

# ============================================================
# Z盘文件操作日志监控 (watchdog文件事件 + Recent打开追踪 + 剪贴板复制追踪)
# ============================================================

_file_log_queue = queue.Queue()
_file_log_observer = None
_all_file_log_observers = []
_toast_queue = queue.Queue()
_toast_root = None


def _show_notification_toast(parent, title, content, duration=5):
    """右下角通知弹窗，与首次登录成功弹窗风格一致"""
    try:
        popup = tk.Toplevel(parent)
        popup.overrideredirect(True)
        popup.attributes("-topmost", True)
        popup.configure(bg=C_CARD)
        popup.update_idletasks()
        w, h = 320, 140
        sw = popup.winfo_screenwidth()
        sh = popup.winfo_screenheight()
        x = sw - w - 16
        y = sh - h - 60
        popup.geometry(f"{w}x{h}+{x}+{y}")

        top_frame = tk.Frame(popup, bg=C_CARD)
        top_frame.pack(fill="x")
        tk.Label(top_frame, text="MORONG", bg=C_CARD, fg=C_PRIMARY,
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=(16, 0), pady=(12, 0))
        close_lbl = tk.Label(top_frame, text=" \u2716 ", bg=C_CARD, fg="#94A3B8",
                             font=("Segoe UI", 10), cursor="hand2")
        close_lbl.pack(side="right", padx=(0, 8), pady=(12, 0))
        close_lbl.bind("<Button-1>", lambda e: popup.destroy() if popup.winfo_exists() else None)

        tk.Label(popup, text=title, bg=C_CARD, fg="#1E293B",
                 font=("Microsoft YaHei UI", 10, "bold"), anchor="w").pack(fill="x", padx=(16, 16), pady=(4, 0))
        tk.Label(popup, text=content[:80], bg=C_CARD, fg="#475569",
                 font=("Microsoft YaHei UI", 9), anchor="w", wraplength=280, justify="left").pack(fill="x", padx=(16, 16), pady=(2, 12))

        duration_ms = max(1000, int(duration) * 1000)
        popup.after(duration_ms, lambda: popup.destroy() if popup.winfo_exists() else None)
    except Exception:
        pass



def _get_clipboard_files():
    """获取剪贴板中的文件路径列表（使用 tkinter 替代 ctypes API，避免杀软误报）"""
    try:
        import tkinter as _tk
        tmp_root = _tk._default_root or _tk.Tk()
        tmp_root.withdraw()
        clip_text = tmp_root.clipboard_get()
        lines = clip_text.strip().split('\n')
        files = []
        for line in lines:
            line = line.strip()
            if line and len(line) > 2 and line[1] == ':' and os.path.exists(line):
                files.append(line)
        return files
    except Exception:
        return []


def _resolve_lnk_target(lnk_path, drive_letter):
    """快速读取 .lnk 二进制内容，搜索目标盘符路径"""
    try:
        with open(lnk_path, 'rb') as f:
            data = f.read(8192)
        marker = f'{drive_letter}:\\'.encode('utf-16-le')
        idx = data.find(marker)
        if idx < 0:
            return None
        end = data.find(b'\x00\x00', idx + 6)
        if end < 0:
            end = min(idx + 520, len(data))
        path = data[idx:end].decode('utf-16-le', errors='ignore').rstrip('\x00')
        return path if len(path) > 3 else None
    except Exception:
        return None


class ZDriveLogHandler(FileSystemEventHandler):
    """Z盘文件系统事件：新建、修改、删除、重命名、移动出"""
    def __init__(self, log_queue, drive_letter='Z'):
        self._queue = log_queue
        self._drive = drive_letter.upper()
        self._start_time = time.time()
        self._last_mod = {}
        self._cooldown = 45
        self._initial_snapshot = set()
        try:
            root = drive_letter + ":\\"
            if os.path.isdir(root):
                for item in os.listdir(root):
                    self._initial_snapshot.add(os.path.join(root, item))
        except Exception:
            pass

    def _get_size(self, path):
        try:
            if path and os.path.isfile(path):
                return os.path.getsize(path)
        except Exception:
            pass
        return 0

    def _push(self, event_type, src, dest="", is_dir=False, file_size=0):
        self._queue.put({
            "event_type": event_type, "path": src,
            "dest_path": dest or "", "is_dir": is_dir,
            "file_size": file_size, "timestamp": time.time(),
            "drive_letter": self._drive
        })
        if self._queue.qsize() > 2000:
            try: self._queue.get_nowait()
            except queue.Empty: pass

    def on_any_event(self, event):
        if event.is_directory and event.event_type != 'moved':
            return
        et = event.event_type
        src = event.src_path
        dest = getattr(event, 'dest_path', None)
        now = time.time()

        if now - self._start_time < self._cooldown and et in ('created', 'modified'):
            return

        # 修改事件：30秒内同文件去重
        if et == 'modified':
            last = self._last_mod.get(src)
            if last and now - last['time'] < 30:
                return  # 30秒内已记录过此文件的修改
            sz = self._get_size(src)
            self._last_mod[src] = {'time': now, 'size': sz}
            if len(self._last_mod) > 500:
                self._last_mod = {k: v for k, v in self._last_mod.items() if now - v['time'] < 60}
            self._push('修改', src, is_dir=False, file_size=sz)
            return

        # 删除事件
        if et == 'deleted':
            self._push('删除', src, is_dir=event.is_directory)

            return

        # 创建事件
        if et == 'created':
            sz = self._get_size(src) if not event.is_directory else 0
            self._push('新建', src, is_dir=event.is_directory, file_size=sz)
            return

        # 移动事件：获取目标路径大小（源路径已不存在）
        if et == 'moved':
            if dest and len(dest) > 1 and dest[0].upper() != self._drive:
                cn = '移动出'
            else:
                cn = '重命名'
            sz = self._get_size(dest) if not event.is_directory else 0
            self._push(cn, src, dest=dest or "", is_dir=event.is_directory, file_size=sz)
            return

        return


class RecentFolderHandler(FileSystemEventHandler):
    """监控 Recent 文件夹，追踪用户打开Z盘文件的操作"""
    def __init__(self, log_queue, drive_letter='Z'):
        self._queue = log_queue
        self._drive = drive_letter.upper()
        self._seen = set()

    def on_created(self, event):
        self._check(event.src_path)
    def on_modified(self, event):
        self._check(event.src_path)

    def _check(self, lnk_path):
        if not lnk_path.lower().endswith('.lnk'):
            return
        if lnk_path in self._seen:
            return
        self._seen.add(lnk_path)
        if len(self._seen) > 200:
            recent = list(self._seen)
            self._seen = set(recent[-100:])
        target = _resolve_lnk_target(lnk_path, self._drive)
        if target:
            sz = 0
            try:
                if os.path.isfile(target):
                    sz = os.path.getsize(target)
            except Exception:
                pass
            self._queue.put({
                "event_type": "打开", "path": target,
                "dest_path": "", "is_dir": False, "file_size": sz,
                "timestamp": time.time()
            })


def _clipboard_monitor(log_queue, drive_letter, stop_event):
    """后台线程：监控剪贴板，追踪用户复制Z盘文件"""
    last_sig = ""
    while not stop_event.is_set():
        try:
            files = _get_clipboard_files()
            z_files = [f for f in files if len(f) > 1 and f[0].upper() == drive_letter.upper()]
            if z_files:
                sig = "|".join(sorted(z_files))
                if sig != last_sig:
                    last_sig = sig
                    for f in z_files:
                        sz = 0
                        try:
                            if os.path.isfile(f):
                                sz = os.path.getsize(f)
                        except Exception:
                            pass
                        log_queue.put({
                            "event_type": "复制", "path": f,
                            "dest_path": "", "is_dir": False, "file_size": sz,
                            "timestamp": time.time()
                        })
            else:
                last_sig = ""
        except Exception:
            pass
        stop_event.wait(2.0)


def start_file_log_monitor(drive_path, log_queue):
    drive_letter = 'Z'
    if len(drive_path) >= 2 and drive_path[1] == ':':
        drive_letter = drive_path[0].upper()
    elif not drive_path:
        return None

    monitors = {'zdrive': None, 'recent': None, 'clip_thread': None, 'stop_evt': threading.Event()}

    # 1. Z盘文件系统事件
    if HAS_WATCHDOG and PollingObserver is not None:
        try:
            obs = PollingObserver(timeout=5.0)
            obs.schedule(ZDriveLogHandler(log_queue, drive_letter), drive_path, recursive=True)
            obs.start()
            monitors['zdrive'] = obs
            print(f"[FileLog] Z盘文件监控已启动: {drive_path}")
        except Exception as e:
            print(f"[FileLog] Z盘监控启动失败: {e}")

        # 2. Recent 文件夹 → 打开追踪
        try:
            recent_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Recent')
            if os.path.isdir(recent_dir):
                robs = PollingObserver(timeout=3.0)
                robs.schedule(RecentFolderHandler(log_queue, drive_letter), recent_dir, recursive=False)
                robs.start()
                monitors['recent'] = robs
                print(f"[FileLog] Recent文件夹监控已启动")
        except Exception as e:
            print(f"[FileLog] Recent监控启动失败: {e}")
    else:
        print("[FileLog] watchdog 未安装，跳过文件系统监控")

    # 3. 剪贴板 → 复制追踪
    try:
        monitors['clip_thread'] = threading.Thread(
            target=_clipboard_monitor,
            args=(log_queue, drive_letter, monitors['stop_evt']),
            daemon=True, name="clipboard-mon")
        monitors['clip_thread'].start()
        print("[FileLog] 剪贴板监控已启动")
    except Exception as e:
        print(f"[FileLog] 剪贴板监控启动失败: {e}")

    if monitors['zdrive'] or monitors['recent'] or monitors['clip_thread']:
        return monitors
    return None


def stop_file_log_monitor(monitors):
    """停止所有文件监控"""
    if not monitors:
        return
    if isinstance(monitors, dict):
        for key in ('zdrive', 'recent'):
            obs = monitors.get(key)
            if obs:
                try:
                    obs.stop()
                    obs.join(timeout=5)
                except Exception:
                    pass
        if monitors.get('stop_evt'):
            monitors['stop_evt'].set()
        if monitors.get('clip_thread'):
            monitors['clip_thread'].join(timeout=3)
    elif monitors:
        try:
            monitors.stop()
            monitors.join(timeout=5)
        except Exception:
            pass
    print("[FileLog] 文件监控已全部停止")


_file_log_uploader_stop = None

def _file_log_uploader(server, username, token, log_queue, stop_event):
    while not stop_event.is_set():
        stop_event.wait(5)
        batch = []
        while not log_queue.empty() and len(batch) < 200:
            try:
                batch.append(log_queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            try:
                r = requests.post(
                    f"{server}/api/auth/file-log",
                    json={"logs": batch},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=15
                )
                if r.status_code == 401:
                    token = _refresh_file_log_token(server, username)
            except Exception:
                pass


def _refresh_file_log_token(server, username):
    try:
        config = load_config()
        pwd = config.get("password", "")
        if not pwd:
            return ""
        enc_pwd, encrypted = _rsa_encrypt_password(server, pwd)
        r = requests.post(
            f"{server}/api/auth/login",
            json={"username": username, "password": enc_pwd, "encrypted": encrypted},
            timeout=10
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("success"):
                return d.get("token", "")
    except Exception:
        pass
    return ""


# ============================================================
# Drive UI & Shortcuts

def setup_drive_ui(drive, label):
    letter = sanitize_drive_letter(drive).rstrip(":")
    safe_label = sanitize_label(label)
    CNW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
    try:
        subprocess.Popen(
            ["reg", "add",
             f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{letter}\\DefaultIcon",
             "/ve", "/t", "REG_SZ", "/d", "C:\\Windows\\System32\\imageres.dll,27", "/f"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CNW).communicate(timeout=5)
        subprocess.Popen(
            ["reg", "add",
             f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{letter}\\DefaultLabel",
             "/ve", "/t", "REG_SZ", "/d", safe_label, "/f"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CNW).communicate(timeout=5)
    except Exception:
        pass
    try:
        esc_label = safe_label.replace("'", "''")
        ps_cmd = (
            f"$v = Get-WmiObject Win32_LogicalDisk -Filter \"DeviceID='{letter}:'\";"
            f"if ($v) {{ $v.VolumeName = '{esc_label}'; $v.Put() | Out-Null }}"
        )
        subprocess.Popen(
            ["powershell", "-Command", ps_cmd],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CNW).communicate(timeout=10)
    except Exception:
        pass
    try:
        zone_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
            rf"Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Ranges\MorongDisk_{letter}")
        winreg.SetValueEx(zone_key, ":Range", 0, winreg.REG_SZ, f"{letter}:")
        winreg.SetValueEx(zone_key, "file", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(zone_key)
    except Exception:
        pass



def setup_sendto(drive, label):
    safe_label = sanitize_label(label)
    drive = sanitize_drive_letter(drive)
    sendto = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "SendTo",
        f"{safe_label} ({drive.rstrip(':')}).lnk")
    if not os.path.exists(sendto):
        try:
            import pythoncom
            from win32com.shell import shell, shellcon
            shortcut = pythoncom.CoCreateInstance(
                shell.CLSID_ShellLink, None,
                pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IShellLink)
            shortcut.SetPath(drive)
            persist = shortcut.QueryInterface(pythoncom.IID_IPersistFile)
            persist.Save(sendto, 0)
        except Exception:
            try:
                vbs_path = os.path.join(DATA_DIR, "_shortcut.vbs")
                with open(vbs_path, "w", encoding="gbk") as f:
                    f.write(f'Set ws=CreateObject("WScript.Shell")\n'
                            f'Set sc=ws.CreateShortcut("{sendto}")\n'
                            f'sc.TargetPath="{drive}"\nsc.Save\n')
                subprocess.Popen(["cscript.exe", "//Nologo", vbs_path],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)).communicate(timeout=10)
                try:
                    os.remove(vbs_path)
                except Exception:
                    pass
            except Exception:
                pass


_TASK_NAME = "MorongDiskAutoStart"


def _launcher_vbs_path():
    return os.path.join(
        os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else BASE_DIR,
        "MorongDiskLauncher.vbs")


def _create_launcher_vbs(exe_path):
    vbs = _launcher_vbs_path()
    with open(vbs, "w", encoding="gbk") as f:
        f.write(
            'On Error Resume Next\n'
            'Set ws = CreateObject("WScript.Shell")\n'
            'If WScript.Arguments.Count > 0 Then\n'
            '  arg = WScript.Arguments(0)\n'
            'Else\n'
            '  arg = ""\n'
            'End If\n'
            'If arg = "--auto" Or arg = "--silent" Then\n'
            f'  WScript.Sleep 15000\n'
            'End If\n'
            f'ws.Run """{exe_path}""" & " " & arg, 0, False\n')
    return vbs


def _startup_lnk_path():
    return os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
        "MorongDisk.lnk")


def _create_startup_lnk(exe_path):
    try:
        lnk = _startup_lnk_path()
        vbs_path = os.path.join(tempfile.gettempdir(), "morong_lnk.vbs")
        with open(vbs_path, "w", encoding="gbk") as f:
            f.write(
                f'Set s = CreateObject("WScript.Shell").CreateShortcut("{lnk}")\n'
                f's.TargetPath = "{exe_path}"\n'
                f's.Arguments = "--auto"\n'
                f's.WorkingDirectory = "{os.path.dirname(exe_path)}"\n'
                f's.Description = "MorongDisk Auto Start"\n'
                f's.Save\n')
        subprocess.Popen(
            ["wscript", "//nologo", vbs_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=0x08000000).communicate(timeout=10)
        try:
            os.remove(vbs_path)
        except Exception:
            pass
        return os.path.exists(lnk)
    except Exception:
        return False


def is_autostart_enabled():
    try:
        r = subprocess.run(
            ["schtasks", "/query", "/tn", _TASK_NAME, "/fo", "list"],
            capture_output=True, creationflags=0x08000000)
        if r.returncode == 0:
            return True
    except Exception:
        pass
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, "MorongDisk")
        winreg.CloseKey(key)
        return True
    except Exception:
        pass
    return os.path.exists(_startup_lnk_path())


def setup_autostart(exe_path):
    vbs = _create_launcher_vbs(exe_path)
    ok = False
    try:
        xml = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<RegistrationInfo>'
            f'<Description>MorongDisk Auto Start</Description>'
            '</RegistrationInfo>'
            '<Triggers><LogonTrigger><Enabled>true</Enabled>'
            '<Delay>PT30S</Delay>'
            '</LogonTrigger></Triggers>'
            '<Principals><Principal><LogonType>InteractiveToken</LogonType>'
            '<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>'
            '<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
            '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
            '<AllowHardTerminate>false</AllowHardTerminate>'
            '<StartWhenAvailable>true</StartWhenAvailable>'
            '<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'
            '<AllowStartOnDemand>true</AllowStartOnDemand>'
            '<Enabled>true</Enabled><Hidden>true</Hidden>'
            '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>'
            '<RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>'
            '</Settings>'
            f'<Actions><Exec><Command>wscript.exe</Command><Arguments>"{vbs}" --auto</Arguments>'
            f'<WorkingDirectory>{os.path.dirname(exe_path)}</WorkingDirectory></Exec></Actions>'
            '</Task>'
        )
        tmp_xml = os.path.join(tempfile.gettempdir(), "morong_autostart.xml")
        with open(tmp_xml, "w", encoding="utf-16") as f:
            f.write(xml)
        r = subprocess.run(
            ["schtasks", "/create", "/tn", _TASK_NAME, "/xml", tmp_xml, "/f"],
            capture_output=True, creationflags=0x08000000)
        try:
            os.remove(tmp_xml)
        except Exception:
            pass
        if r.returncode == 0:
            print("[AutoStart] 方案1: 任务计划(VBS)已创建")
            remove_autostart_registry()
            _remove_startup_lnk()
            ok = True
            return
        print(f"[AutoStart] 方案1失败(rc={r.returncode})")
    except Exception as e:
        print(f"[AutoStart] 方案1异常: {e}")

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "MorongDisk", 0, winreg.REG_SZ,
                          f'wscript.exe "{vbs}" --auto')
        winreg.CloseKey(key)
        print("[AutoStart] 方案2: 注册表Run(VBS)已创建")
        _remove_startup_lnk()
        ok = True
        return
    except Exception as e:
        print(f"[AutoStart] 方案2失败: {e}")

    try:
        lnk = _startup_lnk_path()
        tmp_vbs = os.path.join(tempfile.gettempdir(), "morong_lnk.vbs")
        with open(tmp_vbs, "w", encoding="gbk") as f:
            f.write(
                f'Set s = CreateObject("WScript.Shell").CreateShortcut("{lnk}")\n'
                f's.TargetPath = "wscript.exe"\n'
                f's.Arguments = """{vbs}"" --auto"\n'
                f's.WorkingDirectory = "{os.path.dirname(exe_path)}"\n'
                f's.Description = "MorongDisk Auto Start"\n'
                f's.Save\n')
        subprocess.Popen(
            ["wscript", "//nologo", tmp_vbs],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=0x08000000).communicate(timeout=10)
        try:
            os.remove(tmp_vbs)
        except Exception:
            pass
        if os.path.exists(lnk):
            print("[AutoStart] 方案3: 启动文件夹快捷方式(VBS)已创建")
            ok = True
        else:
            print("[AutoStart] 方案3失败")
    except Exception as e:
        print(f"[AutoStart] 方案3异常: {e}")

    if not ok:
        print("[AutoStart] 所有方案均失败")


def remove_autostart_registry():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "MorongDisk")
        winreg.CloseKey(key)
    except Exception:
        pass


def _remove_startup_lnk():
    lnk = _startup_lnk_path()
    if os.path.exists(lnk):
        try:
            os.remove(lnk)
        except Exception:
            pass


def remove_autostart():
    try:
        subprocess.run(
            ["schtasks", "/delete", "/tn", _TASK_NAME, "/f"],
            capture_output=True, creationflags=0x08000000)
    except Exception:
        pass
    remove_autostart_registry()
    _remove_startup_lnk()
    vbs_path = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "Start Menu", "Programs", "Startup",
        "AutoMount_Morong.vbs")
    if os.path.exists(vbs_path):
        try:
            os.remove(vbs_path)
        except Exception:
            pass


def unmount(drive):
    drive = sanitize_drive_letter(drive)
    try:
        subprocess.Popen(
            ["net", "use", drive, "/delete", "/y"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
        ).communicate(timeout=5)
    except Exception:
        pass
    _kill_own_rclone(drive)


def thorough_unmount(drive, label, remove_autostart_flag=True):
    """彻底卸载：断开连接、杀进程、清理注册表、删快捷方式、删自启"""
    drive = sanitize_drive_letter(drive)
    letter = drive.rstrip(":")
    safe_label = sanitize_label(label)
    CNW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

    def _quiet_run(cmd):
        try:
            subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=CNW).communicate(timeout=5)
        except Exception:
            pass

    # 1. 断开网络驱动器
    _quiet_run(["net", "use", drive, "/delete", "/y"])

    # 2. 杀 rclone 进程
    _kill_own_rclone(drive)

    # 3. 清理驱动器图标注册表
    _quiet_run(["reg", "delete",
                f"HKCU\\Software\\Classes\\Applications\\explorer.exe\\Drives\\{letter}",
                "/f"])
    _quiet_run(["reg", "delete",
                f"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons\\{letter}",
                "/f"])

    # 4. 删除 SendTo 快捷方式
    sendto = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "SendTo",
        f"{safe_label} ({letter}).lnk")
    if os.path.exists(sendto):
        try:
            os.remove(sendto)
        except Exception:
            pass

    # 5. 更新 PID 文件（仅删除当前盘符条目）
    try:
        if os.path.exists(PID_FILE):
            with open(PID_FILE, "r") as f:
                pid_data = json.load(f)
            pid_data.pop(drive.upper(), None)
            if pid_data:
                with open(PID_FILE, "w") as f:
                    json.dump(pid_data, f)
            else:
                os.remove(PID_FILE)
    except Exception:
        pass

    # 6. 删除开机自启（仅当 remove_autostart_flag=True 时）
    if remove_autostart_flag:
        remove_autostart()


# ============================================================
# System Tray Icon (Native Windows API via ctypes)
# ============================================================

# Windows 常量
WM_USER = 0x0400
WM_TRAYICON = WM_USER + 1
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_COMMAND = 0x0111
NIM_ADD = 0x00000000
NIM_MODIFY = 0x00000001
NIM_DELETE = 0x00000002
NIF_ICON = 0x00000002
NIF_MESSAGE = 0x00000001
NIF_TIP = 0x00000004
WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
WM_LBUTTONUP = 0x0202
MF_STRING = 0x00000000
MF_GRAYED = 0x00000003
MF_CHECKED = 0x00000008
MF_SEPARATOR = 0x00000800
IDM_UNMOUNT = 1001
IDM_EXIT = 1002
IDM_AUTOSTART = 1003
IDM_LOGOUT = 1004
IDM_OPEN = 1005

# 修复 64 位 Python 上 DefWindowProcW 的 LPARAM 溢出
ctypes.windll.user32.DefWindowProcW.argtypes = [
    wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
ctypes.windll.user32.DefWindowProcW.restype = ctypes.c_ssize_t


class NOTIFYICONDATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("hWnd", wt.HWND),
        ("uID", wt.UINT),
        ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT),
        ("hIcon", wt.HICON),
        ("szTip", ctypes.c_wchar * 128),
        ("dwState", wt.DWORD),
        ("dwStateMask", wt.DWORD),
        ("szInfo", ctypes.c_wchar * 256),
        ("uTimeout", wt.UINT),
        ("szInfoTitle", ctypes.c_wchar * 64),
        ("dwInfoFlags", wt.DWORD),
    ]


def _create_simple_icon():
    """创建 16x16 蓝色圆形图标"""
    width, height = 16, 16
    # XOR mask (blue circle with white Z)
    xor_data = bytearray(width * height * 4)  # BGRA
    for y in range(height):
        for x in range(width):
            idx = (y * width + x) * 4
            dx, dy = x - 7.5, y - 7.5
            dist = (dx*dx + dy*dy) ** 0.5
            if dist < 6.5:
                # 蓝色圆形
                xor_data[idx] = 0xEB    # B
                xor_data[idx+1] = 0x63  # G
                xor_data[idx+2] = 0x25  # R
                xor_data[idx+3] = 0xFF  # A
                # 中心白色字母区域
                if 5 <= y <= 11 and 5 <= x <= 10:
                    xor_data[idx] = 0xFF
                    xor_data[idx+1] = 0xFF
                    xor_data[idx+2] = 0xFF
            else:
                xor_data[idx] = 0
                xor_data[idx+1] = 0
                xor_data[idx+2] = 0
                xor_data[idx+3] = 0

    # AND mask (all transparent)
    and_data = bytearray(width * height // 8 + width * height)

    xor_bytes = bytes(xor_data)
    and_bytes = bytes(and_data)

    h_icon = ctypes.windll.user32.CreateIcon(
        None, width, height, 1, 32,
        ctypes.c_char_p(and_bytes),
        ctypes.c_char_p(xor_bytes))
    return h_icon


class NativeTrayIcon:
    """使用 Windows 原生 API 的系统托盘图标 + tkinter 自绘右键菜单"""

    def __init__(self, tooltip, on_unmount, on_exit, on_toggle_autostart=None, on_logout=None, on_open=None, root_ref=None):
        self.tooltip = tooltip
        self.on_unmount = on_unmount
        self.on_exit = on_exit
        self.on_toggle_autostart = on_toggle_autostart
        self.on_logout = on_logout
        self.on_open = on_open
        self._root_ref = root_ref
        self._hwnd = None
        self._hicon = None
        self._nid = None
        self._thread = None
        self._running = False
        self._menu_win = None
        self._WndProcType = ctypes.WINFUNCTYPE(
            ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._hwnd:
            try:
                ctypes.windll.user32.PostMessageW(self._hwnd, WM_DESTROY, 0, 0)
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        self._remove_icon()
        if self._hwnd:
            try:
                ctypes.windll.user32.DestroyWindow(self._hwnd)
            except Exception:
                pass
            self._hwnd = None
        if hasattr(self, '_class_name') and self._class_name:
            try:
                ctypes.windll.user32.UnregisterClassW(self._class_name, self._hinst if hasattr(self, '_hinst') else None)
            except Exception:
                pass
            self._class_name = None

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAYICON:
            if lparam == WM_LBUTTONUP:
                if self.on_open:
                    self.on_open()
                return 0
            if lparam == WM_RBUTTONUP:
                if hasattr(self, '_root_ref') and self._root_ref:
                    self._root_ref.after(0, self._show_tk_menu)
                return 0
            if lparam == WM_LBUTTONDBLCLK:
                if hasattr(self, '_root_ref') and self._root_ref:
                    self._root_ref.after(0, self._show_tk_menu)
            return 0
        if msg == WM_COMMAND:
            cmd_id = wparam & 0xFFFF
            self._handle_cmd(cmd_id)
            return 0
        if msg == WM_DESTROY:
            self._remove_icon()
            ctypes.windll.user32.PostQuitMessage(0)
            return 0
        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _handle_cmd(self, cmd_id):
        if cmd_id == IDM_UNMOUNT:
            if self.on_unmount:
                self.on_unmount()
        elif cmd_id == IDM_EXIT:
            if self.on_exit:
                self.on_exit()
        elif cmd_id == IDM_AUTOSTART:
            if self.on_toggle_autostart:
                self.on_toggle_autostart()
        elif cmd_id == IDM_LOGOUT:
            if self.on_logout:
                self.on_logout()
        elif cmd_id == IDM_OPEN:
            if self.on_open:
                self.on_open()

    def _run(self):
        user32 = ctypes.windll.user32

        class WNDCLASSEX(ctypes.Structure):
            _fields_ = [
                ("cbSize", wt.UINT),
                ("style", wt.UINT),
                ("lpfnWndProc", self._WndProcType),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wt.HINSTANCE),
                ("hIcon", wt.HICON),
                ("hCursor", wt.HANDLE),
                ("hbrBackground", wt.HBRUSH),
                ("lpszMenuName", wt.LPCWSTR),
                ("lpszClassName", wt.LPCWSTR),
                ("hIconSm", wt.HICON),
            ]

        self._wnd_proc_ref = self._WndProcType(self._wnd_proc)

        wc = WNDCLASSEX()
        wc.cbSize = ctypes.sizeof(WNDCLASSEX)
        wc.lpfnWndProc = self._wnd_proc_ref
        hinst = ctypes.windll.kernel32.GetModuleHandleW(None)
        wc.hInstance = hinst
        class_name = f"MorongDiskTrayClass_{id(self)}"
        wc.lpszClassName = class_name
        user32.RegisterClassExW(ctypes.byref(wc))
        self._class_name = class_name
        self._hinst = hinst

        HWND_MESSAGE = ctypes.c_void_p(-3)
        self._hwnd = user32.CreateWindowExW(
            0, class_name, "MorongDiskTray", 0,
            0, 0, 0, 0, HWND_MESSAGE, None, hinst, None)

        if not self._hwnd:
            print("[Tray] Failed to create message window")
            return

        self._hicon = _create_simple_icon()

        nid = NOTIFYICONDATA()
        nid.cbSize = ctypes.sizeof(NOTIFYICONDATA)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP
        nid.uCallbackMessage = WM_TRAYICON
        nid.hIcon = self._hicon
        nid.szTip = self.tooltip
        self._nid = nid

        ctypes.windll.shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))

        msg = wt.MSG()
        while self._running:
            ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if ret <= 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def _show_tk_menu(self):
        root = self._root_ref
        if not root:
            return

        if hasattr(self, '_menu_win') and self._menu_win and self._menu_win.winfo_exists():
            self._menu_win.destroy()
            self._menu_win = None

        if hasattr(self, '_close_timer') and self._close_timer:
            try:
                root.after_cancel(self._close_timer)
            except Exception:
                pass
            self._close_timer = None

        self._mouse_entered_menu = False

        menu = tk.Toplevel(root)
        menu.overrideredirect(True)
        menu.attributes("-topmost", True)
        menu.configure(bg="#C7D2E0")

        self._menu_win = menu

        container = tk.Frame(menu, bg="#FFFFFF", bd=0)
        container.pack(fill="both", expand=True, padx=1, pady=1)

        items = [
            ("", self.tooltip, None, False, False),
            None,
            ("\U0001f4c2", "打开磁盘", IDM_OPEN, False, False),
            None,
            ("\u2705" if is_autostart_enabled() else "\u25cb",
             "开机自动挂载", IDM_AUTOSTART, True, is_autostart_enabled()),
            None,
            ("\U0001f504", "退出登录", IDM_LOGOUT, False, False),
            ("\U0001f4e4", "卸载磁盘", IDM_UNMOUNT, False, False),
            ("\u274e", "退出程序", IDM_EXIT, False, False),
        ]

        C_MENU_TEXT = "#1E293B"
        C_MENU_HOVER = "#EFF6FF"
        C_MENU_TITLE = "#94A3B8"
        C_MENU_SEP = "#E2E8F0"

        _menu_closed = [False]

        def dismiss():
            if _menu_closed[0]:
                return
            _menu_closed[0] = True
            if hasattr(self, '_close_timer') and self._close_timer:
                try:
                    root.after_cancel(self._close_timer)
                except Exception:
                    pass
                self._close_timer = None
            try:
                if menu.winfo_exists():
                    menu.destroy()
            except Exception:
                pass
            self._menu_win = None

        menu.bind("<Escape>", lambda e: dismiss())

        def on_item_click(cmd_id):
            dismiss()
            if cmd_id is not None:
                self._handle_cmd(cmd_id)

        def on_item_enter(lbl):
            lbl.configure(bg=C_MENU_HOVER)

        def on_item_leave(lbl):
            lbl.configure(bg="#FFFFFF")

        for item in items:
            if item is None:
                sep = tk.Frame(container, bg=C_MENU_SEP, height=1)
                sep.pack(fill="x", padx=6, pady=3)
                continue

            emoji, text, cmd_id, is_toggle, toggle_state = item

            if cmd_id is None:
                row = tk.Frame(container, bg="#FFFFFF")
                row.pack(fill="x", padx=2, pady=0)
                lbl = tk.Label(row, text=f"  {text}", bg="#FFFFFF", fg=C_MENU_TITLE,
                               font=("Microsoft YaHei UI", 9), anchor="w",
                               padx=8, pady=5)
                lbl.pack(fill="x")
            else:
                row = tk.Frame(container, bg="#FFFFFF", cursor="hand2")
                row.pack(fill="x", padx=2, pady=0)

                display_text = f"  {emoji}  {text}" if emoji else f"  {text}"
                lbl = tk.Label(row, text=display_text, bg="#FFFFFF", fg=C_MENU_TEXT,
                               font=("Microsoft YaHei UI", 10), anchor="w",
                               padx=8, pady=5)
                lbl.pack(fill="x")

                lbl.bind("<Button-1>", lambda e, c=cmd_id: on_item_click(c))
                lbl.bind("<Enter>", lambda e, l=lbl: on_item_enter(l))
                lbl.bind("<Leave>", lambda e, l=lbl: on_item_leave(l))
                row.bind("<Button-1>", lambda e, c=cmd_id: on_item_click(c))
                row.bind("<Enter>", lambda e, l=lbl: on_item_enter(l))
                row.bind("<Leave>", lambda e, l=lbl: on_item_leave(l))

        menu.update_idletasks()
        sw = menu.winfo_screenwidth()
        sh = menu.winfo_screenheight()
        mw = 220
        mh = menu.winfo_reqheight()
        mx = sw - mw - 12
        my = sh - mh - 50
        menu.geometry(f"{mw}x{mh}+{mx}+{my}")

        def on_menu_enter(e):
            self._mouse_entered_menu = True
            if hasattr(self, '_close_timer') and self._close_timer:
                try:
                    root.after_cancel(self._close_timer)
                except Exception:
                    pass
                self._close_timer = None

        def on_menu_leave(e):
            if _menu_closed[0]:
                return
            if self._mouse_entered_menu:
                self._close_timer = root.after(3000, dismiss)

        menu.bind("<Enter>", on_menu_enter)
        menu.bind("<Leave>", on_menu_leave)
        container.bind("<Enter>", on_menu_enter)
        container.bind("<Leave>", on_menu_leave)

        self._close_timer = root.after(5000, dismiss)

    def _remove_icon(self):
        if self._nid:
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            self._nid = None
        if self._hicon:
            ctypes.windll.user32.DestroyIcon(self._hicon)

    def update_tooltip(self, text):
        self.tooltip = text
        if self._nid and self._hwnd:
            self._nid.szTip = text
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))



class MountMonitor:
    def __init__(self, server, username, password, webdav_url, drive, label, drives=None, token=""):
        self.server = server
        self.username = username
        self.password = password
        self.webdav_url = webdav_url
        self.drive = sanitize_drive_letter(drive)
        self.label = label
        self.drives = drives or []
        self.token = token
        self._running = False
        self._thread = None
        self._reconnect_count = 0
        self._last_cmd_fetch = time.time()
        self._last_notif_id = 0

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        interval = 15
        max_interval = 300  # 最大 5 分钟
        miss = 0
        while self._running:
            time.sleep(interval)
            if not self._running:
                break

            # 每 60 秒同步一次管理后台的远程命令（隐藏/恢复磁盘）+ 通知轮询
            now = time.time()
            if now - self._last_cmd_fetch >= 60:
                self._last_cmd_fetch = now
                try:
                    cmd_result = fetch_and_execute_commands(
                        self.server, self.username, self.password, token=self.token)
                    if cmd_result and cmd_result.get("remount"):
                        print("[Monitor] 服务端 base_path 已更新，正在重新挂载...")
                        self._remount_all()
                except Exception as e:
                    print(f"[Monitor] 命令同步异常: {e}")
                try:
                    self._poll_notifications()
                except Exception as e:
                    print(f"[Monitor] 通知轮询异常: {e}")

            if self._any_drive_accessible():
                miss = 0
                interval = 15  # 成功时重置间隔
                continue
            miss += 1
            if miss < 2:
                continue
            self._reconnect_count += 1
            print(f"[Monitor] 断线检测，第{self._reconnect_count}次重连 (间隔{interval}s)...")
            if not self._wait_net():
                continue
            if not self._running:
                break
            self._remount_all()
            if self._any_drive_accessible():
                miss = 0
                interval = 15  # 重连成功，重置间隔
                print(f"[Monitor] 重连成功!")
            else:
                interval = min(interval * 2, max_interval)
                print(f"[Monitor] 重连失败 (下次间隔{interval}s)")

    def _poll_notifications(self):
        if not self.token:
            return
        try:
            r = requests.get(
                f"{self.server}/api/auth/notifications",
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=10)
            if r.status_code != 200:
                return
            notifs = r.json()
            if not isinstance(notifs, list):
                return
            for n in notifs:
                nid = n.get("id", 0)
                if nid <= self._last_notif_id:
                    continue
                if n.get("is_read"):
                    continue
                title = n.get("title", "")
                content = n.get("content", "")
                duration = n.get("duration", 5) or 5
                if title:
                    self._show_toast(title, content, duration)
                    self._last_notif_id = nid
                    try:
                        requests.post(
                            f"{self.server}/api/auth/notifications/{nid}/read",
                            headers={"Authorization": f"Bearer {self.token}"},
                            timeout=5)
                    except Exception:
                        pass
                break
        except Exception:
            pass

    def _show_toast(self, title, content, duration=5):
        try:
            _toast_queue.put((title, content, duration))
        except Exception:
            pass

    def _any_drive_accessible(self):
        if self.drives and len(self.drives) >= 1:
            for d in self.drives:
                if is_drive_accessible(sanitize_drive_letter(d.get("drive_letter", "Z:"))):
                    return True
            return False
        return is_drive_accessible(self.drive)

    def _remount_all(self):
        if self.drives and len(self.drives) >= 1:
            for d in self.drives:
                dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                lb = sanitize_label(d.get("label", "远程磁盘"))
                wp = d.get("webdav_path", "")
                mount_url = self.webdav_url
                if wp:
                    if not wp.startswith("/"):
                        wp = "/" + wp
                    mount_url = self.webdav_url.rstrip("/") + wp
                config_name = f"ALIST_DRIVE_{dl.rstrip(':').upper()}"
                ok, msg = mount_webdav(mount_url, self.username, self.password, dl, lb, config_name=config_name)
                if ok:
                    print(f"[Monitor] 重新挂载成功: {dl}")
                else:
                    print(f"[Monitor] 重新挂载失败: {dl} - {msg}")
        else:
            ok, msg = mount_webdav(self.webdav_url, self.username, self.password, self.drive, self.label)
            if ok:
                print(f"[Monitor] 重新挂载成功: {msg}")
            else:
                print(f"[Monitor] 重新挂载失败: {msg}")

    def _wait_net(self, max_s=60):
        for _ in range(max_s // 5):
            if not self._running:
                return False
            if is_network_available(self.server):
                return True
            time.sleep(5)
        return False


# ============================================================
# Login Window
# ============================================================

C_PRIMARY = "#2563EB"
C_PRIMARY_HOVER = "#1D4ED8"
C_DANGER = "#DC2626"
C_BG = "#F1F5F9"
C_CARD = "#FFFFFF"
C_SUBTEXT = "#64748B"
C_BORDER = "#E2E8F0"
C_TEXT = "#1E293B"
C_SUCCESS = "#27AE60"


class LoginWindow:
    def __init__(self, root, on_success, skip_auto_login=False):
        self.root = root
        self.on_success = on_success
        self.config = load_config()
        self._logging_in = False
        self._skip_auto_login = skip_auto_login
        self._mount_done = threading.Event()  # 线程安全的完成标志
        self._mount_ok = False
        self._mount_msg = ""
        self._build_ui()
        self._load_saved()

    def _build_ui(self):
        self.root.title("morong远程磁盘")
        self.root.geometry("400x520")
        self.root.resizable(False, False)
        self.root.configure(bg=C_BG)


        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 400) // 2
        y = (self.root.winfo_screenheight() - 520) // 2
        self.root.geometry(f"+{x}+{y}")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Return>", lambda e: self._do_login())

        card = tk.Frame(self.root, bg=C_CARD, highlightbackground=C_BORDER, highlightthickness=1)
        card.place(relx=0.5, rely=0.48, anchor="center", width=340, height=440)

        tk.Label(card, text="MORONG", bg=C_CARD, fg=C_PRIMARY,
                 font=("Segoe UI", 24, "bold")).pack(pady=(24, 0))
        tk.Label(card, text="远程磁盘挂载客户端", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 10)).pack(pady=(2, 14))

        # 服务器地址 + 测试按钮
        f1 = tk.Frame(card, bg=C_CARD)
        f1.pack(fill="x", padx=28, pady=4)
        tk.Label(f1, text="服务器地址", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        sf = tk.Frame(f1, bg=C_CARD)
        sf.pack(fill="x", pady=(3, 0))
        self.e_server = tk.Entry(sf, font=("Consolas", 11), relief="solid", bd=1)
        self.e_server.pack(side="left", fill="x", expand=True)
        self.btn_test = tk.Label(sf, text="测试", bg=C_BORDER, fg=C_SUBTEXT,
                                  font=("Microsoft YaHei UI", 9), cursor="hand2",
                                  width=5, pady=3)
        self.btn_test.pack(side="right", padx=(4, 0))
        self.btn_test.bind("<Button-1>", lambda e: self._test_server())
        self.btn_test.bind("<Enter>", lambda e: self.btn_test.configure(bg=C_PRIMARY, fg="white"))
        self.btn_test.bind("<Leave>", lambda e: self.btn_test.configure(bg=C_BORDER, fg=C_SUBTEXT))

        f2 = tk.Frame(card, bg=C_CARD)
        f2.pack(fill="x", padx=28, pady=4)
        tk.Label(f2, text="用户名", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        uf = tk.Frame(f2, bg=C_CARD)
        uf.pack(fill="x", pady=(3, 0))
        self.e_user = tk.Entry(uf, font=("Microsoft YaHei UI", 11), relief="solid", bd=1)
        self.e_user.pack(side="left", fill="x", expand=True)
        tk.Label(uf, text="", bg=C_CARD, width=5, pady=3).pack(side="right", padx=(4, 0))

        # 密码 + 可见性切换
        f3 = tk.Frame(card, bg=C_CARD)
        f3.pack(fill="x", padx=28, pady=4)
        tk.Label(f3, text="密码", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        pf = tk.Frame(f3, bg=C_CARD)
        pf.pack(fill="x", pady=(3, 0))
        self.e_pwd = tk.Entry(pf, font=("Microsoft YaHei UI", 11), show="*", relief="solid", bd=1)
        self.e_pwd.pack(side="left", fill="x", expand=True)
        self._pwd_visible = False
        self.btn_eye = tk.Label(pf, text="\U0001F648", bg=C_CARD, fg=C_SUBTEXT,
                                 font=("Segoe UI Emoji", 13), cursor="hand2", width=3)
        self.btn_eye.pack(side="right", padx=(2, 0))
        self.btn_eye.bind("<Button-1>", lambda e: self._toggle_pwd_visibility())
        self.btn_eye.bind("<Enter>", lambda e: self.btn_eye.configure(fg=C_PRIMARY))
        self.btn_eye.bind("<Leave>", lambda e: self.btn_eye.configure(fg=C_SUBTEXT))

        f4 = tk.Frame(card, bg=C_CARD)
        f4.pack(fill="x", padx=28, pady=(6, 0))
        self.var_remember = tk.BooleanVar(value=False)
        self.var_auto = tk.BooleanVar(value=False)
        tk.Checkbutton(f4, text="记住密码", variable=self.var_remember,
                       bg=C_CARD, fg=C_SUBTEXT, selectcolor=C_CARD, activebackground=C_CARD,
                       font=("Microsoft YaHei UI", 9)).pack(side="left")
        tk.Checkbutton(f4, text="开机自动挂载", variable=self.var_auto,
                       bg=C_CARD, fg=C_SUBTEXT, selectcolor=C_CARD, activebackground=C_CARD,
                       font=("Microsoft YaHei UI", 9)).pack(side="right")

        # 状态 + 加载动画
        sf2 = tk.Frame(card, bg=C_CARD)
        sf2.pack(pady=(6, 0))
        self.lbl_status = tk.Label(sf2, text="", bg=C_CARD, fg=C_DANGER,
                                    font=("Microsoft YaHei UI", 9))
        self.lbl_status.pack(side="left")
        self._spinner_angle = 0
        self._spinner_canvas = tk.Canvas(sf2, width=16, height=16, bg=C_CARD, highlightthickness=0)
        self._spinner_canvas.pack(side="left", padx=(4, 0))
        self._spinner_canvas.pack_forget()

        self.btn = tk.Label(card, text="登  录", bg=C_PRIMARY, fg="white",
                            font=("Microsoft YaHei UI", 12, "bold"),
                            cursor="hand2", padx=60, pady=8)
        self.btn.pack(pady=(8, 4))
        self.btn.bind("<Button-1>", lambda e: self._do_login())
        self.btn.bind("<Enter>", lambda e: self.btn.configure(bg=C_PRIMARY_HOVER))
        self.btn.bind("<Leave>", lambda e: self.btn.configure(bg=C_PRIMARY))

        self.btn_chpwd = tk.Label(card, text="修改密码", bg=C_CARD, fg=C_SUBTEXT,
                                   font=("Microsoft YaHei UI", 9), cursor="hand2")
        self.btn_chpwd.pack(pady=(0, 8))
        self.btn_chpwd.bind("<Button-1>", lambda e: self._show_change_password())
        self.btn_chpwd.bind("<Enter>", lambda e: self.btn_chpwd.configure(fg=C_PRIMARY))
        self.btn_chpwd.bind("<Leave>", lambda e: self.btn_chpwd.configure(fg=C_SUBTEXT))

    def _toggle_pwd_visibility(self):
        self._pwd_visible = not self._pwd_visible
        if self._pwd_visible:
            self.e_pwd.config(show="")
            self.btn_eye.config(text="\U0001F441")
        else:
            self.e_pwd.config(show="*")
            self.btn_eye.config(text="\U0001F648")

    def _test_server(self):
        server = self.e_server.get().strip().rstrip("/")
        if not server:
            self._set_status("请输入服务器地址", C_DANGER)
            return
        self.btn_test.config(text="...", bg=C_SUBTEXT, fg="white")
        self.root.update()

        def _do_test():
            try:
                r = requests.get(f"{server}/api/health", timeout=5)
                if r.status_code == 200:
                    d = r.json()
                    msg = f"连接成功 v{d.get('version','?')} ({d.get('users',0)} 用户)"
                    self.root.after(0, lambda: self._set_status(msg, C_SUCCESS))
                    self.root.after(0, lambda: self.btn_test.config(text="OK", bg=C_SUCCESS, fg="white"))
                else:
                    self.root.after(0, lambda: self._set_status(f"服务器响应异常: HTTP {r.status_code}", C_DANGER))
                    self.root.after(0, lambda: self.btn_test.config(text="!", bg=C_DANGER, fg="white"))
            except Exception as ex:
                self.root.after(0, lambda: self._set_status(f"连接失败: {ex}", C_DANGER))
                self.root.after(0, lambda: self.btn_test.config(text="!", bg=C_DANGER, fg="white"))
            self.root.after(3000, lambda: self.btn_test.config(text="测试", bg=C_BORDER, fg=C_SUBTEXT))

        threading.Thread(target=_do_test, daemon=True).start()

    def _start_spinner(self):
        self._spinner_canvas.pack(side="left", padx=(4, 0))
        self._animate_spinner()

    def _stop_spinner(self):
        self._spinner_canvas.pack_forget()

    def _animate_spinner(self):
        if not self._logging_in:
            self._stop_spinner()
            return
        c = self._spinner_canvas
        c.delete("all")
        cx, cy, r = 8, 8, 6
        self._spinner_angle = (self._spinner_angle + 30) % 360
        import math
        for i in range(8):
            a = math.radians(self._spinner_angle + i * 45)
            alpha = 1.0 - i * 0.12
            x1 = cx + r * math.cos(a)
            y1 = cy + r * math.sin(a)
            color = C_PRIMARY if i < 2 else C_SUBTEXT if i < 5 else C_BORDER
            c.create_oval(x1 - 1.5, y1 - 1.5, x1 + 1.5, y1 + 1.5, fill=color, outline="")
        self.root.after(80, self._animate_spinner)

    def _load_saved(self):
        c = self.config
        if c.get("server"):
            self.e_server.delete(0, "end")
            self.e_server.insert(0, c.get("server", ""))
        if c.get("username"):
            self.e_user.insert(0, c.get("username", ""))
            if c.get("password"):
                self.e_pwd.insert(0, c.get("password", ""))
            self.var_remember.set(True)
        self.var_auto.set(c.get("auto_login", False))
        if not self._skip_auto_login and c.get("auto_login") and c.get("username") and c.get("password"):
            if "--auto" in sys.argv or "--silent" in sys.argv:
                self.root.withdraw()
                self.root.overrideredirect(True)
                self.root.geometry("1x1+0+0")
                self.root.title("")
                self.root.attributes("-alpha", 0.0)
                def _block_map(evt):
                    try:
                        self.root.withdraw()
                        self.root.overrideredirect(True)
                        self.root.geometry("1x1+0+0")
                        self.root.attributes("-alpha", 0.0)
                    except Exception:
                        pass
                    return "break"
                self.root.bind("<Map>", _block_map)
            self.root.after(300, self._do_login)

    def _set_status(self, text, color=C_DANGER):
        self.lbl_status.config(text=text, fg=color)

    def _do_login(self):
        if self._logging_in:
            return
        server = self.e_server.get().strip().rstrip("/")
        username = self.e_user.get().strip()
        password = self.e_pwd.get()

        if not server:
            self._set_status("请输入服务器地址"); return
        if not username:
            self._set_status("请输入用户名"); return
        if not password:
            self._set_status("请输入密码"); return

        remember = self.var_remember.get()
        auto = self.var_auto.get()

        self._logging_in = True
        self._mount_done.clear()
        self._mount_ok = False
        self._poll_count = 0
        self.btn.config(state="disabled", bg="#94A3B8")
        self._set_status("正在验证...", C_SUBTEXT)
        self._start_spinner()

        threading.Thread(
            target=self._login_thread,
            args=(server, username, password, remember, auto),
            daemon=True).start()

        # 轮询挂载结果（主线程检查，避免 root.after 从后台线程调用）
        self._poll_mount()

    def _poll_mount(self):
        """主线程轮询挂载结果"""
        if self._mount_done.is_set():
            if self._mount_ok:
                self._logging_in = False
                self._stop_spinner()
                self.on_success(self._auth_data, self._password)
            else:
                self._fail(self._mount_msg)
            return
        # 超时保护：最多等待 60 秒（600 × 100ms）
        self._poll_count = getattr(self, '_poll_count', 0) + 1
        if self._poll_count >= 600:
            self._fail("挂载响应超时，请检查网络和 rclone 状态")
            return
        # 继续轮询
        self.root.after(100, self._poll_mount)

    def _login_thread(self, server, username, password, remember, auto):
        try:
            enc_pwd, encrypted = _rsa_encrypt_password(server, password)
            r = requests.post(
                f"{server}/api/auth/login",
                json={"username": username, "password": enc_pwd, "encrypted": encrypted},
                timeout=10)
            if r.status_code != 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                self._mount_msg = data.get("error", f"认证失败 (HTTP {r.status_code})")
                self._mount_done.set()
                return
            data = r.json()
        except requests.exceptions.ConnectionError:
            self._mount_msg = "无法连接服务器"
            self._mount_done.set()
            return
        except requests.exceptions.Timeout:
            self._mount_msg = "连接超时"
            self._mount_done.set()
            return
        except Exception as e:
            self._mount_msg = f"网络错误: {e}"
            self._mount_done.set()
            return

        if not data.get("success"):
            self._mount_msg = data.get("error", "认证失败")
            self._mount_done.set()
            return

        self.config.update({
            "server": server, "username": username,
            "password": password if remember else "",
            "remember_password": remember, "auto_login": auto,
            "drive": data.get("drive", "Z:"),
            "label": data.get("label", "远程磁盘"),
            "drives": data.get("drives", []),
        })
        save_config(self.config)

        # 上报硬件信息（后台线程，不阻塞挂载）
        threading.Thread(
            target=_send_system_info,
            args=(server, data.get("token", "")),
            daemon=True
        ).start()

        # 在主线程更新状态文字
        self.root.after(0, self._set_status, "认证成功，正在挂载...", "#27AE60")

        # 执行挂载
        try:
            self._do_mount(data, password, auto)
        except Exception as e:
            self._mount_msg = f"挂载异常: {e}"
            self._mount_done.set()

    def _do_mount(self, auth_data, password, auto):
        """在后台线程执行挂载（支持多盘符）"""
        webdav_url = auth_data["webdav_url"]
        drive = sanitize_drive_letter(auth_data.get("drive", "Z:"))
        label = sanitize_label(auth_data.get("label", "远程磁盘"))
        username = auth_data["username"]
        drives = auth_data.get("drives", [])


        if not is_winfsp_installed():
            self.root.after(0, self._set_status, "首次运行，正在安装 WinFsp...", C_SUBTEXT)
            ok, msg = install_winfsp()
            if not ok:
                self._mount_msg = f"WinFsp 安装失败: {msg}"
                self._mount_done.set()
                return
            time.sleep(2)

        if not os.path.exists(RCLONE_EXE):
            self._mount_msg = "找不到 rclone.exe"
            self._mount_done.set()
            return

        if drives and len(drives) >= 1:
            first_ok = False
            for i, d in enumerate(drives):
                dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                wp = d.get("webdav_path", "")
                if wp:
                    dir_name = wp.rstrip("/").split("/")[-1]
                    lb = sanitize_label(dir_name) if dir_name else sanitize_label(d.get("label", "远程磁盘"))
                else:
                    lb = sanitize_label(d.get("label", "远程磁盘"))
                mount_url = webdav_url
                if wp:
                    if not wp.startswith("/"):
                        wp = "/" + wp
                    mount_url = webdav_url.rstrip("/") + wp
                config_name = f"ALIST_DRIVE_{dl.rstrip(':').upper()}"
                ok, msg = mount_webdav(mount_url, username, password, dl, lb, config_name=config_name)
                if ok:
                    try:
                        setup_drive_ui(dl, lb)
                        setup_sendto(dl, lb)
                    except Exception:
                        pass
                    if not first_ok:
                        first_ok = True
                else:
                    if i == 0:
                        _kill_own_rclone(dl)
                        self._mount_msg = msg
                        self._mount_done.set()
                        return
                    _kill_own_rclone(dl)
                    print(f"[Mount] 盘符 {dl} 挂载失败: {msg}")
        else:
            ok, msg = mount_webdav(webdav_url, username, password, drive, label)
            if not ok:
                self._mount_msg = msg
                self._mount_done.set()
                return
            try:
                setup_drive_ui(drive, label)
                setup_sendto(drive, label)
            except Exception:
                pass

        if auto:
            try:
                exe = sys.executable if IS_FROZEN else os.path.join(BASE_DIR, "MorongDisk.exe")
                setup_autostart(exe)
            except Exception:
                pass

        self._auth_data = auth_data
        self._password = password
        self._mount_ok = True
        self._mount_done.set()

    def _fail(self, msg):
        self._logging_in = False
        self._stop_spinner()
        self._set_status(msg)
        self.btn.config(state="normal", bg=C_PRIMARY)
        if ("--auto" in sys.argv or "--silent" in sys.argv) and _app_state.get("root"):
            _ensure_auto_reconnect_tray()
            _schedule_auto_background_retry()

    def _schedule_auto_retry(self):
        pass

    def _auto_retry(self):
        pass

    def _show_change_password(self):
        if self._logging_in:
            return
        dlg = tk.Toplevel(self.root)
        dlg.title("修改密码")
        dlg.geometry("360x320")
        dlg.resizable(False, False)
        dlg.configure(bg=C_CARD)
        dlg.attributes("-topmost", True)
        dlg.transient(self.root)
        dlg.grab_set()

        dlg.update_idletasks()
        x = (dlg.winfo_screenwidth() - 360) // 2
        y = (dlg.winfo_screenheight() - 320) // 2
        dlg.geometry(f"+{x}+{y}")

        tk.Label(dlg, text="修改密码", bg=C_CARD, fg=C_PRIMARY,
                 font=("Microsoft YaHei UI", 16, "bold")).pack(pady=(20, 12))

        f1 = tk.Frame(dlg, bg=C_CARD)
        f1.pack(fill="x", padx=30, pady=4)
        tk.Label(f1, text="当前密码", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        e_old = tk.Entry(f1, font=("Microsoft YaHei UI", 11), show="*", relief="solid", bd=1)
        e_old.pack(fill="x", pady=(2, 0))

        f2 = tk.Frame(dlg, bg=C_CARD)
        f2.pack(fill="x", padx=30, pady=4)
        tk.Label(f2, text="新密码", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        e_new = tk.Entry(f2, font=("Microsoft YaHei UI", 11), show="*", relief="solid", bd=1)
        e_new.pack(fill="x", pady=(2, 0))

        f3 = tk.Frame(dlg, bg=C_CARD)
        f3.pack(fill="x", padx=30, pady=4)
        tk.Label(f3, text="确认新密码", bg=C_CARD, fg=C_SUBTEXT,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w")
        e_confirm = tk.Entry(f3, font=("Microsoft YaHei UI", 11), show="*", relief="solid", bd=1)
        e_confirm.pack(fill="x", pady=(2, 0))

        lbl_msg = tk.Label(dlg, text="", bg=C_CARD, fg=C_DANGER,
                           font=("Microsoft YaHei UI", 9), wraplength=300)
        lbl_msg.pack(pady=(6, 0))

        def do_change():
            server = self.e_server.get().strip().rstrip("/")
            username = self.e_user.get().strip()
            old_pwd = e_old.get()
            new_pwd = e_new.get()
            confirm_pwd = e_confirm.get()

            if not server or not username:
                lbl_msg.config(text="请先填写服务器地址和用户名", fg=C_DANGER)
                return
            if not old_pwd:
                lbl_msg.config(text="请输入当前密码", fg=C_DANGER)
                return
            if not new_pwd or len(new_pwd) < 6:
                lbl_msg.config(text="新密码至少6个字符", fg=C_DANGER)
                return
            if len(new_pwd) > 128:
                lbl_msg.config(text="新密码不能超过128个字符", fg=C_DANGER)
                return
            if new_pwd != confirm_pwd:
                lbl_msg.config(text="两次输入的新密码不一致", fg=C_DANGER)
                return
            if old_pwd == new_pwd:
                lbl_msg.config(text="新密码不能与当前密码相同", fg=C_DANGER)
                return

            lbl_msg.config(text="正在修改...", fg=C_SUBTEXT)
            dlg.update()

            def _change_thread():
                try:
                    enc_old_pwd, old_enc = _rsa_encrypt_password(server, old_pwd)
                    r_login = requests.post(
                        f"{server}/api/auth/login",
                        json={"username": username, "password": enc_old_pwd, "encrypted": old_enc},
                        timeout=10)
                    login_data = r_login.json()
                    if r_login.status_code != 200 or not login_data.get("success"):
                        dlg.after(0, lambda: lbl_msg.config(text="当前密码错误", fg=C_DANGER))
                        return
                    token = login_data.get("token", "")
                    if not token:
                        dlg.after(0, lambda: lbl_msg.config(text="获取令牌失败", fg=C_DANGER))
                        return


                    enc_new, new_enc = _rsa_encrypt_password(server, new_pwd)
                    use_enc = old_enc and new_enc
                    r = requests.post(
                        f"{server}/api/auth/change-password",
                        json={"old_password": enc_old_pwd if use_enc else old_pwd,
                              "new_password": enc_new if use_enc else new_pwd,
                              "encrypted": use_enc},
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10)
                    result = r.json()
                    if r.status_code == 200 and result.get("success"):
                        dlg.after(0, lambda: lbl_msg.config(text="密码修改成功！", fg="#27AE60"))
                        self.e_pwd.delete(0, tk.END)
                        self.config["password"] = ""
                        self.config["remember_password"] = False
                        save_config(self.config)
                        dlg.after(1200, dlg.destroy)
                    else:
                        dlg.after(0, lambda: lbl_msg.config(
                            text=result.get("error", "修改失败"), fg=C_DANGER))
                except requests.exceptions.ConnectionError:
                    dlg.after(0, lambda: lbl_msg.config(text="无法连接服务器", fg=C_DANGER))
                except Exception as ex:
                    dlg.after(0, lambda: lbl_msg.config(text=f"错误: {ex}", fg=C_DANGER))

            threading.Thread(target=_change_thread, daemon=True).start()

        btn_frame = tk.Frame(dlg, bg=C_CARD)
        btn_frame.pack(pady=(10, 0))
        tk.Button(btn_frame, text="确认修改", command=do_change,
                  bg=C_PRIMARY, fg="white", font=("Microsoft YaHei UI", 10, "bold"),
                  relief="flat", padx=20, pady=4, cursor="hand2").pack(side="left", padx=8)
        tk.Button(btn_frame, text="取消", command=dlg.destroy,
                  bg="#E2E8F0", fg=C_TEXT, font=("Microsoft YaHei UI", 10),
                  relief="flat", padx=20, pady=4, cursor="hand2").pack(side="left", padx=8)

    def _on_close(self):
        try:
            _kill_own_rclone()
        except Exception:
            pass
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass
        self.root.destroy()


# ============================================================
# Main
# ============================================================

def _ask_unmount_password(root, drive, username, password):
    """自定义密码确认弹窗（兼容 root withdrawn 状态）"""
    try:
        was_hidden = not root.winfo_viewable()
    except Exception:
        was_hidden = True

    if was_hidden:
        try:
            root.withdraw()
        except Exception:
            pass

    result = [None]
    C_TEXT = "#1E293B"
    C_HINT = "#475569"

    try:
        dlg = tk.Toplevel(root)
        dlg.title("卸载确认")
        dlg.geometry("380x260")
        dlg.resizable(False, False)
        dlg.configure(bg=C_CARD)
        dlg.attributes("-topmost", True)
        dlg.grab_set()

        dlg.update_idletasks()
        x = (dlg.winfo_screenwidth() - 380) // 2
        y = (dlg.winfo_screenheight() - 260) // 2
        dlg.geometry(f"+{x}+{y}")

        tk.Label(dlg, text="\u26a0\ufe0f  卸载确认", bg=C_CARD, fg=C_PRIMARY,
                 font=("Segoe UI", 16, "bold")).pack(pady=(20, 6))
        tk.Label(dlg, text=f"\U0001f511  请输入密码以确认卸载 {drive}",
                 bg=C_CARD, fg=C_TEXT,
                 font=("Microsoft YaHei UI", 10)).pack(pady=(0, 12))

        pwd_var = tk.StringVar()
        entry = tk.Entry(dlg, textvariable=pwd_var, show="\u25cf",
                         font=("Microsoft YaHei UI", 13), relief="solid", bd=1)
        entry.pack(fill="x", padx=44)

        status_lbl = tk.Label(dlg, text="", bg=C_CARD, fg=C_DANGER,
                              font=("Microsoft YaHei UI", 9))
        status_lbl.pack(pady=(4, 0))

        def do_verify():
            pwd = pwd_var.get()
            if not pwd:
                status_lbl.config(text="\u274c  请输入密码")
                return
            config = load_config()
            server_url = config.get("server", "")
            verified = False
            try:
                enc_pwd, encrypted = _rsa_encrypt_password(server_url, pwd)
                r = requests.post(
                    f"{server_url}/api/auth/login",
                    json={"username": username, "password": enc_pwd, "encrypted": encrypted}, timeout=10)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("success"):
                        verified = True
            except Exception:
                if pwd == password:
                    verified = True
            if verified:
                result[0] = True
                dlg.destroy()
            else:
                status_lbl.config(text="\u274c  密码错误，请重试")
                entry.delete(0, "end")

        entry.bind("<Return>", lambda e: do_verify())

        btn_f = tk.Frame(dlg, bg=C_CARD)
        btn_f.pack(pady=(12, 0))
        tk.Label(btn_f, text="\u2705  确  认", bg=C_PRIMARY, fg="white",
                 font=("Microsoft YaHei UI", 10, "bold"),
                 cursor="hand2", padx=20, pady=5
                 ).bind("<Button-1>", lambda e: do_verify())

        def cancel():
            result[0] = None
            dlg.destroy()

        tk.Label(dlg, text="\u274e  取消", bg=C_CARD, fg=C_HINT,
                 font=("Microsoft YaHei UI", 9), cursor="hand2"
                 ).bind("<Button-1>", lambda e: cancel())

        dlg.protocol("WM_DELETE_WINDOW", cancel)
        entry.focus_set()
        dlg.wait_window()
    except Exception as e:
        print(f"[Unmount] 密码弹窗异常: {e}")

    return result[0]


def _do_self_uninstall():
    """MorongDisk 自身卸载：清理所有数据、注册表、快捷方式，然后删除自身"""
    CNW = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)

    # 0. 确认对话框
    MB_YESNO = 0x00000004
    MB_ICONQUESTION = 0x00000020
    MB_TOPMOST = 0x00040000
    MB_ICONWARNING = 0x00000030
    IDYES = 6
    ret = ctypes.windll.user32.MessageBoxW(
        0,
        "确定要卸载 morong远程磁盘 吗？\n\n"
        "将清理以下内容：\n"
        "  · 程序文件及安装目录\n"
        "  · 桌面快捷方式和开机自启\n"
        "  · 配置文件和缓存数据\n"
        "  · 注册表相关条目\n\n"
        "注：WinFsp 驱动不会被卸载（可能被其他程序使用）。",
        "morong远程磁盘 卸载",
        MB_YESNO | MB_ICONQUESTION | MB_TOPMOST
    )
    if ret != IDYES:
        sys.exit(0)

    # 1. 终止 rclone 进程
    try:
        proc = subprocess.Popen(
            ["tasklist", "/FI", "IMAGENAME eq rclone.exe", "/FO", "CSV", "/NH"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=CNW)
        stdout, _ = proc.communicate(timeout=5)
        for line in stdout.decode("utf-8", errors="replace").split("\n"):
            line = line.strip()
            if "rclone" in line.lower():
                parts = line.split(",")
                if len(parts) >= 2:
                    pid = parts[1].strip('"')
                    try:
                        subprocess.Popen(
                            ["taskkill", "/F", "/PID", pid],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=CNW)
                    except Exception:
                        pass
    except Exception:
        pass

    # 2. 断开所有 WebDAV 挂载
    try:
        proc = subprocess.Popen(
            ["net", "use"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CNW)
        stdout, _ = proc.communicate(timeout=5)
        for line in stdout.decode("utf-8", errors="replace").split("\n"):
            if "\\\\" in line and "WebDAV" in line:
                parts = line.split()
                for p in parts:
                    if len(p) == 2 and p[1] == ":":
                        subprocess.Popen(
                            ["net", "use", p, "/delete", "/y"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=CNW)
    except Exception:
        pass

    # 3. 删除开机自启快捷方式
    startup = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup",
        "AutoMount_Morong.vbs")
    try:
        if os.path.exists(startup):
            os.remove(startup)
    except Exception:
        pass

    # 4. 删除桌面快捷方式
    desktop = os.path.join(os.path.expanduser("~"), "Desktop", "morong远程磁盘.lnk")
    try:
        if os.path.exists(desktop):
            os.remove(desktop)
    except Exception:
        pass

    # 5. 删除 SendTo 快捷方式（从配置读取标签和盘符，精确删除）
    sendto_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        "Microsoft", "Windows", "SendTo")
    try:
        cfg = load_config()
        label = sanitize_label(cfg.get("label", "远程磁盘"))
        drive = sanitize_drive_letter(cfg.get("drive", "Z:"))
        letter = drive.rstrip(":")
        sendto_name = f"{label} ({letter}).lnk"
        sendto_path = os.path.join(sendto_dir, sendto_name)
        if os.path.exists(sendto_path):
            os.remove(sendto_path)
    except Exception:
        pass

    # 6. 删除配置目录（含 _shortcut.vbs 等）
    appdata = os.environ.get("APPDATA", "")
    config_dir = os.path.join(appdata, "AlistDrive")
    try:
        if os.path.isdir(config_dir):
            shutil.rmtree(config_dir, ignore_errors=True)
    except Exception:
        pass

    # 7. 清理注册表（HKCU + HKLM 都检查）
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MorongDisk"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MorongDisk"),
    ]
    for hive, path in reg_paths:
        try:
            parent = "\\".join(path.split("\\")[:-1])
            key_name = path.split("\\")[-1]
            key = winreg.OpenKey(hive, parent, 0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteKey(key, key_name)
            winreg.CloseKey(key)
        except Exception:
            pass

    # 清理驱动器图标注册表
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        for sub in ("DefaultIcon", "DefaultLabel"):
            try:
                key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\{letter}"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS)
                winreg.DeleteValue(key, sub)
                winreg.CloseKey(key)
            except Exception:
                pass
        # 尝试删除空的盘符 key
        try:
            parent_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons"
            parent = winreg.OpenKey(winreg.HKEY_CURRENT_USER, parent_path, 0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteKey(parent, letter)
            winreg.CloseKey(parent)
        except Exception:
            pass
        # 清理 setup_drive_ui 写入的 Classes 路径
        try:
            cls_path = rf"SOFTWARE\Classes\Applications\explorer.exe\Drives\{letter}"
            cls_parent = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Classes\Applications\explorer.exe\Drives",
                0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteKey(cls_parent, letter)
            winreg.CloseKey(cls_parent)
        except Exception:
            pass

    # 8. 延迟删除安装目录（使用 Python 子进程，避免 bat 自删除被杀软标记）
    install_dir = os.path.dirname(os.path.abspath(sys.executable))
    exe_path = os.path.abspath(sys.executable)
    _cleanup_script = os.path.join(
        os.environ.get("TEMP", r"C:\Windows\Temp"), "md_cleanup.py")
    with open(_cleanup_script, "w", encoding="utf-8") as f:
        f.write(
            "import os, time, shutil\n"
            f"target_dir = {repr(install_dir)}\n"
            f"target_exe = {repr(exe_path)}\n"
            "for i in range(10):\n"
            "    time.sleep(1)\n"
            "    try:\n"
            "        if os.path.exists(target_exe):\n"
            "            os.remove(target_exe)\n"
            "    except Exception:\n"
            "        pass\n"
            "    if not os.path.exists(target_exe):\n"
            "        break\n"
            "try:\n"
            "    if os.path.isdir(target_dir):\n"
            "        shutil.rmtree(target_dir, ignore_errors=True)\n"
            "except Exception:\n"
            "    pass\n"
            "try:\n"
            "    os.remove(__file__)\n"
            "except Exception:\n"
            "    pass\n"
        )

    # 9. 启动清理子进程
    subprocess.Popen(
        [sys.executable, _cleanup_script],
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000) |
        getattr(subprocess, 'DETACHED_PROCESS', 0x8))

    # 10. 最小清理后退出
    try:
        _kill_own_rclone()
    except Exception:
        pass
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception:
        pass
    os._exit(0)


def _add_security_exclusions():
    try:
        exe_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else BASE_DIR
        marker = os.path.join(
            os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "MorongDisk", "sec_done")
        if os.path.exists(marker):
            return
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"],
                capture_output=True, text=True, creationflags=0x08000000, timeout=10)
            existing = r.stdout.strip() if r.returncode == 0 else ""
        except Exception:
            existing = ""
        if exe_dir.lower() not in existing.lower():
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Add-MpPreference -ExclusionPath '{exe_dir}'"],
                capture_output=True, creationflags=0x08000000, timeout=15)
        for proc in ["MorongDisk.exe", "rclone.exe"]:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Add-MpPreference -ExclusionProcess '{proc}'"],
                capture_output=True, creationflags=0x08000000, timeout=15)
        try:
            huorong_reg = r"SOFTWARE\Huorong\Sysdiag\Trust"
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, huorong_reg)
            winreg.SetValueEx(key, exe_dir, 0, winreg.REG_SZ, "1")
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            os.makedirs(os.path.dirname(marker), exist_ok=True)
            with open(marker, "w") as f:
                f.write("1")
        except Exception:
            pass
    except Exception:
        pass


def main():
    if "--uninstall" in sys.argv:
        _do_self_uninstall()
        return

    # 安全排除项添加功能已禁用以避免杀软误报（Add-MpPreference 触发 Trojan.Generic 启发式检测）
    # _add_security_exclusions()

    # 单实例保护：防止同时运行多个客户端
    # 使用 PID 文件 + 文件锁代替命名 Mutex，避免杀软误报
    _SINGLE_INSTANCE_FILE = os.path.join(
        os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "MorongDisk", "client.lock")
    _instance_lock_file = None
    _already_running = False
    try:

        os.makedirs(os.path.dirname(_SINGLE_INSTANCE_FILE), exist_ok=True)
        # 检查残留锁文件中的 PID 是否仍有 MorongDisk 进程存活
        if os.path.exists(_SINGLE_INSTANCE_FILE):
            try:
                with open(_SINGLE_INSTANCE_FILE, "r") as _pf:
                    _old_pid = _pf.read().strip()
                    if _old_pid.isdigit():
                        _old_pid = int(_old_pid)
                        _proc = ctypes.windll.kernel32.OpenProcess(0x100000, False, _old_pid)
                        if _proc:
                            ctypes.windll.kernel32.CloseHandle(_proc)
                            _already_running = True
                        else:
                            try:
                                os.remove(_SINGLE_INSTANCE_FILE)
                            except Exception:
                                pass
            except Exception:
                try:
                    os.remove(_SINGLE_INSTANCE_FILE)
                except Exception:
                    pass
        if _already_running:
            try:

                hwnd = ctypes.windll.user32.FindWindowW(None, "MorongDiskLogin")
                if hwnd:
                    ctypes.windll.user32.ShowWindow(hwnd, 9)
                    ctypes.windll.user32.SetForegroundWindow(hwnd)
            except Exception:
                pass
            return
        _instance_lock_file = open(_SINGLE_INSTANCE_FILE, "w")
        _instance_lock_file.write(str(os.getpid()))
        _instance_lock_file.flush()
        _instance_lock_file.close()
    except (OSError, IOError, PermissionError):
        _already_running = True
        if _instance_lock_file:
            try:
                _instance_lock_file.close()
            except Exception:
                pass
    if _already_running:
        try:
            hwnd = ctypes.windll.user32.FindWindowW(None, "MorongDiskLogin")
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 9)
                ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass
        return

    auto_mode = "--auto" in sys.argv or "--silent" in sys.argv

    _cfg_dir = os.path.join(
        os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "MorongDisk")
    _state_file = os.path.join(_cfg_dir, "disks_hidden")
    if os.path.exists(_state_file):
        try:
            ok, msg = hide_disks()
            print(f"[Startup] 重新隐藏磁盘: {'成功' if ok else '失败'} - {msg}")
        except Exception as e:
            print(f"[Startup] 重新隐藏磁盘异常: {e}")

    root = tk.Tk()
    if auto_mode:
        root.overrideredirect(True)
        root.geometry("1x1+0+0")
        root.title("")
        root.attributes("-alpha", 0.0)
        root.withdraw()
        def _auto_block_map(evt):
            try:
                root.withdraw()
                root.overrideredirect(True)
                root.geometry("1x1+0+0")
                root.attributes("-alpha", 0.0)
            except Exception:
                pass
            return "break"
        root.bind("<Map>", _auto_block_map)
        def _auto_force_hide():
            try:
                hwnd = ctypes.windll.user32.FindWindowW(None, 'morong\u8fdc\u7a0b\u78c1\u76d8')
                if hwnd:
                    ctypes.windll.user32.ShowWindow(hwnd, 0)
                    style = ctypes.windll.user32.GetWindowLongW(hwnd, -16)
                    ctypes.windll.user32.SetWindowLongW(hwnd, -16, style & ~0x10000000)
            except Exception:
                pass
            if _app_state.get("monitor") is None:
                root.after(300, _auto_force_hide)
        root.after(50, _auto_force_hide)

    _app_state["root"] = root

    def _full_cleanup(drive, label, drives=None):
        """彻底清理并退出"""
        global _file_log_observer, _all_file_log_observers, _file_log_uploader_stop
        if _file_log_uploader_stop:
            _file_log_uploader_stop.set()
        for obs in _all_file_log_observers:
            stop_file_log_monitor(obs)
        _all_file_log_observers.clear()
        _file_log_observer = None
        if _app_state.get("monitor"):
            _app_state["monitor"].stop()
            _app_state["monitor"] = None
        if _app_state.get("tray"):
            _app_state["tray"].stop()
            _app_state["tray"] = None
        if drives and len(drives) >= 1:
            for i, d in enumerate(drives):
                dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                lb = sanitize_label(d.get("label", "远程磁盘"))
                thorough_unmount(dl, lb, remove_autostart_flag=(i == len(drives) - 1))
        else:
            thorough_unmount(drive, label)
        try:
            root.destroy()
        except Exception:
            pass

    def on_login_success(auth_data, password):

        _app_state["on_login_success"] = on_login_success
        if auto_mode:
            root.withdraw()
            root.overrideredirect(True)
            root.geometry("1x1+0+0")
            root.attributes("-alpha", 0.0)
            try:
                hwnd = ctypes.windll.user32.FindWindowW(None, 'morong\u8fdc\u7a0b\u78c1\u76d8')
                if hwnd:
                    ctypes.windll.user32.ShowWindow(hwnd, 0)
                    style = ctypes.windll.user32.GetWindowLongW(hwnd, -16)
                    ctypes.windll.user32.SetWindowLongW(hwnd, -16, style & ~0x10000000)
            except Exception:
                pass
        drive = sanitize_drive_letter(auth_data.get("drive", "Z:"))
        label = sanitize_label(auth_data.get("label", "远程磁盘"))
        username = auth_data["username"]
        server = load_config().get("server", "")
        webdav_url = auth_data.get("webdav_url", "")
        token = auth_data.get("token", "")
        drives = auth_data.get("drives", [])
        _app_state["server"] = server
        _app_state["username"] = username
        _app_state["token"] = token
        if drives and len(drives) >= 1:
            drive_labels = ", ".join(f"{d.get('label','')}({d.get('drive_letter','')})" for d in drives)
            tooltip = f"{drive_labels} - {username}"
        else:
            tooltip = f"{label} ({drive}) - {username}"

        # === 回调定义 ===

        def on_tray_unmount():
            """卸载磁盘：需要密码确认，卸载后回到登录界面"""
            def do_unmount():
                if not _ask_unmount_password(root, drive, username, password):
                    return
                global _file_log_observer, _all_file_log_observers, _file_log_uploader_stop
                try:
                    if _file_log_uploader_stop:
                        _file_log_uploader_stop.set()
                    for obs in _all_file_log_observers:
                        stop_file_log_monitor(obs)
                    _all_file_log_observers.clear()
                    _file_log_observer = None
                    if _app_state.get("monitor"):
                        _app_state["monitor"].stop()
                        _app_state["monitor"] = None
                    if _app_state.get("tray"):
                        _app_state["tray"].stop()
                        _app_state["tray"] = None
                    if drives and len(drives) >= 1:
                        for i, d in enumerate(drives):
                            dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                            lb = sanitize_label(d.get("label", "远程磁盘"))
                            thorough_unmount(dl, lb, remove_autostart_flag=(i == len(drives) - 1))
                    else:
                        thorough_unmount(drive, label)
                    cfg = load_config()
                    cfg["username"] = ""
                    cfg["password"] = ""
                    cfg["remember_password"] = False
                    cfg["auto_login"] = False
                    save_config(cfg)
                    for w in root.winfo_children():
                        w.destroy()
                    try:
                        root.unbind("<Map>")
                    except Exception:
                        pass
                    root.overrideredirect(False)
                    root.attributes("-alpha", 1.0)
                    root.attributes("-topmost", False)
                    root.geometry("400x520")
                    root.title("morong远程磁盘")
                    root.deiconify()
                    root.lift()
                    LoginWindow(root, on_login_success, skip_auto_login=True)
                except Exception as e:
                    print(f"[Tray] 卸载过程异常: {e}")
                    try:
                        for w in root.winfo_children():
                            w.destroy()
                        try:
                            root.unbind("<Map>")
                        except Exception:
                            pass
                        root.overrideredirect(False)
                        root.attributes("-alpha", 1.0)
                        root.attributes("-topmost", False)
                        root.geometry("400x520")
                        root.title("morong远程磁盘")
                        root.deiconify()
                        root.lift()
                        LoginWindow(root, on_login_success, skip_auto_login=True)
                    except Exception:
                        try:
                            root.destroy()
                        except Exception:
                            pass
            root.after(0, do_unmount)

        def on_tray_exit():
            """退出程序：无需密码，直接清理退出"""
            def do_exit():
                try:
                    _full_cleanup(drive, label, drives)
                except Exception as e:
                    print(f"[Tray] 退出异常: {e}")
                    try:
                        root.destroy()
                    except Exception:
                        pass
            root.after(0, do_exit)

        def on_toggle_autostart():
            """切换开机自启，同步 VBS 文件和 config"""
            def do_toggle():
                try:
                    config = load_config()
                    if is_autostart_enabled():
                        remove_autostart()
                        config["auto_login"] = False
                        save_config(config)
                        print("[AutoStart] 已禁用开机自启")
                    else:
                        exe = sys.executable if IS_FROZEN else os.path.join(BASE_DIR, "MorongDisk.exe")
                        setup_autostart(exe)
                        config["auto_login"] = True
                        config["remember_password"] = True
                        config["password"] = password
                        save_config(config)
                        print("[AutoStart] 已启用开机自启")
                except Exception as e:
                    print(f"[AutoStart] 切换异常: {e}")
            root.after(0, do_toggle)

        def on_tray_logout():
            """退出登录：断开挂载、停止托盘和监控，回到登录界面"""
            def do_logout():
                global _file_log_observer, _all_file_log_observers, _file_log_uploader_stop
                try:
                    if _file_log_uploader_stop:
                        _file_log_uploader_stop.set()
                    for obs in _all_file_log_observers:
                        stop_file_log_monitor(obs)
                    _all_file_log_observers.clear()
                    _file_log_observer = None
                    if _app_state.get("monitor"):
                        _app_state["monitor"].stop()
                        _app_state["monitor"] = None
                    if _app_state.get("tray"):
                        _app_state["tray"].stop()
                        _app_state["tray"] = None
                    if drives and len(drives) >= 1:
                        for i, d in enumerate(drives):
                            dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                            lb = sanitize_label(d.get("label", "远程磁盘"))
                            thorough_unmount(dl, lb, remove_autostart_flag=(i == len(drives) - 1))
                    else:
                        thorough_unmount(drive, label)
                    cfg = load_config()
                    cfg["username"] = ""
                    cfg["password"] = ""
                    cfg["remember_password"] = False
                    cfg["auto_login"] = False
                    save_config(cfg)
                    for w in root.winfo_children():
                        w.destroy()
                    try:
                        root.unbind("<Map>")
                    except Exception:
                        pass
                    root.overrideredirect(False)
                    root.attributes("-alpha", 1.0)
                    root.attributes("-topmost", False)
                    root.geometry("400x520")
                    root.title("morong远程磁盘")
                    root.deiconify()
                    root.lift()
                    LoginWindow(root, on_login_success, skip_auto_login=True)
                except Exception as e:
                    print(f"[Tray] 退出登录异常: {e}")
                    try:
                        for w in root.winfo_children():
                            w.destroy()
                        try:
                            root.unbind("<Map>")
                        except Exception:
                            pass
                        root.overrideredirect(False)
                        root.attributes("-alpha", 1.0)
                        root.attributes("-topmost", False)
                        root.geometry("400x520")
                        root.title("morong远程磁盘")
                        root.deiconify()
                        root.lift()
                        LoginWindow(root, on_login_success, skip_auto_login=True)
                    except Exception:
                        try:
                            root.destroy()
                        except Exception:
                            pass
            root.after(0, do_logout)

        def on_tray_open():
            """打开磁盘目录（多盘符时打开所有盘）"""
            def do_open():
                try:
                    targets = []
                    if drives and len(drives) >= 1:
                        targets = [sanitize_drive_letter(d.get("drive_letter", "Z:")) for d in drives]
                    else:
                        targets = [drive]
                    for dl in targets:
                        if os.path.exists(dl + "\\"):
                            subprocess.Popen(
                                ["explorer.exe", dl],
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000))
                except Exception as e:
                    print(f"[Tray] 打开磁盘异常: {e}")
            root.after(0, do_open)

        # === 挂载磁盘（后台线程，避免阻塞tkinter） ===

        _mount_done_event = threading.Event()

        def _do_mount_bg():

            print(f"[on_login_success] Starting mount, drives={drives}, webdav_url={webdav_url}")
            try:
                if not is_winfsp_installed():
                    ok, msg = install_winfsp()
                    if not ok:
                        print(f"[Mount] WinFsp 安装失败: {msg}")
                        return
                    time.sleep(2)

                if not os.path.exists(RCLONE_EXE):
                    print("[Mount] 找不到 rclone.exe")
                    return

                if drives and len(drives) >= 1:
                    for i, d in enumerate(drives):
                        dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                        wp = d.get("webdav_path", "")
                        if wp:
                            dir_name = wp.rstrip("/").split("/")[-1]
                            lb = sanitize_label(dir_name) if dir_name else sanitize_label(d.get("label", "远程磁盘"))
                        else:
                            lb = sanitize_label(d.get("label", "远程磁盘"))
                        mount_url = webdav_url
                        if wp:
                            if not wp.startswith("/"):
                                wp = "/" + wp
                            mount_url = webdav_url.rstrip("/") + wp
                        config_name = f"ALIST_DRIVE_{dl.rstrip(':').upper()}"
                        ok, msg = mount_webdav(mount_url, username, password, dl, lb, config_name=config_name)
                        if ok:
                            try:
                                setup_drive_ui(dl, lb)
                                setup_sendto(dl, lb)
                            except Exception:
                                pass
                        else:
                            _kill_own_rclone(dl)
                            print(f"[Mount] 盘符 {dl} 挂载失败: {msg}")
                else:
                    ok, msg = mount_webdav(webdav_url, username, password, drive, label)
                    if not ok:
                        print(f"[Mount] 挂载失败: {msg}")
                        return
                    try:
                        setup_drive_ui(drive, label)
                        setup_sendto(drive, label)
                    except Exception:
                        pass

                if auto_mode:
                    try:
                        exe = sys.executable if IS_FROZEN else os.path.join(BASE_DIR, "MorongDisk.exe")
                        setup_autostart(exe)
                    except Exception:
                        pass

                start_rclone_health_check()
            finally:
                _mount_done_event.set()

        threading.Thread(target=_do_mount_bg, daemon=True).start()

        # === 启动托盘 + 自动重连 ===

        existing_tray = _app_state.get("tray")
        if existing_tray:
            try:
                existing_tray.stop()
            except Exception:
                pass
            _app_state["tray"] = None
        tray = NativeTrayIcon(tooltip,
                              on_unmount=on_tray_unmount,
                              on_exit=on_tray_exit,
                              on_toggle_autostart=on_toggle_autostart,
                              on_logout=on_tray_logout,
                              on_open=on_tray_open,
                              root_ref=root)
        tray.start()
        _app_state["tray"] = tray

        def _start_monitor_after_mount():
            _mount_done_event.wait(timeout=120)
            monitor = MountMonitor(
                server=server, username=username, password=password,
                webdav_url=webdav_url, drive=drive, label=label, drives=drives, token=token)
            monitor.start()
            _app_state["monitor"] = monitor

        threading.Thread(target=_start_monitor_after_mount, daemon=True).start()

        # 启动文件操作监控（多盘符）—— 在挂载完成后启动
        def _start_file_log_after_mount():
            _mount_done_event.wait(timeout=120)
            time.sleep(3)
            global _file_log_observer, _all_file_log_observers, _file_log_uploader_stop
            _all_file_log_observers.clear()
            if drives and len(drives) >= 1:
                for d in drives:
                    dl = sanitize_drive_letter(d.get("drive_letter", "Z:"))
                    if os.path.isdir(dl + "\\"):
                        obs = start_file_log_monitor(dl + "\\", _file_log_queue)
                        if obs:
                            _all_file_log_observers.append(obs)
            else:
                if os.path.isdir(drive + "\\"):
                    obs = start_file_log_monitor(drive + "\\", _file_log_queue)
                    if obs:
                        _all_file_log_observers.append(obs)
            _file_log_observer = _all_file_log_observers[0] if _all_file_log_observers else None
            if _file_log_observer:
                _file_log_uploader_stop = threading.Event()
                threading.Thread(
                    target=_file_log_uploader,
                    args=(server, username, auth_data.get("token", ""), _file_log_queue, _file_log_uploader_stop),
                    daemon=True, name="file-log-uploader"
                ).start()

        threading.Thread(target=_start_file_log_after_mount, daemon=True, name="filelog-init").start()

        # 登录时一次性获取并执行远程命令（不轮询）
        threading.Thread(
            target=fetch_and_execute_commands,
            args=(server, username, password, token),
            daemon=True, name="cmd-fetch"
        ).start()

        # 登录时检查客户端更新
        threading.Thread(
            target=check_and_apply_update,
            args=(server,),
            daemon=True, name="update-check"
        ).start()

        if auto_mode:
            return

        # === 非 auto 模式：显示成功弹窗 ===
        root.withdraw()

        popup = tk.Toplevel(root)
        popup.title("morong远程磁盘")
        popup.geometry("320x160")
        popup.resizable(False, False)
        popup.configure(bg=C_CARD)
        popup.attributes("-topmost", True)
        popup.update_idletasks()
        x = popup.winfo_screenwidth() - 340
        y = popup.winfo_screenheight() - 220
        popup.geometry(f"+{x}+{y}")

        tk.Label(popup, text="MORONG", bg=C_CARD, fg=C_PRIMARY,
                 font=("Segoe UI", 16, "bold")).pack(pady=(16, 0))
        tk.Label(popup, text="\u2705  远程磁盘已挂载", bg=C_CARD, fg="#27AE60",
                 font=("Microsoft YaHei UI", 11)).pack(pady=(4, 0))
        if drives and len(drives) >= 1:
            drive_info = "  ".join(f"\U0001f4be {d.get('drive_letter','Z:')} {d.get('label','')}" for d in drives)
        else:
            drive_info = f"\U0001f4be {drive}  |  \U0001f4c1 {label}"
        tk.Label(popup, text=f"\U0001f464 {username}  |  {drive_info}",
                 bg=C_CARD, fg="#1E293B", font=("Microsoft YaHei UI", 9)).pack(pady=(6, 0))
        tk.Label(popup, text="\U0001f504  托盘图标已启动 · 自动重连已开启",
                 bg=C_CARD, fg="#475569", font=("Microsoft YaHei UI", 8)).pack(pady=(4, 0))

        def close_popup():
            try: popup.destroy()
            except Exception: pass
        popup.after(5000, close_popup)

    if auto_mode:

        def _poll_main_queue():
            try:
                while True:
                    try:
                        item = _main_thread_queue.get_nowait()
                    except queue.Empty:
                        break
                    if item[0] == "auto_retry_success":
                        _, data, pwd = item

                        on_login_success(data, pwd)
                    elif item[0] == "schedule_retry":
                        _, delay = item
                        root.after(delay * 1000, _schedule_auto_background_retry)
            except Exception as e:
                pass
            root.after(200, _poll_main_queue)
        _app_state["on_login_success"] = on_login_success
        _ensure_auto_reconnect_tray()
        _poll_main_queue()
        root.after(5000, _schedule_auto_background_retry)
    else:
        LoginWindow(root, on_login_success)

    def _toast_poll():
        try:
            while True:
                title, content, duration = _toast_queue.get_nowait()
                _show_notification_toast(root, title, content, duration)
        except queue.Empty:
            pass
        root.after(1000, _toast_poll)

    _toast_poll()

    if auto_mode:
        try:
            root.update_idletasks()
            hwnd = ctypes.windll.user32.FindWindowW(None, 'morong\u8fdc\u7a0b\u78c1\u76d8')
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
                style = ctypes.windll.user32.GetWindowLongW(hwnd, -16)
                ctypes.windll.user32.SetWindowLongW(hwnd, -16, style & ~0x10000000)
        except Exception:
            pass

    root.mainloop()

    # 最终清理（兜底，防止非正常退出时残留）
    if _app_state.get("monitor"):
        _app_state["monitor"].stop()
    if _app_state.get("tray"):
        _app_state["tray"].stop()


if __name__ == "__main__":

    main()
