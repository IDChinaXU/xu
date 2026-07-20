#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MorongDisk Auth Server v1.16.0
远程磁盘统一认证服务 + AList 双向同步
"""

import os
import sys
import json
import time
import hmac
import hashlib
import base64
import sqlite3
import secrets
import argparse
import logging
import threading
import re
from datetime import datetime
from functools import wraps
from collections import defaultdict

from flask import Flask, request, jsonify, render_template_string, g
import requests as http_requests
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ============================================================
# Configuration
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
DB_PATH = os.path.join(BASE_DIR, "auth.db")
CONFIG_PATH = os.path.join(BASE_DIR, "server_config.json")

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 9800,
    "secret_key": "",
    "token_expire_days": 365,
    "default_webdav_url": "http://192.168.100.242:5244/dav",
    "default_drive": "Z:",
    "default_label": "远程磁盘",
    "alist_url": "http://192.168.100.242:5244",
    "alist_token": "",
    "alist_admin_user": "",
    "alist_admin_pass": "",
    "alist_token_expire": 0,
    "alist_sync_on_login": True,
}


def load_config():
    config = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config.update(json.load(f))
    if not config["secret_key"]:
        config["secret_key"] = secrets.token_hex(32)
        save_config(config)
    return config


def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


CONFIG = load_config()

log = logging.getLogger("werkzeug")
log.setLevel(logging.WARNING)


# ============================================================
# RSA Key Pair (密码传输加密)
# ============================================================

RSA_KEY_PATH = os.path.join(BASE_DIR, "rsa_private.pem")

def _derive_key_from_secret(secret, salt=b"morong-rsa-key-v1"):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))

def _load_or_generate_rsa_key():
    enc_path = RSA_KEY_PATH + ".enc"
    if os.path.exists(enc_path):
        try:
            with open(enc_path, "rb") as f:
                enc_data = f.read()
            key_bytes = _derive_key_from_secret(CONFIG["secret_key"])
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
            try:
                from cryptography.hazmat.decrepit.ciphers.modes import CFB8
            except ImportError:
                from cryptography.hazmat.primitives.ciphers.modes import CFB8
            iv = enc_data[:16]
            ct = enc_data[16:]
            cipher = Cipher(algorithms.AES(key_bytes[:32]), CFB8(iv))
            decryptor = cipher.decryptor()
            pem_data = decryptor.update(ct) + decryptor.finalize()
            return serialization.load_pem_private_key(pem_data, password=None)
        except Exception as e:
            logging.error(f"[RSA] 加密密钥文件解密失败: {e}")
    if os.path.exists(RSA_KEY_PATH):
        try:
            with open(RSA_KEY_PATH, "rb") as f:
                pem_data = f.read()
            key = serialization.load_pem_private_key(pem_data, password=None)
            _save_rsa_key_encrypted(key)
            try:
                os.remove(RSA_KEY_PATH)
            except Exception:
                pass
            return key
        except Exception as e:
            logging.error(f"[RSA] 明文密钥文件加载失败: {e}")
    key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _save_rsa_key_encrypted(key)
    return key

def _save_rsa_key_encrypted(key):
    try:
        pem_data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        key_bytes = _derive_key_from_secret(CONFIG["secret_key"])
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:
            from cryptography.hazmat.decrepit.ciphers.modes import CFB8
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.modes import CFB8
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_bytes[:32]), CFB8(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(pem_data) + encryptor.finalize()
        enc_path = RSA_KEY_PATH + ".enc"
        with open(enc_path, "wb") as f:
            f.write(iv + ct)
    except Exception as e:
        logging.error(f"[RSA] 密钥加密保存失败: {e}")

_RSA_PRIVATE_KEY = _load_or_generate_rsa_key()

def _rsa_public_key_pem():
    return _RSA_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

def _rsa_decrypt_password(encrypted_b64):
    try:
        ciphertext = base64.b64decode(encrypted_b64)
        plaintext = _RSA_PRIVATE_KEY.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        return plaintext.decode("utf-8")
    except Exception:
        return None


# ============================================================
# Brute-force Protection (登录暴力破解防护)
# ============================================================

_LOGIN_ATTEMPTS = defaultdict(lambda: {"count": 0, "locked_until": 0, "last_attempt": 0})
_LOGIN_ATTEMPTS_LOCK = threading.Lock()
_MAX_LOGIN_ATTEMPTS = 5
_LOGIN_LOCK_SECONDS = 300

def _check_login_rate(username, ip):
    with _LOGIN_ATTEMPTS_LOCK:
        key = f"{username}|{ip}"
        info = _LOGIN_ATTEMPTS[key]
        if info["locked_until"] > time.time():
            remaining = int(info["locked_until"] - time.time())
            return False, f"登录失败次数过多，请{remaining}秒后重试"
        return True, None

def _record_login_failure(username, ip):
    with _LOGIN_ATTEMPTS_LOCK:
        key = f"{username}|{ip}"
        info = _LOGIN_ATTEMPTS[key]
        info["count"] += 1
        info["last_attempt"] = time.time()
        if info["count"] >= _MAX_LOGIN_ATTEMPTS:
            info["locked_until"] = time.time() + _LOGIN_LOCK_SECONDS
            info["count"] = 0
        _cleanup_login_attempts_unlocked()

def _record_login_success(username, ip):
    with _LOGIN_ATTEMPTS_LOCK:
        key = f"{username}|{ip}"
        if key in _LOGIN_ATTEMPTS:
            del _LOGIN_ATTEMPTS[key]
        _cleanup_login_attempts_unlocked()

def _cleanup_login_attempts_unlocked():
    now = time.time()
    expired = [k for k, v in _LOGIN_ATTEMPTS.items()
               if (v["locked_until"] > 0 and v["locked_until"] < now)
               or (v["locked_until"] == 0 and v["last_attempt"] > 0 and now - v["last_attempt"] > 3600)]
    for k in expired:
        del _LOGIN_ATTEMPTS[k]


# ============================================================
# Input Validation (输入验证)
# ============================================================

_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\u4e00-\u9fff]{1,32}$')
_MAX_PASSWORD_LEN = 128
_MAX_FIELD_LEN = 256

def validate_username(username):
    if not username or not _USERNAME_RE.match(username):
        return False, "用户名仅支持中英文、数字、下划线，1-32字符"
    return True, None

def validate_password_length(password):
    if not password or len(password) < 1:
        return False, "密码不能为空"
    if len(password) > _MAX_PASSWORD_LEN:
        return False, f"密码长度不能超过{_MAX_PASSWORD_LEN}字符"
    return True, None

def sanitize_string(value, max_len=_MAX_FIELD_LEN):
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if len(value) > max_len:
        value = value[:max_len]
    return value


def _sanitize_webdav_path(path):
    import posixpath
    path = sanitize_string(path, 512)
    if not path:
        return ""
    if ".." in path:
        return ""
    normalized = posixpath.normpath(path)
    if normalized.startswith("..") or normalized.endswith(".."):
        return ""
    return normalized


# ============================================================
# Password / JWT
# ============================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return salt + ":" + h.hex()


_DUMMY_HASH = hash_password("timing_attack_dummy")


def verify_password(password, stored_hash):
    try:
        salt, h = stored_hash.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return hmac.compare_digest(check.hex(), h)
    except Exception:
        return False


_JTI_STORE = {}
_JTI_STORE_LOCK = threading.Lock()
_JTI_MAX_ENTRIES = 5000
_JTI_REPLAY_WINDOW = 5

def _check_and_register_jti(jti):
    with _JTI_STORE_LOCK:
        now = time.time()
        if jti in _JTI_STORE:
            if now - _JTI_STORE[jti] < _JTI_REPLAY_WINDOW:
                return False
        _JTI_STORE[jti] = now
        if len(_JTI_STORE) > _JTI_MAX_ENTRIES:
            expired = [k for k, v in _JTI_STORE.items() if now - v > 86400]
            if expired:
                for k in expired:
                    del _JTI_STORE[k]
            else:
                sorted_items = sorted(_JTI_STORE.items(), key=lambda x: x[1])
                for k, _ in sorted_items[:len(sorted_items) // 10]:
                    del _JTI_STORE[k]
        return True

def jwt_encode(payload):
    header = {"alg": "HS256", "typ": "JWT"}
    payload["iat"] = int(time.time())
    payload["jti"] = secrets.token_hex(16)
    h = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b"=")
    p = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).rstrip(b"=")
    sig = hmac.new(CONFIG["secret_key"].encode(), h + b"." + p, hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return (h + b"." + p + b"." + s).decode()


def jwt_decode(token):
    try:
        if len(token) > 2048:
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, s = parts
        if len(h) > 512 or len(p) > 1024 or len(s) > 512:
            return None
        header = json.loads(base64.urlsafe_b64decode(h + "=="))
        if header.get("alg") != "HS256":
            return None
        expected = hmac.new(CONFIG["secret_key"].encode(), h.encode() + b"." + p.encode(), hashlib.sha256).digest()
        actual = base64.urlsafe_b64decode(s + "==")
        if not hmac.compare_digest(expected, actual):
            return None
        payload = json.loads(base64.urlsafe_b64decode(p + "=="))
        if payload.get("exp", 0) < time.time():
            return None


        return payload
    except Exception:
        return None


# ============================================================
# Database
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_db()
    try:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            webdav_url TEXT DEFAULT '',
            drive_letter TEXT DEFAULT 'Z:',
            label TEXT DEFAULT '远程磁盘',
            alist_id INTEGER DEFAULT 0,
            alist_base_path TEXT DEFAULT '/公司文件',
            alist_role_id INTEGER DEFAULT 0,
            alist_disabled INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT DEFAULT ''
        )
    """)
        for col, default in [
            ("alist_id", "0"), ("alist_base_path", "'/公司文件'"),
            ("alist_role_id", "0"), ("alist_disabled", "0"),
            ("alist_role", "''"), ("alist_enabled", "0"),
            ("last_heartbeat", "''"), ("disk_hidden", "0"),
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
            except Exception:
                pass

        conn.execute("""
        CREATE TABLE IF NOT EXISTS hardware_info (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            hostname TEXT DEFAULT '',
            os_info TEXT DEFAULT '',
            bios_sn TEXT DEFAULT '',
            bios_vendor TEXT DEFAULT '',
            cpu_model TEXT DEFAULT '',
            cpu_cores INTEGER DEFAULT 0,
            cpu_threads INTEGER DEFAULT 0,
            cpu_speed TEXT DEFAULT '',
            cpu_cache TEXT DEFAULT '',
            ram_total_gb REAL DEFAULT 0,
            ram_details TEXT DEFAULT '',
            gpu_info TEXT DEFAULT '',
            disk_info TEXT DEFAULT '',
            network_info TEXT DEFAULT '',
            monitor_info TEXT DEFAULT '',
            raw_json TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS remote_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            command_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            result TEXT DEFAULT '',
            created_at TEXT DEFAULT '',
            executed_at TEXT DEFAULT ''
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS file_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            path TEXT NOT NULL,
            dest_path TEXT DEFAULT '',
            is_dir INTEGER DEFAULT 0,
            file_size INTEGER DEFAULT 0,
            drive_letter TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
        try:
            conn.execute("SELECT drive_letter FROM file_logs LIMIT 1")
        except Exception:
            conn.execute("ALTER TABLE file_logs ADD COLUMN drive_letter TEXT DEFAULT ''")


        conn.execute("""
        CREATE TABLE IF NOT EXISTS recycle_bin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            original_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            is_dir INTEGER DEFAULT 0,
            deleted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT DEFAULT '',
            deleted_by TEXT DEFAULT '',
            remark TEXT DEFAULT ''
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS recycle_delete_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            file_name TEXT NOT NULL,
            original_path TEXT DEFAULT '',
            file_size INTEGER DEFAULT 0,
            deleted_by TEXT DEFAULT '',
            remark TEXT DEFAULT '',
            deleted_at TEXT DEFAULT '',
            permanent_deleted_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_quotas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            quota_mb INTEGER DEFAULT 0,
            used_mb REAL DEFAULT 0,
            updated_at TEXT DEFAULT ''
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT DEFAULT '',
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            duration INTEGER DEFAULT 5,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            path TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS user_drives (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            drive_letter TEXT NOT NULL DEFAULT 'Z:',
            label TEXT DEFAULT '远程磁盘',
            webdav_path TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
        try:
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_drives_uniq ON user_drives(username, drive_letter)")
        except Exception:
            pass

        conn.commit()
        row = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not row:
            conn.execute("INSERT INTO users (username, password_hash, alist_id) VALUES (?, ?, ?)",
                         ("admin", hash_password("admin123"), 2))
            conn.commit()
            print("  [*] 已创建默认管理员: admin / admin123")

        try:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(recycle_bin)").fetchall()]
            if "deleted_by" not in cols:
                conn.execute("ALTER TABLE recycle_bin ADD COLUMN deleted_by TEXT DEFAULT ''")
            if "remark" not in cols:
                conn.execute("ALTER TABLE recycle_bin ADD COLUMN remark TEXT DEFAULT ''")
            conn.commit()
        except Exception:
            pass
    finally:
        conn.close()


def get_user(username):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_alist_id(alist_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE alist_id=?", (alist_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_user(username, password, webdav_url="", drive_letter="Z:", label="远程磁盘",
                alist_id=0, alist_base_path="/公司文件", alist_role_id=0):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, webdav_url, drive_letter, label,"
            " alist_id, alist_base_path, alist_role_id) VALUES (?,?,?,?,?,?,?,?)",
            (username, hash_password(password), webdav_url, drive_letter, label,
             alist_id, alist_base_path, alist_role_id),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_user(username, **kwargs):
    conn = get_db()
    try:
        allowed = {"password_hash", "webdav_url", "drive_letter", "label", "active",
                   "alist_id", "alist_base_path", "alist_role_id", "alist_disabled"}
        sets, vals = [], []
        for k, v in kwargs.items():
            if k in allowed:
                sets.append(f"{k}=?")
                vals.append(v)
        if not sets:
            return False
        vals.append(username)
        conn.execute(f"UPDATE users SET {','.join(sets)} WHERE username=?", vals)
        conn.commit()
        return True
    finally:
        conn.close()


def delete_user_db(username):
    conn = get_db()
    try:
        for table in ("user_drives", "hardware_info", "remote_commands",
                      "file_logs", "notifications", "bookmarks",
                      "user_quotas", "recycle_bin", "audit_logs"):
            try:
                conn.execute(f"DELETE FROM {table} WHERE username=?", (username,))
            except Exception:
                pass
        conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
    finally:
        conn.close()


def list_users():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, username, webdav_url, drive_letter, label, alist_id, alist_base_path,"
            " alist_role_id, alist_disabled, active, created_at, last_login, last_heartbeat, disk_hidden FROM users"
        ).fetchall()
        result = [dict(r) for r in rows]
        usernames = [u["username"] for u in result]
        drives_map = {}
        if usernames:
            placeholders = ",".join("?" * len(usernames))
            drive_rows = conn.execute(
                f"SELECT id, username, drive_letter, label, webdav_path, sort_order"
                f" FROM user_drives WHERE username IN ({placeholders}) ORDER BY sort_order, id",
                usernames
            ).fetchall()
            for dr in drive_rows:
                drives_map.setdefault(dr["username"], []).append(dict(dr))
        for u in result:
            u["drives"] = drives_map.get(u["username"], [])
        return result
    finally:
        conn.close()


def record_login(username):
    conn = get_db()
    try:
        conn.execute("UPDATE users SET last_login=? WHERE username=?", (datetime.now().isoformat(), username))
        conn.commit()
    finally:
        conn.close()


def get_user_drives(username):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, drive_letter, label, webdav_path, sort_order FROM user_drives"
            " WHERE username=? ORDER BY sort_order, id",
            (username,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def sanitize_drive_letter(drive):
    if not drive:
        return "Z:"
    d = str(drive).strip().upper()
    if len(d) >= 2 and d[1] == ':':
        return d[:2]
    if len(d) == 1 and d.isalpha():
        return d + ":"
    return "Z:"


def set_user_drives(username, drives):
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM user_drives WHERE username=?", (username,))
        for i, d in enumerate(drives):
            dl = d.get("drive_letter", "Z:")
            lb = d.get("label", "远程磁盘")
            wp = d.get("webdav_path", "")
            so = d.get("sort_order", i)
            conn.execute(
                "INSERT INTO user_drives (username, drive_letter, label, webdav_path, sort_order)"
                " VALUES (?,?,?,?,?)",
                (username, dl, lb, wp, so),
            )
        conn.commit()
        return True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        return False
    finally:
        conn.close()


def add_user_drive(username, drive_letter, label="远程磁盘", webdav_path="", sort_order=0):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO user_drives (username, drive_letter, label, webdav_path, sort_order)"
            " VALUES (?,?,?,?,?)",
            (username, drive_letter, label, webdav_path, sort_order),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def delete_user_drive(username, drive_letter):
    conn = get_db()
    try:
        conn.execute("DELETE FROM user_drives WHERE username=? AND drive_letter=?",
                      (username, drive_letter))
        conn.commit()
    finally:
        conn.close()


def record_heartbeat(username, disk_hidden=None):
    conn = get_db()
    try:
        if disk_hidden is not None:
            conn.execute("UPDATE users SET last_heartbeat=?, disk_hidden=? WHERE username=?",
                         (datetime.now().isoformat(), "1" if disk_hidden else "0", username))
        else:
            conn.execute("UPDATE users SET last_heartbeat=? WHERE username=?", (datetime.now().isoformat(), username))
        conn.commit()
    finally:
        conn.close()


# ============================================================
# AList Admin API  (自动刷新 Token)
# ============================================================

_alist_token_lock = threading.Lock()
_remount_users_lock = threading.Lock()
_remount_users = set()  # 用户名集合：base_path 被修正后需要客户端重新挂载


def _alist_base():
    return CONFIG.get("alist_url", "").rstrip("/")


def _alist_headers(token=None):
    t = token or CONFIG.get("alist_token", "")
    return {"Authorization": t, "Content-Type": "application/json"} if t else {"Content-Type": "application/json"}


def alist_refresh_token():
    """用管理员凭据登录 AList，刷新 token。线程安全。"""
    base = _alist_base()
    admin_user = CONFIG.get("alist_admin_user", "")
    admin_pass = CONFIG.get("alist_admin_pass", "")
    if not base or not admin_user or not admin_pass:
        logging.warning("[AList] 无法刷新 token: 缺少地址或管理员凭据")
        return False, "缺少 AList 地址或管理员凭据"
    try:
        r = http_requests.post(f"{base}/api/auth/login",
                               json={"username": admin_user, "password": admin_pass}, timeout=15)
        d = r.json()
        if d.get("code") == 200:
            new_token = d.get("data", {}).get("token", "")
            if new_token:
                with _alist_token_lock:
                    CONFIG["alist_token"] = new_token
                    CONFIG["alist_token_expire"] = int(time.time()) + 86400  # 24h
                    save_config(CONFIG)
                logging.info("[AList] Token 刷新成功，有效期 24h")
                return True, None
        return False, d.get("message", "登录失败")
    except Exception as e:
        logging.error(f"[AList] Token 刷新异常: {e}")
        return False, str(e)


def alist_ensure_token():
    """检查 token 是否有效，过期则自动刷新。"""
    with _alist_token_lock:
        expire = CONFIG.get("alist_token_expire", 0)
        token = CONFIG.get("alist_token", "")
        if token and expire and expire - time.time() > 600:
            return True, None
    logging.info("[AList] Token 已过期或即将过期，自动刷新...")
    return alist_refresh_token()


def _alist_request(method, path, retry=True, **kwargs):
    """统一的 AList API 请求封装，token 失效时自动刷新重试一次。"""
    alist_ensure_token()
    base = _alist_base()
    if not base:
        return None, "未配置 AList 地址"
    url = f"{base}{path}"
    headers = _alist_headers()
    kwargs.setdefault("timeout", 15)
    try:
        r = getattr(http_requests, method)(url, headers=headers, **kwargs)
        d = r.json()
        # token 失效(401/403) 且允许重试 → 刷新后重试一次
        if retry and r.status_code in (401, 403):
            logging.info(f"[AList] API 返回 {r.status_code}，尝试刷新 token 后重试")
            ok, err = alist_refresh_token()
            if ok:
                return _alist_request(method, path, retry=False, **kwargs)
            return None, f"Token 刷新失败: {err}"
        return d, None
    except Exception as e:
        return None, str(e)


def alist_login(username, password):
    """用凭据尝试登录 AList（用于代理验证，不走 admin token）"""
    base = _alist_base()
    if not base:
        return False, None
    try:
        r = http_requests.post(f"{base}/api/auth/login",
                               json={"username": username, "password": password}, timeout=10)
        d = r.json()
        return d.get("code") == 200, d.get("data", {}).get("token") if d.get("code") == 200 else None
    except Exception:
        return False, None


def alist_get_me(user_token):
    """用用户自己的 token 调用 /api/me 获取用户信息（id, base_path, role）。
    不依赖 admin token，比 _alist_request 更可靠。"""
    base = _alist_base()
    if not base or not user_token:
        return None
    try:
        r = http_requests.get(f"{base}/api/me",
                              headers=_alist_headers(user_token), timeout=10)
        d = r.json()
        if d.get("code") == 200:
            return d.get("data")
        logging.warning(f"[AList] /api/me 返回 code={d.get('code')}: {d.get('message', '')}")
    except Exception as e:
        logging.error(f"[AList] /api/me 异常: {e}")
    return None


def alist_get_users(token=None):
    """获取 AList 全部用户"""
    if token:
        # 直接用传入的 token（CLI 场景）
        base = _alist_base()
        if not base:
            return None, "未配置 AList 地址"
        try:
            r = http_requests.get(f"{base}/api/admin/user/list",
                                  headers=_alist_headers(token), timeout=15)
            d = r.json()
            if d.get("code") == 200:
                content = d.get("data", {})
                if isinstance(content, dict):
                    return content.get("content", []), None
                return content if isinstance(content, list) else [], None
            return None, d.get("message", "未知错误")
        except Exception as e:
            return None, str(e)
    d, err = _alist_request("get", "/api/admin/user/list")
    if err:
        return None, err
    if d.get("code") == 200:
        content = d.get("data", {})
        if isinstance(content, dict):
            return content.get("content", []), None
        return content if isinstance(content, list) else [], None
    return None, d.get("message", "未知错误")


def alist_create_user(username, password, base_path="/公司文件", role_id=0, disabled=False, token=None):
    """在 AList 中创建用户"""
    # 有角色时 base_path 设为角色权限路径的公共父目录，减少 WebDAV 目录层级
    effective_bp = _role_base_path(role_id) if role_id else (base_path or "/公司文件")
    payload = {
        "username": username, "password": password,
        "base_path": effective_bp, "role": [role_id],
        "disabled": disabled, "permission": 0, "sso_id": ""
    }

    if token:
        base = _alist_base()
        if not base:
            return None, "未配置 AList"
        try:
            r = http_requests.post(f"{base}/api/admin/user/create",
                                   json=payload, headers=_alist_headers(token), timeout=15)
            d = r.json()
            if d.get("code") == 200:

                return (True, None)
            return (None, d.get("message", "创建失败"))
        except Exception as e:
            return None, str(e)
    d, err = _alist_request("post", "/api/admin/user/create", json=payload)
    if err:
        return None, err
    if d.get("code") == 200:

        return (True, None)
    return (None, d.get("message", "创建失败"))


def alist_update_user(alist_id, username, password=None, base_path=None,
                      role_id=None, disabled=None, token=None):
    """更新 AList 用户"""
    if not alist_id:
        return None, "缺少 AList ID"
    # 有角色时 base_path 设为角色权限路径的公共父目录，减少 WebDAV 目录层级
    effective_role = role_id if role_id is not None else 0
    if effective_role:
        effective_bp = _role_base_path(effective_role)
    elif base_path is not None:
        effective_bp = base_path
    else:
        # base_path 未指定且无角色时，保留数据库中已有的路径
        existing = get_user(username)
        effective_bp = (existing or {}).get("alist_base_path", "/公司文件") or "/公司文件"
    payload = {"id": alist_id, "username": username,
               "base_path": effective_bp,
               "role": [effective_role],
               "disabled": disabled if disabled is not None else False,
               "permission": 0, "sso_id": ""}
    if password:
        payload["password"] = password

    if token:
        base = _alist_base()
        if not base:
            return None, "缺少配置"
        try:
            r = http_requests.post(f"{base}/api/admin/user/update",
                                   json=payload, headers=_alist_headers(token), timeout=15)
            d = r.json()
            if d.get("code") == 200:
                return (True, None)
            return (None, d.get("message", "更新失败"))
        except Exception as e:
            return None, str(e)
    d, err = _alist_request("post", "/api/admin/user/update", json=payload)
    if err:
        return None, err
    if d.get("code") == 200:
        return (True, None)
    return (None, d.get("message", "更新失败"))


def alist_delete_user(alist_id, token=None):
    """删除 AList 用户"""
    if not alist_id:
        return None, "缺少 AList ID"
    if token:
        base = _alist_base()
        if not base:
            return None, "缺少配置"
        try:
            r = http_requests.post(f"{base}/api/admin/user/delete?id={alist_id}",
                                   headers=_alist_headers(token), timeout=15)
            d = r.json()
            return (True, None) if d.get("code") == 200 else (None, d.get("message", "删除失败"))
        except Exception as e:
            return None, str(e)
    d, err = _alist_request("post", f"/api/admin/user/delete?id={alist_id}")
    if err:
        return None, err
    return (True, None) if d.get("code") == 200 else (None, d.get("message", "删除失败"))


def alist_get_user(alist_id, token=None):
    """获取单个 AList 用户"""
    if token:
        base = _alist_base()
        if not base:
            return None, "未配置"
        try:
            r = http_requests.get(f"{base}/api/admin/user/get?id={alist_id}",
                                  headers=_alist_headers(token), timeout=15)
            d = r.json()
            return (d.get("data"), None) if d.get("code") == 200 else (None, d.get("message", "获取失败"))
        except Exception as e:
            return None, str(e)
    d, err = _alist_request("get", f"/api/admin/user/get?id={alist_id}")
    if err:
        return None, err
    return (d.get("data"), None) if d.get("code") == 200 else (None, d.get("message", "获取失败"))


def alist_get_roles(token=None):
    """获取 AList 所有角色，返回 {role_id: [缩短后的最终路径名, ...]}
    AList v3 角色 API 返回 permission_scopes: [{path, permission}, ...]"""
    def _extract_paths(content):
        role_paths = {}
        for role in content:
            rid = role.get("id", 0)
            if not rid:
                continue
            scopes = role.get("permission_scopes", [])
            if not isinstance(scopes, list):
                scopes = []
            short = []
            seen = set()
            for sc in scopes:
                if not isinstance(sc, dict):
                    continue
                bp = sc.get("path", "")
                if bp and bp != "/":
                    name = bp.rstrip("/").split("/")[-1]
                    if name and name not in seen:
                        short.append(name)
                        seen.add(name)
            role_paths[rid] = short
        return role_paths

    def _do_request(t):
        base = _alist_base()
        if not base:
            return None, "未配置 AList 地址"
        r = http_requests.get(f"{base}/api/admin/role/list",
                              headers=_alist_headers(t), timeout=15)
        d = r.json()
        if d.get("code") != 200:
            return None, d.get("message", "获取角色列表失败")
        content = d.get("data", [])
        if isinstance(content, dict):
            content = content.get("content", [])
        if not isinstance(content, list):
            content = []
        return _extract_paths(content), None

    if token:
        return _do_request(token)
    d, err = _alist_request("get", "/api/admin/role/list")
    if err:
        return None, err
    content = d.get("data", [])
    if isinstance(content, dict):
        content = content.get("content", [])
    if not isinstance(content, list):
        content = []
    return _extract_paths(content), None


def alist_get_roles_raw(token=None):
    """获取 AList 原始角色列表，返回 [{id, name, base_path, description}, ...]
    用于管理后台角色下拉选择"""
    def _extract_roles(content):
        roles = []
        for role in content:
            if not isinstance(role, dict):
                continue
            rid = role.get("id", 0)
            if not rid:
                continue
            scopes = role.get("permission_scopes", [])
            if not isinstance(scopes, list):
                scopes = []
            bp = _common_parent_path([s.get("path", "") for s in scopes if isinstance(s, dict)])
            roles.append({
                "id": rid,
                "name": role.get("name", ""),
                "description": role.get("description", ""),
                "base_path": bp,
                "permission_scopes": scopes,
            })
        return roles

    def _do_request(t):
        base = _alist_base()
        if not base:
            return None, "未配置 AList 地址"
        r = http_requests.get(f"{base}/api/admin/role/list",
                              headers=_alist_headers(t), timeout=15)
        d = r.json()
        if d.get("code") != 200:
            return None, d.get("message", "获取角色列表失败")
        content = d.get("data", [])
        if isinstance(content, dict):
            content = content.get("content", [])
        if not isinstance(content, list):
            content = []
        return _extract_roles(content), None

    if token:
        return _do_request(token)
    d, err = _alist_request("get", "/api/admin/role/list")
    if err:
        return None, err
    content = d.get("data", [])
    if isinstance(content, dict):
        content = content.get("content", [])
    if not isinstance(content, list):
        content = []
    return _extract_roles(content), None


def _common_parent_path(paths):
    """计算多个路径的公共父目录，如 ['/a/b/c', '/a/b/d/e'] → '/a/b'"""
    if not paths:
        return "/"
    parts_list = [p.strip("/").split("/") for p in paths if p and p != "/"]
    if not parts_list:
        return "/"
    common = parts_list[0]
    for parts in parts_list[1:]:
        i = 0
        while i < len(common) and i < len(parts) and common[i] == parts[i]:
            i += 1
        common = common[:i]
    if not common:
        return "/"
    return "/" + "/".join(common)


def _role_base_path(role_id):
    """根据角色权限范围计算用户的最佳 base_path（公共父目录），
    使 WebDAV 挂载后用户只需最少点击即可到达最终文件夹"""
    if not role_id:
        return "/公司文件"
    try:
        d, err = _alist_request("get", "/api/admin/role/list")
        if err:
            return "/"
        content = d.get("data", [])
        if isinstance(content, dict):
            content = content.get("content", [])
        if not isinstance(content, list):
            return "/"
        for role in content:
            if role.get("id") == role_id:
                scopes = role.get("permission_scopes", [])
                paths = [s.get("path", "") for s in scopes if isinstance(s, dict)]
                return _common_parent_path(paths)
    except Exception:
        pass
    return "/"


def _alist_create_alias(mount_path, source_path):
    """在 AList 中创建 Alias 存储，将 source_path 映射到 mount_path。
    source_path 可以是换行分隔的多个路径（Alias 驱动支持多源）。"""
    try:
        addition = json.dumps({"paths": source_path, "writable": True}, ensure_ascii=False)
        payload = {
            "mount_path": mount_path, "order": 10, "driver": "Alias",
            "cache_expiration": 0, "web_proxy": False,
            "webdav_policy": "native_proxy", "disable_index": False,
            "enable_sign": False, "addition": addition,
        }
        d, err = _alist_request("post", "/api/admin/storage/create", json=payload)
        if err:
            return None, err
        if d.get("code") == 200:
            return d.get("data", {}).get("id"), None
        return None, d.get("message", "创建 Alias 失败")
    except Exception as e:
        return None, str(e)


def _alist_update_alias(storage_id, mount_path, source_path):
    """更新 AList 中已有的 Alias 存储"""
    try:
        addition = json.dumps({"paths": source_path, "writable": True}, ensure_ascii=False)
        payload = {
            "id": storage_id,
            "mount_path": mount_path, "order": 10, "driver": "Alias",
            "cache_expiration": 0, "web_proxy": False,
            "webdav_policy": "native_proxy", "disable_index": False,
            "enable_sign": False, "addition": addition,
        }
        d, err = _alist_request("post", "/api/admin/storage/update", json=payload)
        if err:
            return False, err
        if d.get("code") == 200:
            return True, None
        return False, d.get("message", "更新 Alias 失败")
    except Exception as e:
        return False, str(e)


def _alist_delete_alias(storage_id):
    """删除 AList 中的 Alias 存储"""
    if not storage_id:
        return
    try:
        _alist_request("post", f"/api/admin/storage/delete?id={storage_id}")
    except Exception:
        pass


def _alias_mount_from_personal(pp):
    """从个人文件夹路径推导 Alias 挂载路径。
    /公司文件/信息化部/个人盘/许志龙 → /公司文件/信息化部/许志龙
    /公司文件/信息化部/许志龙(无"个人盘") → /公司文件/信息化部/许志龙
    """
    parts = pp.strip("/").split("/")
    if len(parts) < 2:
        return ""
    person_name = parts[-1]
    try:
        idx = parts.index("个人盘")
        dept_parts = parts[:idx]
    except ValueError:
        dept_parts = parts[:-1]
    if not dept_parts:
        return f"/{person_name}"
    return "/" + "/".join(dept_parts) + f"/{person_name}"


def _ensure_role_aliases(username, role_id):
    """已废弃：不再自动创建 AList Alias 存储。
    AList 存储管理应由管理员在 AList 后台手动操作，避免自动创建导致冲突或重复。"""
    return 0


def _ensure_user_drive_alias(username, role_id):
    """为用户创建/更新 Alias 存储，将角色权限的最终目录映射到 /drives/{username}/ 下。
    这样 rclone 挂载 /dav/drives/{username}/ 时，用户直接看到最终目录而无需逐级点击。
    返回 Alias 挂载路径（如 /drives/xu），失败返回 None。"""
    if not role_id:
        return None
    try:
        token = CONFIG.get("alist_token", "")
        if not token:
            return None

        # 获取角色权限路径
        d, rerr = _alist_request("get", "/api/admin/role/list")
        if rerr or not d:
            return None
        rcontent = d.get("data", [])
        if isinstance(rcontent, dict):
            rcontent = rcontent.get("content", [])
        if not isinstance(rcontent, list):
            return None

        target_role = None
        for role in rcontent:
            if role.get("id") == role_id:
                target_role = role
                break
        if not target_role:
            return None

        scopes = target_role.get("permission_scopes", [])
        paths = [s.get("path", "") for s in scopes if isinstance(s, dict)]
        if not paths:
            return None

        # 构造 Alias 源路径：每个权限路径一行
        alias_paths = "\n".join(p for p in paths if p and p != "/")
        if not alias_paths:
            return None

        mount_path = f"/drives/{username}"

        # 检查是否已有同名 Alias 存储
        d2, err2 = _alist_request("get", "/api/admin/storage/list")
        if err2 or not d2:
            return None
        storages = d2.get("data", {})
        if isinstance(storages, dict):
            storages = storages.get("content", [])
        existing_id = None
        existing_paths = None
        for s in storages:
            if s.get("mount_path") == mount_path and s.get("driver") == "Alias":
                existing_id = s.get("id")
                existing_paths = s.get("addition", "")
                break

        if existing_id:
            # 已存在：检查 paths 是否变化，变化则更新
            try:
                existing_data = json.loads(existing_paths) if isinstance(existing_paths, str) else {}
                old_paths = existing_data.get("paths", "")
            except Exception:
                old_paths = ""
            if old_paths != alias_paths:
                ok, _ = _alist_update_alias(existing_id, mount_path, alias_paths)
                if ok:
                    logging.info(f"[Alias] 已更新 {mount_path} (id={existing_id})")
                else:
                    logging.warning(f"[Alias] 更新失败 {mount_path}")
            return mount_path
        else:
            # 不存在：创建
            sid, err3 = _alist_create_alias(mount_path, alias_paths)
            if sid:
                logging.info(f"[Alias] 已创建 {mount_path} (id={sid}), paths: {paths}")
                return mount_path
            else:
                logging.warning(f"[Alias] 创建失败 {mount_path}: {err3}")
                return None
    except Exception as e:
        logging.error(f"[Alias] _ensure_user_drive_alias 异常: {e}")
        return None


def _alist_token_refresh_loop():
    """后台线程：每 12 小时自动刷新 AList token"""
    while True:
        time.sleep(12 * 3600)
        try:
            admin_user = CONFIG.get("alist_admin_user", "")
            admin_pass = CONFIG.get("alist_admin_pass", "")
            if admin_user and admin_pass:
                logging.info("[AList] 定时刷新 token (12h)")
                alist_refresh_token()
        except Exception as e:
            logging.error(f"[AList] 定时刷新异常: {e}")


def _alist_basepath_sync_loop():
    """后台线程：每 60 秒自动同步角色用户的 base_path 和 Alias 到 AList
    1) base_path 修正为角色权限路径的公共父目录
    2) 为个人文件夹创建 Alias 存储（使其出现在部门目录下）"""
    while True:
        time.sleep(60)
        try:
            token = CONFIG.get("alist_token", "")
            if not token:
                continue

            # 一次性拉取角色列表
            d, rerr = _alist_request("get", "/api/admin/role/list")
            if rerr or not d:
                continue
            rcontent = d.get("data", [])
            if isinstance(rcontent, dict):
                rcontent = rcontent.get("content", [])
            if not isinstance(rcontent, list):
                rcontent = []

            # 构建 role_id -> {base_path, personal_paths} 映射
            role_info = {}
            for role in rcontent:
                rid = role.get("id", 0)
                if not rid:
                    continue
                scopes = role.get("permission_scopes", [])
                paths = [s.get("path", "") for s in scopes if isinstance(s, dict)]
                personal = [p for p in paths if "个人盘" in p]
                role_info[rid] = {
                    "base_path": _common_parent_path(paths),
                    "personal_paths": personal,
                    "all_paths": paths,
                }

            # 拉取 AList 侧所有用户
            alist_users, err = alist_get_users(token)
            if err or not alist_users:
                continue
            alist_map = {}
            for au in alist_users:
                aid = au.get("id", 0)
                if aid:
                    alist_map[aid] = au

            # 遍历本地有角色的用户
            local_users = list_users()
            fixed_bp = 0
            for lu in local_users:
                role_id = int(lu.get("alist_role_id", 0) or 0)
                alist_id = int(lu.get("alist_id", 0) or 0)
                if role_id <= 0 or alist_id <= 0:
                    continue
                info = role_info.get(role_id)
                if not info:
                    continue
                expected_bp = info["base_path"]
                au = alist_map.get(alist_id)
                if not au:
                    continue

                # 检查并修正 base_path
                cur_bp = au.get("base_path", "")
                if cur_bp != expected_bp:
                    ok, err = alist_update_user(
                        alist_id=alist_id,
                        username=lu["username"],
                        base_path=expected_bp,
                        role_id=role_id,
                        token=token,
                    )
                    if ok:
                        fixed_bp += 1
                        update_user(lu["username"], alist_base_path=expected_bp)
                        with _remount_users_lock:
                            _remount_users.add(lu["username"])
                        logging.info(f"[AList] 自动修正 base_path: {lu['username']} '{cur_bp}' → '{expected_bp}'")
                    else:
                        logging.warning(f"[AList] 修正 base_path 失败: {lu['username']} - {err}")

            if fixed_bp:
                logging.info(f"[AList] 自动同步完成: base_path 修正 {fixed_bp} 个")
        except Exception as e:
            logging.error(f"[AList] base_path 自动同步异常: {e}")


def alist_auto_init():
    """启动时自动刷新 token 并启动后台刷新线程"""
    admin_user = CONFIG.get("alist_admin_user", "")
    admin_pass = CONFIG.get("alist_admin_pass", "")
    if not admin_user or not admin_pass:
        logging.info("[AList] 未配置管理员凭据，跳过自动刷新 (可在管理面板配置)")
        return
    # 启动时最多重试 3 次（间隔 3 秒），防止 AList 尚未就绪
    for attempt in range(1, 4):
        ok, err = alist_refresh_token()
        if ok:
            logging.info("[AList] 启动刷新 token 成功")
            break
        logging.warning(f"[AList] 启动刷新 token 失败 (第{attempt}次): {err}")
        if attempt < 3:
            time.sleep(3)
    t = threading.Thread(target=_alist_token_refresh_loop, daemon=True, name="alist-token-refresh")
    t.start()
    logging.info("[AList] 后台 token 刷新线程已启动 (间隔 12h)")
    # 禁用自动 base_path 同步（用户要求不动 AList 后台），改为手动触发
    # t2 = threading.Thread(target=_alist_basepath_sync_loop, daemon=True, name="alist-basepath-sync")
    # t2.start()
    # logging.info("[AList] 后台 base_path 同步线程已启动 (间隔 60s)")


# ============================================================
# Bidirectional Sync
# ============================================================

def sync_from_alist(token=None):
    """从 AList 拉取全部用户到本地"""
    alist_users, err = alist_get_users(token)
    if err:
        return None, err

    results = {"created": 0, "updated": 0, "skipped": 0, "disabled": 0, "details": []}

    # 记录本次同步到的 AList ID 集合，用于后续清理
    synced_alist_ids = set()

    for u in alist_users:
        username = u.get("username", "").strip()
        if not username or username == "guest":
            results["skipped"] += 1
            continue

        alist_id = u.get("id", 0)
        base_path = u.get("base_path", "/公司文件")
        role_list = u.get("role", [0])
        role_id = role_list[0] if role_list else 0
        disabled = u.get("disabled", False)
        synced_alist_ids.add(alist_id)

        local = get_user(username)
        if local:
            # 更新本地记录的 AList 信息，同时同步启用/禁用状态
            update_user(username, alist_id=alist_id, alist_base_path=base_path,
                        alist_role_id=role_id, alist_disabled=1 if disabled else 0,
                        active=0 if disabled else 1)
            results["updated"] += 1
            results["details"].append(f"~ {username} (id={alist_id}, path={base_path})")
        else:
            # 新建本地用户（随机占位密码，实际登录走 AList 代理验证）
            # 尊重 AList 的禁用状态
            ok = create_user(username, secrets.token_hex(16),
                             alist_id=alist_id, alist_base_path=base_path,
                             alist_role_id=role_id)
            if ok:
                if disabled:
                    update_user(username, alist_disabled=1, active=0)
                results["created"] += 1
                tag = " [禁用]" if disabled else ""
                results["details"].append(f"+ {username} (id={alist_id}, path={base_path}){tag}")
            else:
                results["skipped"] += 1
        if disabled:
            results["disabled"] += 1

    # 清理：AList 中已删除但本地仍存在的用户（标记为禁用而非删除）
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT username, alist_id FROM users WHERE alist_id > 0"
        ).fetchall()
        for row in rows:
            if row["alist_id"] not in synced_alist_ids:
                conn.execute(
                    "UPDATE users SET active=0, alist_disabled=1 WHERE username=?",
                    (row["username"],),
                )
                results["details"].append(f"! {row['username']} (AList中已不存在，已禁用)")
        conn.commit()
    finally:
        conn.close()

    return results, None


def push_to_alist(username, password=None, base_path=None, role_id=None, disabled=None):
    """将本地用户推送到 AList（创建或更新）"""
    local = get_user(username)
    if not local:
        return None, "本地用户不存在"

    alist_id = local.get("alist_id", 0)

    if alist_id and alist_id > 0:
        # AList 中已存在 → 更新
        ok, err = alist_update_user(
            alist_id=alist_id, username=username,
            password=password,
            base_path=base_path if base_path is not None else local.get("alist_base_path", "/公司文件"),
            role_id=role_id if role_id is not None else local.get("alist_role_id", 0),
            disabled=disabled if disabled is not None else bool(local.get("alist_disabled", 0)),
        )
        return ok, err
    else:
        # AList 中不存在 → 创建
        pwd = password or secrets.token_hex(16)
        bp = base_path if base_path is not None else local.get("alist_base_path", "/公司文件")
        rid = role_id if role_id is not None else local.get("alist_role_id", 0)
        ok, err = alist_create_user(username, pwd, base_path=bp, role_id=rid)
        if ok:
            # 创建成功后获取 AList ID
            users, _ = alist_get_users()
            if users:
                for u in users:
                    if u.get("username") == username:
                        update_user(username, alist_id=u.get("id", 0))
                        break
        return ok, err


# ============================================================
# Flask Application
# ============================================================

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024


@app.after_request
def _add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "未提供认证令牌"}), 401
        payload = jwt_decode(token)
        if not payload:
            return jsonify({"error": "认证令牌无效或已过期"}), 401
        request.user = payload
        return f(*args, **kwargs)
    return wrapper


_ADMIN_ATTEMPTS = defaultdict(lambda: {"count": 0, "locked_until": 0})
_ADMIN_ATTEMPTS_LOCK = threading.Lock()
_MAX_ADMIN_ATTEMPTS = 10
_ADMIN_LOCK_SECONDS = 600

_admin_tokens = {}
_ADMIN_TOKEN_LOCK = threading.Lock()
_ADMIN_TOKEN_TTL = 7200

def require_admin(f):
    """管理后台 API 需要管理员验证（Token 或密码）"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr or "unknown"
        with _ADMIN_ATTEMPTS_LOCK:
            info = _ADMIN_ATTEMPTS[client_ip]
            if info["locked_until"] > time.time():
                return jsonify({"error": "管理员验证失败次数过多，请稍后重试"}), 429
        auth = request.headers.get("X-Admin-Auth", "")
        if not auth:
            return jsonify({"error": "需要管理员验证"}), 401
        token_valid = False
        with _ADMIN_TOKEN_LOCK:
            token_info = _admin_tokens.get(auth)
            if token_info:
                if token_info["expires"] > time.time():
                    token_valid = True
                else:
                    del _admin_tokens[auth]
                    now = time.time()
                    expired = [t for t, v in _admin_tokens.items() if v["expires"] < now]
                    for t in expired:
                        del _admin_tokens[t]
        if token_valid:
            with _ADMIN_ATTEMPTS_LOCK:
                if client_ip in _ADMIN_ATTEMPTS:
                    del _ADMIN_ATTEMPTS[client_ip]
            return f(*args, **kwargs)
        if len(auth) > _MAX_PASSWORD_LEN:
            return jsonify({"error": "管理员密码错误"}), 401
        admin = get_user("admin")
        if not admin or not verify_password(auth, admin["password_hash"]):
            with _ADMIN_ATTEMPTS_LOCK:
                info = _ADMIN_ATTEMPTS[client_ip]
                info["count"] += 1
                if info["count"] >= _MAX_ADMIN_ATTEMPTS:
                    info["locked_until"] = time.time() + _ADMIN_LOCK_SECONDS
                    info["count"] = 0
            return jsonify({"error": "管理员密码错误"}), 401
        with _ADMIN_ATTEMPTS_LOCK:
            if client_ip in _ADMIN_ATTEMPTS:
                del _ADMIN_ATTEMPTS[client_ip]
        return f(*args, **kwargs)
    return wrapper


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "密码不能为空"}), 400
    client_ip = request.remote_addr or "unknown"
    with _ADMIN_ATTEMPTS_LOCK:
        info = _ADMIN_ATTEMPTS[client_ip]
        if info["locked_until"] > time.time():
            return jsonify({"error": "管理员验证失败次数过多，请稍后重试"}), 429
    admin = get_user("admin")
    if not admin or not verify_password(password, admin["password_hash"]):
        with _ADMIN_ATTEMPTS_LOCK:
            info = _ADMIN_ATTEMPTS[client_ip]
            info["count"] += 1
            if info["count"] >= _MAX_ADMIN_ATTEMPTS:
                info["locked_until"] = time.time() + _ADMIN_LOCK_SECONDS
                info["count"] = 0
        return jsonify({"error": "密码错误"}), 401
    with _ADMIN_ATTEMPTS_LOCK:
        if client_ip in _ADMIN_ATTEMPTS:
            del _ADMIN_ATTEMPTS[client_ip]
    _audit("admin", "admin_login", "管理员登录", client_ip)
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _ADMIN_TOKEN_LOCK:
        _admin_tokens[token] = {"expires": now + _ADMIN_TOKEN_TTL}
        expired = [t for t, v in _admin_tokens.items() if v["expires"] < now]
        for t in expired:
            del _admin_tokens[t]
    return jsonify({"token": token, "expires_at": int(now + _ADMIN_TOKEN_TTL), "expires_in": _ADMIN_TOKEN_TTL})


@app.route("/api/admin/refresh-token", methods=["POST"])
@require_admin
def admin_refresh_token():
    old_token = request.headers.get("X-Admin-Auth", "")
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _ADMIN_TOKEN_LOCK:
        _admin_tokens[token] = {"expires": now + _ADMIN_TOKEN_TTL}
        if old_token in _admin_tokens:
            del _admin_tokens[old_token]
    return jsonify({"token": token, "expires_at": int(now + _ADMIN_TOKEN_TTL), "expires_in": _ADMIN_TOKEN_TTL})


# ---------- Health & Info ----------

@app.route("/api/auth/public-key", methods=["GET"])
def api_public_key():
    return jsonify({"public_key": _rsa_public_key_pem()})


@app.route("/api/health", methods=["GET"])
def api_health():
    """健康检查：检测数据库和 AList 连通性"""
    db_ok = False
    conn = None
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        db_ok = True
    except Exception:
        pass
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
    alist_ok = bool(CONFIG.get("alist_token"))
    user_count = -1
    if db_ok:
        try:
            conn = get_db()
            row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
            user_count = row[0] if row else 0
        except Exception:
            pass
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass
    status = "ok" if (db_ok and alist_ok) else "degraded" if db_ok else "error"
    return jsonify({
        "status": status,
        "version": "1.16.0",
        "db": db_ok,
        "alist": alist_ok,
        "users": user_count,
    })


# ---------- Auth API ----------

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求格式错误"}), 400
    username = sanitize_string(data.get("username") or "", 32)
    password = data.get("password") or ""
    encrypted = data.get("encrypted", False)

    valid, err = validate_username(username)
    if not valid:
        return jsonify({"error": err}), 400

    client_ip = request.remote_addr or "unknown"
    rate_ok, rate_err = _check_login_rate(username, client_ip)
    if not rate_ok:
        return jsonify({"error": rate_err}), 429

    if encrypted:
        decrypted = _rsa_decrypt_password(password)
        if decrypted is None:
            _record_login_failure(username, client_ip)
            return jsonify({"error": "密码解密失败"}), 400
        password = decrypted

    valid, err = validate_password_length(password)
    if not valid:
        return jsonify({"error": err}), 400

    user = get_user(username)
    local_ok = False
    if user:
        if not user.get("active", 1):
            verify_password(password, _DUMMY_HASH)
            time.sleep(0.5)
            return jsonify({"error": "用户名或密码错误"}), 401
        local_ok = verify_password(password, user["password_hash"])
    else:
        verify_password(password, _DUMMY_HASH)
        time.sleep(0.5)

    alist_ok = False
    alist_user_token = None
    if not local_ok and CONFIG.get("alist_sync_on_login", True):
        alist_ok, alist_user_token = alist_login(username, password)

    # 本地验证成功但 AList 信息缺失（role_id=0）→ 也尝试 AList 同步
    if local_ok and user and not int(user.get("alist_role_id", 0) or 0) and CONFIG.get("alist_sync_on_login", True):
        try:
            _ok, _tok = alist_login(username, password)
            if _ok and _tok:
                me = alist_get_me(_tok)
                if me:
                    role_val = me.get("role", 0)
                    if isinstance(role_val, list) and role_val:
                        rid = role_val[0]
                    elif isinstance(role_val, int):
                        rid = role_val
                    else:
                        rid = 0
                    update_user(username,
                                alist_id=me.get("id", 0),
                                alist_base_path=me.get("base_path", "/公司文件") or "/公司文件",
                                alist_role_id=rid)
                    user = get_user(username)
                    print(f"  [+] 本地验证成功，AList 信息已补全: {username} (role={rid})")
        except Exception as e:
            print(f"  [!] AList 信息补全异常: {e}")

    if not local_ok and not alist_ok:
        _record_login_failure(username, client_ip)
        time.sleep(0.5)
        return jsonify({"error": "用户名或密码错误"}), 401

    _record_login_success(username, client_ip)

    # AList 验证成功 + 本地没账号 → 自动创建并同步 AList 信息
    if alist_ok and not user:
        alist_id, alist_base_path, alist_role_id = 0, "/公司文件", 0
        try:
            me = alist_get_me(alist_user_token)
            if me:
                alist_id = me.get("id", 0)
                alist_base_path = me.get("base_path", "/公司文件") or "/公司文件"
                role_val = me.get("role", 0)
                if isinstance(role_val, list) and role_val:
                    alist_role_id = role_val[0]
                elif isinstance(role_val, int):
                    alist_role_id = role_val
                print(f"  [+] /api/me 获取成功: {username} (alist_id={alist_id}, role={alist_role_id}, bp={alist_base_path})")
            else:
                print(f"  [!] /api/me 返回空，尝试 admin token 回退")
                d, au_err = _alist_request("get", "/api/admin/user/list")
                if au_err:
                    print(f"  [!] admin token 也失败: {au_err}")
                if d and d.get("code") == 200:
                    content = d.get("data", {})
                    if isinstance(content, dict):
                        alist_users = content.get("content", [])
                    else:
                        alist_users = content if isinstance(content, list) else []
                    for au in alist_users:
                        if au.get("username") == username:
                            alist_id = au.get("id", 0)
                            alist_base_path = au.get("base_path", "/公司文件") or "/公司文件"
                            role_val = au.get("role", 0)
                            if isinstance(role_val, list) and role_val:
                                alist_role_id = role_val[0]
                            elif isinstance(role_val, int):
                                alist_role_id = role_val
                            break
        except Exception as e:
            print(f"  [!] AList 用户信息同步异常: {e}")
        create_user(username, password, alist_id=alist_id,
                    alist_base_path=alist_base_path, alist_role_id=alist_role_id)
        user = get_user(username)
        print(f"  [+] AList 用户自动同步完成: {username} (alist_id={alist_id}, role={alist_role_id}, bp={alist_base_path})")

    # AList 验证成功 + 本地有但密码不匹配 → 更新本地密码 + 同步 AList 信息
    if alist_ok and user and not local_ok:
        update_user(username, password_hash=hash_password(password))
        if not user.get("alist_id"):
            try:
                me = alist_get_me(alist_user_token)
                if me:
                    role_val = me.get("role", 0)
                    if isinstance(role_val, list) and role_val:
                        rid = role_val[0]
                    elif isinstance(role_val, int):
                        rid = role_val
                    else:
                        rid = 0
                    update_user(username,
                                alist_id=me.get("id", 0),
                                alist_base_path=me.get("base_path", "/公司文件") or "/公司文件",
                                alist_role_id=rid)
                    print(f"  [+] 密码同步+用户信息更新: {username} (alist_id={me.get('id',0)}, role={rid})")
                else:
                    d, _ = _alist_request("get", "/api/admin/user/list")
                    if d and d.get("code") == 200:
                        content = d.get("data", {})
                        if isinstance(content, dict):
                            alist_users = content.get("content", [])
                        else:
                            alist_users = content if isinstance(content, list) else []
                        for au in alist_users:
                            if au.get("username") == username:
                                role_val = au.get("role", 0)
                                if isinstance(role_val, list) and role_val:
                                    rid = role_val[0]
                                elif isinstance(role_val, int):
                                    rid = role_val
                                else:
                                    rid = 0
                                update_user(username,
                                            alist_id=au.get("id", 0),
                                            alist_base_path=au.get("base_path", "/公司文件") or "/公司文件",
                                            alist_role_id=rid)
                                break
            except Exception as e:
                print(f"  [!] AList 信息同步异常(密码更新): {e}")

    if not user:
        user = get_user(username)

    record_login(username)
    _audit(username, "login", "用户登录", request.remote_addr or "")
    expire_days = CONFIG.get("token_expire_days", 7)
    payload = {"sub": username, "exp": int(time.time()) + expire_days * 86400}
    token = jwt_encode(payload)
    webdav_url = user.get("webdav_url") or CONFIG["default_webdav_url"]
    # 登录时自动修正 AList 用户的 base_path 为角色权限的最终目录
    # 使 WebDAV 挂载 /dav/ 后用户直接看到最终目录，无需逐级点击
    role_id = int(user.get("alist_role_id", 0) or 0)
    alist_id = int(user.get("alist_id", 0) or 0)
    if role_id and alist_id:
        try:
            expected_bp = _role_base_path(role_id)
            if expected_bp and expected_bp != "/":
                # 获取 AList 侧当前 base_path
                au, _ = alist_get_user(alist_id)
                cur_bp = (au or {}).get("base_path", "")
                if cur_bp != expected_bp:
                    ok, err = alist_update_user(alist_id=alist_id, username=username,
                                                base_path=expected_bp, role_id=role_id)
                    if ok:
                        update_user(username, alist_base_path=expected_bp)
                        print(f"  [+] base_path 已修正: {username} '{cur_bp}' -> '{expected_bp}'")
                    else:
                        print(f"  [!] base_path 修正失败: {username} - {err}")
        except Exception as e:
            print(f"  [!] base_path 修正异常: {e}")
    user_drives = get_user_drives(username)

    if not user_drives:
        user_drives = [{"drive_letter": user.get("drive_letter", "Z:"),
                         "label": user.get("label", "远程磁盘"),
                         "webdav_path": ""}]
    result = {
        "success": True, "token": token, "webdav_url": webdav_url,
        "drive": user.get("drive_letter", "Z:"),
        "label": user.get("label", "远程磁盘"), "username": username,
        "drives": user_drives,
    }

    return jsonify(result)


@app.route("/api/auth/verify", methods=["GET"])
@require_auth
def api_verify():
    user = get_user(request.user["sub"])
    if not user or not user.get("active", 1):
        return jsonify({"valid": False}), 401
    wurl = user.get("webdav_url") or CONFIG["default_webdav_url"]
    role_id = int(user.get("alist_role_id", 0) or 0)
    alist_id = int(user.get("alist_id", 0) or 0)
    if role_id and alist_id:
        try:
            expected_bp = _role_base_path(role_id)
            if expected_bp and expected_bp != "/":
                au, _ = alist_get_user(alist_id)
                cur_bp = (au or {}).get("base_path", "")
                if cur_bp != expected_bp:
                    ok, err = alist_update_user(alist_id=alist_id, username=user["username"],
                                                base_path=expected_bp, role_id=role_id)
                    if ok:
                        update_user(user["username"], alist_base_path=expected_bp)
        except Exception:
            pass
    user_drives = get_user_drives(user["username"])
    if not user_drives:
        user_drives = [{"drive_letter": user.get("drive_letter", "Z:"),
                         "label": user.get("label", "远程磁盘"),
                         "webdav_path": ""}]
    return jsonify({
        "valid": True, "username": user["username"],
        "webdav_url": wurl,
        "drive": user.get("drive_letter", "Z:"),
        "label": user.get("label", "远程磁盘"),
        "drives": user_drives,
    })


@app.route("/api/auth/hardware-info", methods=["POST"])
@require_auth
def upload_hardware_info():
    """客户端上报硬件信息"""
    username = request.user.get("sub", "")
    if not username:
        return jsonify({"error": "无效用户"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "数据为空"}), 400

    # 解析结构化字段
    hostname = sanitize_string(data.get("hostname", ""), 64)
    os_info = sanitize_string(f'{data.get("os_name", "")} {data.get("os_arch", "")}'.strip(), 128)
    bios_sn = sanitize_string(data.get("bios_sn", ""), 128)
    sn_dec = data.get("bios_sn_dec", "")
    if sn_dec:
        bios_sn = f'{bios_sn}  SN(Dec): {sanitize_string(str(sn_dec), 64)}'
    bios_vendor = sanitize_string(f'{data.get("bios_vendor", "")} {data.get("bios_ver", "")}'.strip(), 128)
    cpu_model = sanitize_string(data.get("cpu_model", ""), 128)
    cpu_cores = data.get("cpu_cores", 0)
    cpu_threads = data.get("cpu_threads", 0)
    cpu_speed = sanitize_string(data.get("cpu_speed", ""), 32)
    cpu_cache = sanitize_string(data.get("cpu_cache", ""), 64)

    ram_total = data.get("ram_total_gb", 0)
    sticks = data.get("ram_sticks", [])
    ram_details_parts = []
    for s in sticks:
        ram_details_parts.append(
            f'{s.get("gb", 0)}GB {s.get("type", "")}/{s.get("speed", 0)} [{s.get("mfr", "")}] {s.get("pn", "")}'.strip()
        )
    ram_details = "\n".join(ram_details_parts)

    gpus = data.get("gpus", [])
    gpu_info = "\n".join(f'{g.get("name", "")} {g.get("vram_gb", 0)}GB' for g in gpus)

    disks = data.get("disks", [])
    disk_info = "\n".join(
        f'{d.get("model", "")} {d.get("size_gb", 0)}GB [{d.get("type", "")}]' for d in disks
    )

    nets = data.get("networks", [])
    net_parts = []
    for n in nets:
        status = n.get("status", "")
        mac = n.get("mac", "")
        name = n.get("name", "")
        ntype = n.get("type", "")
        if status == "使用中":
            line = f'[使用中] {mac} {ntype}'
        else:
            line = f'[闲置] {mac} {ntype}'
        if name:
            line += f' ({name})'
        if n.get("ip"):
            line += f'  IP:{n["ip"]}  网关:{n.get("gateway", "")}  {n.get("speed", "")}'
        net_parts.append(line)
    network_info = "\n".join(net_parts)

    mons = data.get("monitors", [])
    mon_parts = []
    for idx, m in enumerate(mons):
        name = m.get("name", "未知")
        size = m.get("size", "")
        mon_parts.append(f'显示器{idx+1}: {name}')
        if size:
            mon_parts.append(f'  尺寸: {size}')
    res = data.get("monitor_resolution", "")
    hz = data.get("monitor_refresh", "")
    if res:
        line = f'  分辨率: {res}'
        if hz:
            line += f'  刷新率: {hz}'
        mon_parts.append(line)
    if not mons and not res:
        mon_parts.append('未检测到显示器')
    monitor_info = "\n".join(mon_parts)

    raw_json = json.dumps(data, ensure_ascii=False)
    if len(raw_json) > 65536:
        raw_json = raw_json[:65536]
    updated_at = datetime.now().isoformat()

    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO hardware_info (username, hostname, os_info, bios_sn, bios_vendor,
                cpu_model, cpu_cores, cpu_threads, cpu_speed, cpu_cache,
                ram_total_gb, ram_details, gpu_info, disk_info, network_info,
                monitor_info, raw_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                hostname=excluded.hostname, os_info=excluded.os_info,
                bios_sn=excluded.bios_sn, bios_vendor=excluded.bios_vendor,
                cpu_model=excluded.cpu_model, cpu_cores=excluded.cpu_cores,
                cpu_threads=excluded.cpu_threads, cpu_speed=excluded.cpu_speed,
                cpu_cache=excluded.cpu_cache, ram_total_gb=excluded.ram_total_gb,
                ram_details=excluded.ram_details, gpu_info=excluded.gpu_info,
                disk_info=excluded.disk_info, network_info=excluded.network_info,
                monitor_info=excluded.monitor_info, raw_json=excluded.raw_json,
                updated_at=excluded.updated_at
        """, (username, hostname, os_info, bios_sn, bios_vendor,
              cpu_model, cpu_cores, cpu_threads, cpu_speed, cpu_cache,
              ram_total, ram_details, gpu_info, disk_info, network_info,
              monitor_info, raw_json, updated_at))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"success": True})


@app.route("/api/admin/users/<username>/hardware", methods=["GET"])
@require_admin
def admin_get_hardware(username):
    """管理员查看用户硬件信息"""
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM hardware_info WHERE username=?", (username,)).fetchone()
        if not row:
            return jsonify({"error": "该用户尚未上报硬件信息"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()


# ---------- File Operation Logs ----------

@app.route("/api/auth/move-to-recycle", methods=["POST"])
@require_auth
def client_move_to_recycle():
    username = request.user.get("sub", "")
    data = request.get_json(silent=True) or {}
    file_path = data.get("path", "").strip()
    if not file_path:
        return jsonify({"success": False})
    recycle_dir = _get_recycle_dir(username)
    alist_ensure_token()
    token = CONFIG.get("alist_token", "")
    base = _alist_base()
    if not base or not token:
        return jsonify({"success": False})
    try:
        if ":" in file_path and len(file_path) >= 2 and file_path[1] == ":":
            dl = file_path[0].upper()
            user_drives = get_user_drives(username)
            drive_map = {sanitize_drive_letter(d["drive_letter"]).rstrip(":").upper(): d for d in user_drives}
            drive_info = drive_map.get(dl)
            if drive_info:
                wp = drive_info.get("webdav_path", "")
                user = get_user(username)
                alist_base = user.get("alist_base_path", "/公司文件") if user else "/公司文件"
                base_path = alist_base.rstrip("/") + ("/" + wp.lstrip("/") if wp else "")
                rest = file_path[3:].replace("\\", "/")
                alist_src_dir = base_path + ("/" + rest[:rest.rfind("/")] if "/" in rest else "")
                file_name = rest.rsplit("/", 1)[-1] if "/" in rest else rest
            else:
                return jsonify({"success": False})
        else:
            return jsonify({"success": False})
        r = http_requests.post(f"{base}/api/fs/move",
            json={"src_dir": alist_src_dir, "dst_dir": recycle_dir, "names": [file_name]},
            headers=_alist_headers(token), timeout=10)
        d = r.json()
        if d.get("code") == 200:
            return jsonify({"success": True})
        return jsonify({"success": False})
    except Exception:
        return jsonify({"success": False})


@app.route("/api/auth/file-log", methods=["POST"])
@require_auth
def client_upload_file_logs():
    """客户端批量上报文件操作日志"""
    data = request.get_json(silent=True) or {}
    username = request.user.get("sub", "")
    logs = data.get("logs", [])
    if not logs:
        return jsonify({"success": True, "count": 0})
    logs = logs[:1000]
    conn = get_db()
    try:
        inserted = 0
        for log in logs:
            event_type = sanitize_string(log.get("event_type", ""), 20)
            path = sanitize_string(log.get("path", ""), 512)
            if not event_type or not path:
                continue
            dest_path = sanitize_string(log.get("dest_path", "") or "", 512)
            drive_letter = sanitize_string(log.get("drive_letter", "") or "", 5)
            is_dir = 1 if log.get("is_dir") else 0
            try:
                file_size = min(abs(int(log.get("file_size", 0) or 0)), 2**53)
            except (ValueError, TypeError):
                file_size = 0
            ts = log.get("timestamp", 0)
            try:
                created_at = datetime.fromtimestamp(ts).isoformat() if ts and ts > 0 else datetime.now().isoformat()
            except (ValueError, OSError):
                created_at = datetime.now().isoformat()
            conn.execute(
                "INSERT INTO file_logs (username, event_type, path, dest_path, is_dir, file_size, drive_letter, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, event_type, path, dest_path, is_dir, file_size, drive_letter, created_at)
            )
            if event_type in ("删除", "移动出"):
                file_name = path.rstrip("/\\").split("/")[-1].split("\\")[-1]
                conn.execute(
                    "INSERT INTO recycle_bin (username,original_path,file_name,file_size,is_dir,deleted_at) VALUES (?,?,?,?,?,?)",
                    (username, path, file_name, file_size, is_dir, created_at)
                )

            inserted += 1
        conn.commit()
        return jsonify({"success": True, "count": inserted})
    except Exception as e:
        logging.error(f"[FileLog] 上传失败: {e}")
        return jsonify({"success": False, "error": "内部错误"}), 500
    finally:
        conn.close()


@app.route("/api/admin/users/<username>/file-logs", methods=["GET"])
@require_admin
def admin_get_file_logs(username):
    """管理员查看用户文件操作日志"""
    limit = min(request.args.get("limit", 100, type=int), 1000)
    offset = max(request.args.get("offset", 0, type=int), 0)
    event_type = request.args.get("event_type", "")
    conn = get_db()
    try:
        query = "SELECT id, event_type, path, dest_path, is_dir, file_size, drive_letter, created_at FROM file_logs WHERE username=?"
        params = [username]
        if event_type:
            query += " AND event_type=?"
            params.append(event_type)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) FROM file_logs WHERE username=?" + (" AND event_type=?" if event_type else ""),
            [username, event_type] if event_type else [username]
        ).fetchone()[0]
        return jsonify({
            "total": total,
            "logs": [dict(r) for r in rows]
        })
    finally:
        conn.close()


@app.route("/api/admin/users/<username>/file-logs", methods=["DELETE"])
@require_admin
def admin_clear_file_logs(username):
    """管理员清空用户文件操作日志"""
    conn = get_db()
    try:
        conn.execute("DELETE FROM file_logs WHERE username=?", (username,))
        conn.commit()
        return jsonify({"success": True, "message": "日志已清空"})
    finally:
        conn.close()


# ---------- Remote Commands ----------

@app.route("/api/admin/users/<username>/command", methods=["POST"])
@require_admin
def admin_send_command(username):
    """管理员向用户发送远程命令"""
    data = request.get_json(silent=True) or {}
    command_type = data.get("command_type", "")
    if command_type not in ("hide_disks", "restore_disks"):
        return jsonify({"error": "不支持的命令类型"}), 400
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO remote_commands (username, command_type, status, created_at) VALUES (?, ?, 'pending', ?)",
            (username, command_type, datetime.now().isoformat())
        )
        conn.commit()
        return jsonify({"success": True, "message": f"命令已下发: {command_type}"})
    finally:
        conn.close()


@app.route("/api/auth/commands", methods=["GET"])
@require_auth
def client_get_commands():
    """客户端拉取待执行的命令，拉取后立即标记为 fetching 防止重复执行"""
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, command_type FROM remote_commands WHERE username=? AND status='pending' ORDER BY id",
            (username,)
        ).fetchall()
        commands = [{"id": row["id"], "command_type": row["command_type"]} for row in rows]
        if commands:
            now = datetime.now().isoformat()
            for cmd in commands:
                conn.execute(
                    "UPDATE remote_commands SET status='fetching', executed_at=? WHERE id=? AND status='pending'",
                    (now, cmd["id"])
                )
            conn.commit()
        return jsonify(commands)
    finally:
        conn.close()


@app.route("/api/auth/commands/<int:cmd_id>/result", methods=["POST"])
@require_auth
def client_report_result(cmd_id):
    """客户端上报命令执行结果"""
    username = request.user.get("sub", "")
    data = request.get_json(silent=True) or {}
    status = data.get("status", "failed")
    result = data.get("result", "")
    conn = get_db()
    try:
        row = conn.execute("SELECT id, username FROM remote_commands WHERE id=?", (cmd_id,)).fetchone()
        if not row or row["username"] != username:
            return jsonify({"error": "命令不存在"}), 404
        conn.execute(
            "UPDATE remote_commands SET status=?, result=?, executed_at=? WHERE id=?",
            (status, result, datetime.now().isoformat(), cmd_id)
        )
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()


@app.route("/api/auth/heartbeat", methods=["POST"])
@require_auth
def client_heartbeat():
    """客户端心跳上报（含磁盘隐藏状态）"""
    username = request.user.get("sub", "")
    body = request.get_json(silent=True) or {}
    disk_hidden = body.get("disk_hidden")
    record_heartbeat(username, disk_hidden=disk_hidden)
    # 检查是否需要客户端重新挂载（base_path 被自动修正）
    need_remount = False
    with _remount_users_lock:
        if username in _remount_users:
            _remount_users.discard(username)
            need_remount = True
    return jsonify({"success": True, "remount": need_remount})


@app.route("/api/auth/check-update", methods=["GET"])
def check_update():
    """客户端检查更新"""
    client_type = request.args.get("type", "client")
    if client_type not in ("client", "server", "setup"):
        return jsonify({"update": False, "message": "无效类型"})
    current_version = request.args.get("current_version", "")
    download_dir = os.path.join(BASE_DIR, "download")
    version_file = os.path.join(download_dir, f"{client_type}_version.txt")
    if not os.path.exists(version_file):
        return jsonify({"update": False, "message": "无可用更新"})
    try:
        with open(version_file, "r", encoding="utf-8") as f:
            info = json.load(f)
        server_version = info.get("version", "")
        if not server_version:
            return jsonify({"update": False, "message": "无可用更新"})

        def _parse_ver(v):
            try:
                return tuple(int(x) for x in v.strip().split("."))
            except (ValueError, AttributeError):
                return (0,)

        if current_version and _parse_ver(current_version) >= _parse_ver(server_version):
            return jsonify({"update": False, "message": "已是最新版本"})
        sha256 = info.get("sha256", "")
        if not sha256:
            exe_name = info.get("filename", "")
            exe_path = os.path.join(download_dir, exe_name)
            if os.path.exists(exe_path):
                import hashlib
                h = hashlib.sha256()
                with open(exe_path, "rb") as ef:
                    for chunk in iter(lambda: ef.read(8192), b""):
                        h.update(chunk)
                sha256 = h.hexdigest()
        return jsonify({
            "update": True,
            "version": server_version,
            "filename": info.get("filename", ""),
            "changelog": info.get("changelog", ""),
            "download_url": f"/api/auth/download/{client_type}",
            "sha256": sha256
        })
    except Exception:
        return jsonify({"update": False, "message": "版本文件读取失败"})


@app.route("/api/auth/download/<file_type>", methods=["GET"])
def download_file(file_type):
    """客户端下载更新文件"""
    if file_type not in ("client", "server", "setup"):
        return jsonify({"error": "无效的文件类型"}), 400
    download_dir = os.path.join(BASE_DIR, "download")
    download_dir = os.path.realpath(download_dir)
    version_file = os.path.join(download_dir, f"{file_type}_version.txt")
    if not os.path.exists(version_file):
        return jsonify({"error": "版本文件不存在"}), 404
    try:
        with open(version_file, "r", encoding="utf-8") as f:
            info = json.load(f)
        filename = info.get("filename", "")
        if not filename or "/" in filename or "\\" in filename:
            return jsonify({"error": "无效的文件名"}), 400
        filepath = os.path.realpath(os.path.join(download_dir, filename))
        if not filepath.lower().startswith(download_dir.lower() + os.sep):
            return jsonify({"error": "非法路径"}), 403
        if not os.path.exists(filepath):
            return jsonify({"error": "更新文件不存在"}), 404
        from flask import send_file
        return send_file(filepath, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error": "内部错误"}), 500


@app.route("/api/admin/users/<username>/commands", methods=["GET"])
@require_admin
def admin_get_commands(username):
    """管理员查看用户的命令历史"""
    limit = request.args.get("limit", 10, type=int)
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, command_type, status, result, created_at, executed_at FROM remote_commands WHERE username=? ORDER BY id DESC LIMIT ?",
            (username, limit)
        ).fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        conn.close()


# ---------- Admin: User CRUD (with AList bidirectional sync) ----------

@app.route("/api/admin/users", methods=["GET"])
@require_admin
def admin_list():
    users = list_users()
    # 为有角色的用户补充角色实际路径（缩短为最终目录名）
    try:
        role_paths, _ = alist_get_roles()
        if role_paths:
            for u in users:
                rid = int(u.get("alist_role_id", 0) or 0)
                if rid > 0:
                    u["alist_role_paths"] = role_paths.get(rid, [])
    except Exception:
        pass
    return jsonify(users)


@app.route("/api/admin/users", methods=["POST"])
@require_admin
def admin_create():
    data = request.get_json(silent=True) or {}
    username = sanitize_string(data.get("username") or "", 32)
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400

    valid, err = validate_username(username)
    if not valid:
        return jsonify({"error": err}), 400
    valid, err = validate_password_length(password)
    if not valid:
        return jsonify({"error": err}), 400

    base_path = data.get("alist_base_path", "/公司文件")
    role_id = int(data.get("alist_role_id", 0))

    # 有角色时，实际 base_path 由角色的公共父目录决定
    if role_id:
        computed_bp = _role_base_path(role_id)
        if computed_bp:
            base_path = computed_bp

    # 1. 先检查 AList 是否已有同名用户，如有则更新而非创建
    alist_id = 0
    if CONFIG.get("alist_token"):
        users, _ = alist_get_users()
        existing_alist_user = None
        if users:
            for u in users:
                if u.get("username") == username:
                    existing_alist_user = u
                    alist_id = u.get("id", 0)
                    break

        if existing_alist_user and alist_id > 0:
            # AList 已有同名用户 → 更新配置（base_path, role, password）
            ok, err = alist_update_user(
                alist_id=alist_id, username=username, password=password,
                base_path=base_path, role_id=role_id
            )
            if ok:
                print(f"  [+] AList 已有用户 {username}，已更新配置")
            else:
                print(f"  [!] AList 更新失败: {err}")
        else:
            # AList 无同名用户 → 创建新用户
            ok, err = alist_create_user(username, password, base_path=base_path, role_id=role_id)
            if ok:
                # 获取 AList ID
                users, _ = alist_get_users()
                if users:
                    for u in users:
                        if u.get("username") == username:
                            alist_id = u.get("id", 0)
                            break
            else:
                print(f"  [!] AList 创建失败: {err}")

    # 2. 创建本地用户
    local_ok = create_user(
        username, password,
        data.get("webdav_url", ""), data.get("drive_letter", "Z:"),
        data.get("label", "远程磁盘"),
        alist_id=alist_id, alist_base_path=base_path, alist_role_id=role_id,
    )
    if not local_ok:
        return jsonify({"error": "用户名已存在"}), 400

    return jsonify({"success": True, "alist_id": alist_id})


@app.route("/api/admin/users/<username>", methods=["PUT"])
@require_admin
def admin_update(username):
    data = request.get_json(silent=True) or {}
    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404

    update_kwargs = {}
    if "password" in data and data["password"]:
        update_kwargs["password_hash"] = hash_password(data["password"])
    if "webdav_url" in data:
        update_kwargs["webdav_url"] = sanitize_string(data["webdav_url"], 512)
    if "drive_letter" in data:
        dl = data["drive_letter"]
        if not re.match(r'^[A-Za-z]:$', dl):
            return jsonify({"error": f"无效盘符: {dl}"}), 400
        update_kwargs["drive_letter"] = dl.upper()
    if "label" in data:
        update_kwargs["label"] = sanitize_string(data["label"], 64)
    if "active" in data:
        update_kwargs["active"] = int(data["active"])
    if "alist_base_path" in data:
        update_kwargs["alist_base_path"] = sanitize_string(data["alist_base_path"], 512)
    if "alist_role_id" in data:
        try:
            update_kwargs["alist_role_id"] = int(data["alist_role_id"])
        except (ValueError, TypeError):
            return jsonify({"error": "无效的角色ID"}), 400

    # 有角色时，实际 base_path 由角色的公共父目录决定（与 alist_update_user 逻辑一致）
    rid = update_kwargs.get("alist_role_id", user.get("alist_role_id", 0))
    if rid:
        computed_bp = _role_base_path(rid)
        if computed_bp:
            update_kwargs["alist_base_path"] = computed_bp

    update_user(username, **update_kwargs)

    # 双向同步到 AList
    alist_id = user.get("alist_id", 0)
    if alist_id and CONFIG.get("alist_token"):
        pwd = data.get("password") or None
        bp = update_kwargs.get("alist_base_path", user.get("alist_base_path"))
        rid = update_kwargs.get("alist_role_id", user.get("alist_role_id"))
        disabled = not bool(update_kwargs.get("active", user.get("active", 1)))
        alist_update_user(alist_id, username, password=pwd, base_path=bp,
                          role_id=rid, disabled=disabled)

    _audit("admin", "update_user", f"修改用户 {username}: {','.join(update_kwargs.keys())}")
    return jsonify({"success": True})


@app.route("/api/admin/users/<username>", methods=["DELETE"])
@require_admin
def admin_delete(username):
    if username == "admin":
        return jsonify({"error": "不能删除管理员账号"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404

    # 双向同步：删除 AList 用户
    alist_id = user.get("alist_id", 0)
    if alist_id and CONFIG.get("alist_token"):
        alist_delete_user(alist_id)

    delete_user_db(username)
    _audit("admin", "delete_user", f"删除用户 {username}")
    return jsonify({"success": True})


@app.route("/api/admin/users/<username>/drives", methods=["GET"])
@require_admin
def admin_get_drives(username):
    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    drives = get_user_drives(username)
    if not drives:
        drives = [{"drive_letter": user.get("drive_letter", "Z:"),
                    "label": user.get("label", "远程磁盘"),
                    "webdav_path": "", "sort_order": 0}]
    return jsonify({"drives": drives})


@app.route("/api/admin/users/<username>/drives", methods=["PUT"])
@require_admin
def admin_set_drives(username):
    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    data = request.get_json(silent=True) or {}
    drives = data.get("drives", [])
    if not isinstance(drives, list) or len(drives) == 0:
        return jsonify({"error": "至少需要一个盘符"}), 400
    if len(drives) > 26:
        return jsonify({"error": "盘符数量不能超过26个"}), 400
    seen = set()
    for d in drives:
        if not isinstance(d, dict):
            return jsonify({"error": "盘符数据格式错误"}), 400
        dl = d.get("drive_letter", "")
        if not re.match(r'^[A-Za-z]:$', dl):
            return jsonify({"error": f"无效盘符: {dl}"}), 400
        if dl.upper() in seen:
            return jsonify({"error": f"重复盘符: {dl}"}), 400
        seen.add(dl.upper())
    clean_drives = []
    for i, d in enumerate(drives):
        clean_drives.append({
            "drive_letter": d.get("drive_letter", "Z:").upper(),
            "label": sanitize_string(d.get("label", "远程磁盘"), 64),
            "webdav_path": _sanitize_webdav_path(d.get("webdav_path", "")),
            "sort_order": max(0, min(999, int(d.get("sort_order", i) or i))),
        })
    ok = set_user_drives(username, clean_drives)
    if ok:
        if len(clean_drives) >= 1:
            update_user(username, drive_letter=clean_drives[0]["drive_letter"],
                        label=clean_drives[0]["label"])
        _audit("admin", "set_drives", f"设置用户 {username} 盘符: {','.join(d['drive_letter'] for d in clean_drives)}")
        return jsonify({"success": True})
    return jsonify({"error": "保存失败"}), 500


@app.route("/api/auth/drives", methods=["GET"])
@require_auth
def user_get_drives():
    username = request.user.get("sub", "")
    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    drives = get_user_drives(username)
    if not drives:
        drives = [{"drive_letter": user.get("drive_letter", "Z:"),
                    "label": user.get("label", "远程磁盘"),
                    "webdav_path": ""}]
    return jsonify({"drives": drives})


_cache_size_cache = {}
_cache_size_lock = threading.Lock()
_CACHE_SIZE_TTL = 60


@app.route("/api/auth/cache-config", methods=["GET"])
@require_auth
def user_cache_config():
    username = request.user.get("sub", "")
    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    cache_size_mb = 0
    now = time.time()
    with _cache_size_lock:
        if username in _cache_size_cache:
            ts, cached = _cache_size_cache[username]
            if now - ts < _CACHE_SIZE_TTL:
                cache_size_mb = cached
            else:
                del _cache_size_cache[username]
    with _cache_size_lock:
        need_scan = username not in _cache_size_cache
    if need_scan:
        cache_dir = os.path.join(BASE_DIR, "cache", username)
        if os.path.exists(cache_dir):
            try:
                total = 0
                count = 0
                for dirpath, dirnames, filenames in os.walk(cache_dir):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        try:
                            total += os.path.getsize(fp)
                            count += 1
                        except Exception:
                            pass
                        if count > 50000:
                            break
                    if count > 50000:
                        break
                cache_size_mb = round(total / (1024 * 1024), 2)
            except Exception:
                pass
        with _cache_size_lock:
            _cache_size_cache[username] = (now, cache_size_mb)
    return jsonify({
        "cache_mode": "full",
        "cache_max_size_mb": 10240,
        "cache_max_age_hours": 72,
        "offline_enabled": True,
        "cache_size_mb": cache_size_mb,
    })


@app.route("/api/admin/change-password", methods=["POST"])
@require_admin
def admin_change_password():
    """管理员修改自己的密码"""
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    if not new_password or len(new_password) < 6 or len(new_password) > _MAX_PASSWORD_LEN:
        return jsonify({"error": "新密码需6-128个字符"}), 400

    admin = get_user("admin")
    if not admin or not verify_password(old_password, admin["password_hash"]):
        return jsonify({"error": "当前密码错误"}), 401

    update_user("admin", password_hash=hash_password(new_password))
    return jsonify({"success": True})


@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def user_change_password():
    """普通用户修改密码，同步到 AList"""
    username = request.user.get("sub", "")
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    encrypted = data.get("encrypted", False)

    if encrypted:
        dec = _rsa_decrypt_password(old_password)
        if dec is None:
            return jsonify({"error": "旧密码解密失败"}), 400
        old_password = dec
        dec2 = _rsa_decrypt_password(new_password)
        if dec2 is None:
            return jsonify({"error": "新密码解密失败"}), 400
        new_password = dec2

    if not new_password or len(new_password) < 6 or len(new_password) > _MAX_PASSWORD_LEN:
        return jsonify({"error": "新密码需6-128个字符"}), 400

    if len(old_password) > _MAX_PASSWORD_LEN:
        return jsonify({"error": "当前密码错误"}), 401

    user = get_user(username)
    if not user:
        return jsonify({"error": "用户不存在"}), 404

    if not verify_password(old_password, user["password_hash"]):
        return jsonify({"error": "当前密码错误"}), 401

    alist_id = int(user.get("alist_id", 0) or 0)
    alist_role_id = int(user.get("alist_role_id", 0) or 0)
    alist_base_path = user.get("alist_base_path", "/公司文件") or "/公司文件"
    is_admin_user = (username == "admin")
    alist_synced = False

    if alist_id and CONFIG.get("alist_token") and not is_admin_user:
        ok, err = alist_update_user(alist_id, username, password=new_password,
                                     base_path=alist_base_path, role_id=alist_role_id)
        if not ok:
            logging.warning(f"[Auth] 用户 {username} 密码同步到 AList 失败: {err}")
        else:
            alist_synced = True

    update_user(username, password_hash=hash_password(new_password))

    if alist_synced:
        logging.info(f"[Auth] 用户 {username} 密码已修改并同步到 AList")
    else:
        logging.info(f"[Auth] 用户 {username} 密码已修改")

    _audit(username, "change_password", "修改密码")
    return jsonify({"success": True})


@app.route("/api/admin/alist/sync", methods=["POST"])
@require_admin
def alist_sync():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    if not token:
        alist_ensure_token()
        token = CONFIG.get("alist_token", "")
    if not token:
        return jsonify({"error": "未配置 AList Token，请先配置管理员凭据"}), 400
    results, err = sync_from_alist(token=token)
    if err:
        return jsonify({"error": err}), 500
    return jsonify({"success": True, **results})


@app.route("/api/admin/alist/test", methods=["POST"])
@require_admin
def alist_test():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()
    alist_url = data.get("alist_url", "").strip()
    old_url = CONFIG.get("alist_url", "")
    try:
        if alist_url:
            CONFIG["alist_url"] = alist_url
        if not token:
            alist_ensure_token()
            token = CONFIG.get("alist_token", "")
        if not token:
            return jsonify({"error": "未提供 Token，请先配置管理员凭据并保存"}), 400
        users, err = alist_get_users(token=token)
        if err:
            return jsonify({"error": err}), 400
        role_paths_map = {}
        try:
            rp, _ = alist_get_roles(token=token)
            if rp:
                role_paths_map = rp
        except Exception:
            pass
        result_users = []
        for u in users[:100]:
            rid_list = u.get("role", [])
            paths = []
            for rid in (rid_list if isinstance(rid_list, list) else [rid_list]):
                rp = role_paths_map.get(int(rid) if rid else 0, [])
                paths.extend(rp)
            result_users.append({
                "id": u.get("id"),
                "username": u.get("username", ""),
                "base_path": u.get("base_path", ""),
                "role_paths": paths,
                "role": u.get("role", []),
                "disabled": u.get("disabled", False)
            })
        return jsonify({
            "success": True, "message": f"连接成功，发现 {len(users)} 个用户",
            "user_count": len(users),
            "users": result_users,
        })
    finally:
        if alist_url:
            CONFIG["alist_url"] = old_url


@app.route("/api/admin/alist/config", methods=["POST"])
@require_admin
def alist_save_config():
    data = request.get_json(silent=True) or {}
    changed = False
    for k in ("alist_url", "alist_token"):
        if k in data:
            CONFIG[k] = data[k].strip()
            changed = True
    for k in ("alist_admin_user", "alist_admin_pass"):
        if k in data:
            val = data[k].strip()
            if val and val != "***":
                CONFIG[k] = val
                changed = True
    if "alist_recycle_dir" in data:
        CONFIG["alist_recycle_dir"] = data["alist_recycle_dir"].strip()
        changed = True
    for k in ("alist_admin_user", "alist_admin_pass"):
        if k in data:
            val = data[k].strip()
            # 密码字段: 前端传 "***" 表示未修改，跳过
            if val and val != "***":
                CONFIG[k] = val
                changed = True
    if "alist_sync_on_login" in data:
        CONFIG["alist_sync_on_login"] = bool(data["alist_sync_on_login"])
        changed = True
    if changed:
        save_config(CONFIG)
    # 管理员凭据变更后立即刷新 token，并返回刷新结果
    admin_user = CONFIG.get("alist_admin_user", "")
    admin_pass = CONFIG.get("alist_admin_pass", "")
    token_refreshed = False
    refresh_error = None
    if admin_user and admin_pass:
        ok, err = alist_refresh_token()
        token_refreshed = ok
        refresh_error = err
    return jsonify({
        "success": True,
        "token_refreshed": token_refreshed,
        "refresh_error": refresh_error,
    })


@app.route("/api/admin/alist/roles", methods=["GET"])
@require_admin
def alist_get_roles_api():
    """获取 AList 角色列表（用于管理后台下拉选择）"""
    roles, err = alist_get_roles_raw()
    if err:
        return jsonify({"error": str(err)}), 500
    return jsonify({"roles": roles})


@app.route("/api/admin/alist/role-sync", methods=["POST"])
@require_admin
def alist_role_sync():
    """手动触发：同步本地角色用户的 base_path 到 AList（替代自动循环）"""
    token = CONFIG.get("alist_token", "")
    if not token:
        return jsonify({"error": "AList Token 未配置"}), 400
    try:
        # 拉取角色列表
        d, rerr = _alist_request("get", "/api/admin/role/list")
        if rerr or not d:
            return jsonify({"error": f"获取角色列表失败: {rerr}"}), 500
        rcontent = d.get("data", [])
        if isinstance(rcontent, dict):
            rcontent = rcontent.get("content", [])
        if not isinstance(rcontent, list):
            rcontent = []

        role_info = {}
        for role in rcontent:
            rid = role.get("id", 0)
            if not rid:
                continue
            scopes = role.get("permission_scopes", [])
            paths = [s.get("path", "") for s in scopes if isinstance(s, dict)]
            personal = [p for p in paths if "个人盘" in p]
            role_info[rid] = {
                "base_path": _common_parent_path(paths),
                "personal_paths": personal,
                "all_paths": paths,
            }

        # 拉取 AList 用户
        alist_users, err = alist_get_users(token)
        if err or not alist_users:
            return jsonify({"error": f"获取用户列表失败: {err}"}), 500
        alist_map = {}
        for au in alist_users:
            aid = au.get("id", 0)
            if aid:
                alist_map[aid] = au

        fixed = 0
        for lu in list_users():
            role_id = int(lu.get("alist_role_id", 0) or 0)
            alist_id = int(lu.get("alist_id", 0) or 0)
            if role_id <= 0 or alist_id <= 0:
                continue
            info = role_info.get(role_id)
            if not info:
                continue
            expected_bp = info["base_path"]
            au = alist_map.get(alist_id)
            if not au:
                continue
            cur_bp = au.get("base_path", "")
            if cur_bp != expected_bp:
                ok, _err = alist_update_user(
                    alist_id=alist_id, username=lu["username"],
                    base_path=expected_bp, role_id=role_id, token=token)
                if ok:
                    fixed += 1
                    update_user(lu["username"], alist_base_path=expected_bp)
                    with _remount_users_lock:
                        _remount_users.add(lu["username"])
        return jsonify({"success": True, "fixed": fixed})
    except Exception as e:
        return jsonify({"error": "内部错误"}), 500


@app.route("/api/admin/alist/config", methods=["GET"])
@require_admin
def alist_get_config():
    expire = CONFIG.get("alist_token_expire", 0)
    token = CONFIG.get("alist_token", "")
    token_valid = bool(token and expire and expire - time.time() > 0)
    return jsonify({
        "alist_url": CONFIG.get("alist_url", ""),
        "alist_token": "***" if token else "",
        "alist_token_set": bool(token),
        "alist_token_valid": token_valid,
        "alist_token_expire": expire,
        "alist_admin_user": CONFIG.get("alist_admin_user", ""),
        "alist_admin_pass": "***" if CONFIG.get("alist_admin_pass") else "",
        "alist_admin_set": bool(CONFIG.get("alist_admin_user") and CONFIG.get("alist_admin_pass")),
        "alist_sync_on_login": CONFIG.get("alist_sync_on_login", True),
    })


# ---------- Web Management ----------

ADMIN_HTML = r"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>morong远程磁盘 认证服务管理</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;
     background:#f0f2f5;color:#333;min-height:100vh;font-size:16px;line-height:1.6}
.wrap{width:98%;max-width:none;margin:0 auto;padding:30px 20px}
h1{font-size:28px;margin-bottom:4px;letter-spacing:.5px}
.sub{color:#888;font-size:16px;margin-bottom:22px}
.card{background:#fff;border-radius:12px;padding:26px 30px;margin-bottom:20px;
      box-shadow:0 2px 8px rgba(0,0,0,.06)}
.card h2{font-size:19px;margin-bottom:16px;color:#1a73e8;display:flex;align-items:center;gap:10px}
.row{display:flex;gap:12px;margin-bottom:12px;align-items:center;flex-wrap:wrap}
.row label{min-width:90px;font-size:16px;color:#555;font-weight:500}
.row input,.row select{flex:1;min-width:110px;padding:9px 13px;border:1px solid #d9d9d9;
     border-radius:8px;font-size:16px;outline:none;transition:border-color .2s}
.row input:focus,.row select:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.12)}
button{padding:9px 20px;border:none;border-radius:8px;font-size:16px;cursor:pointer;transition:all .2s;font-weight:500}
.btn-primary{background:#1a73e8;color:#fff}.btn-primary:hover{background:#1557b0;box-shadow:0 2px 6px rgba(26,115,232,.3)}
.btn-success{background:#27ae60;color:#fff}.btn-success:hover{background:#219a52;box-shadow:0 2px 6px rgba(39,174,96,.3)}
.btn-warning{background:#f39c12;color:#fff}.btn-warning:hover{background:#d68910}
.btn-danger{background:#e74c3c;color:#fff}.btn-danger:hover{background:#c0392b;box-shadow:0 2px 6px rgba(231,76,60,.3)}
.btn-outline{background:#fff;color:#1a73e8;border:1px solid #1a73e8}.btn-outline:hover{background:#e8f0fe}
.btn-sm{padding:7px 18px;font-size:15px}
.table-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:16px}
th,td{padding:14px 14px;text-align:left;border-bottom:1px solid #f0f0f0}
th{background:#f8f9fb;color:#555;font-weight:600;font-size:15px;letter-spacing:.3px}
tbody tr:hover{background:#f8fafd}
.badge{display:inline-block;padding:4px 14px;border-radius:12px;font-size:14px;font-weight:500}
.badge-on{background:#e6f7e6;color:#27ae60}
.badge-off{background:#fde8e8;color:#e74c3c}
.badge-alist{background:#e8f0fe;color:#1a73e8}
.badge-online{background:#e6f7e6;color:#27ae60}
.badge-offline{background:#f5f5f5;color:#999}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot-on{background:#27ae60;box-shadow:0 0 4px rgba(39,174,96,.4)}.dot-off{background:#ccc}
.update-banner{background:#fff3e0;color:#e65100;padding:12px 20px;border-radius:10px;margin-bottom:14px;
               display:none;font-size:14px;align-items:center;gap:10px}
.update-banner button{background:#e65100;color:#fff;padding:7px 18px;font-size:14px}
.msg{padding:12px 18px;border-radius:8px;margin-bottom:12px;font-size:16px;display:none;font-weight:500}
.msg-ok{background:#e6f7e6;color:#27ae60}
.msg-err{background:#fde8e8;color:#e74c3c}
.tabs{display:flex;gap:6px;margin-bottom:20px}
.tab{padding:11px 30px;border-radius:10px 10px 0 0;background:#e8e8e8;cursor:pointer;
     font-size:17px;color:#666;transition:all .2s;font-weight:500}
.tab.active{background:#fff;color:#1a73e8;font-weight:600;box-shadow:0 -2px 8px rgba(0,0,0,.06)}
.tab-content{display:none}.tab-content.active{display:block}
.sync-log{background:#f8f9fa;border-radius:8px;padding:14px 18px;font-size:15px;
          font-family:Consolas,monospace;max-height:280px;overflow-y:auto;margin-top:12px;
          white-space:pre-wrap;color:#555;display:none}
.stat{display:inline-block;padding:6px 20px;border-radius:20px;font-size:16px;font-weight:600;margin-right:10px}
.stat-ok{background:#e6f7e6;color:#27ae60}
.stat-info{background:#e8f0fe;color:#1a73e8}
.sync-arrow{display:inline-block;margin:0 8px;font-size:18px;color:#1a73e8}
.login-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);
               display:flex;align-items:center;justify-content:center;z-index:999}
.login-box{background:#fff;border-radius:16px;padding:40px 44px;width:420px;box-shadow:0 12px 40px rgba(0,0,0,.2)}
.login-box h2{font-size:22px;color:#1a73e8;margin-bottom:20px;text-align:center}
.login-box input{width:100%;padding:12px 16px;border:1px solid #d9d9d9;border-radius:10px;
                 font-size:16px;outline:none;margin-bottom:14px;transition:border-color .2s}
.login-box input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.12)}
.login-box button{width:100%;padding:12px;border:none;border-radius:10px;background:#1a73e8;
                  color:#fff;font-size:16px;cursor:pointer;font-weight:600}
.login-box button:hover{background:#1557b0}
.login-box .err{color:#e74c3c;font-size:14px;margin-bottom:10px;display:none}
.hw-section{margin-bottom:16px;border:1px solid #e8e8e8;border-radius:10px;padding:14px 18px}
.hw-title{font-size:16px;font-weight:600;color:#1a73e8;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #f0f0f0}
.hw-row{display:flex;padding:4px 0;font-size:15px}
.hw-label{min-width:100px;color:#888;flex-shrink:0}
.header-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.header-actions button{margin-left:8px}
.action-btn{padding:6px 14px !important;font-size:14px !important;border-radius:6px !important;white-space:nowrap;display:inline-block;margin:2px 3px}
.search-box{display:flex;align-items:center;gap:8px;margin-bottom:14px}
.search-box input{flex:1;max-width:320px;padding:9px 14px;border:1px solid #d9d9d9;border-radius:8px;font-size:15px;outline:none;transition:border-color .2s}
.search-box input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,.12)}
.pagination{display:flex;align-items:center;justify-content:center;gap:12px;margin-top:14px;padding:8px 0}
.pagination button{padding:7px 18px;font-size:14px;border-radius:6px;cursor:pointer;border:1px solid #d9d9d9;background:#fff;color:#333}
.pagination button:disabled{opacity:0.4;cursor:not-allowed}
.pagination span{font-size:14px;color:#666}
</style>
</head>
<body>

<!-- 管理员登录弹层 -->
<div id="login-overlay" class="login-overlay">
<div class="login-box">
  <!-- 登录表单 -->
  <div id="login-form">
    <h2>morong远程磁盘 管理后台</h2>
    <p style="font-size:14px;color:#888;margin-bottom:16px;text-align:center">请输入管理员密码</p>
    <div id="login-err" class="err"></div>
    <input id="login-pwd" type="password" placeholder="管理员密码" autofocus>
    <button onclick="doAdminLogin()">登 录</button>
    <p style="text-align:center;margin-top:12px"><a href="javascript:void(0)" onclick="toggleLoginMode(true)" style="font-size:14px;color:#1a73e8;text-decoration:none">修改密码</a></p>
  </div>
  <!-- 修改密码表单 -->
  <div id="chpwd-form" style="display:none">
    <h2>修改管理员密码</h2>
    <div id="chpwd-err" class="err"></div>
    <input id="chpwd-old" type="password" placeholder="当前密码" style="margin-bottom:8px">
    <input id="chpwd-new" type="password" placeholder="新密码（至少6位）" style="margin-bottom:8px">
    <input id="chpwd-confirm" type="password" placeholder="确认新密码" style="margin-bottom:12px"
      onkeydown="if(event.key==='Enter')doLoginChangePassword()">
    <button onclick="doLoginChangePassword()">确认修改</button>
    <p style="text-align:center;margin-top:12px"><a href="javascript:void(0)" onclick="toggleLoginMode(false)" style="font-size:14px;color:#1a73e8;text-decoration:none">返回登录</a></p>
  </div>
</div>
</div>

<div class="wrap" id="main-wrap" style="display:none">
<div class="header-bar">
  <div>
    <h1 style="margin:0">morong远程磁盘 认证服务 <span style="font-size:16px;color:#999;font-weight:normal">v1.16.0</span></h1>
  </div>
  <div class="header-actions">
    <button onclick="showChangePassword()" style="padding:9px 22px;font-size:16px;border:1px solid #1a73e8;color:#1a73e8;background:#fff;border-radius:8px;cursor:pointer">修改密码</button>
    <button onclick="doLogout()" style="padding:9px 22px;font-size:16px;border:1px solid #e74c3c;color:#e74c3c;background:#fff;border-radius:8px;cursor:pointer">退出登录</button>
  </div>
</div>
<p class="sub">用户管理 & AList 双向同步</p>

<div id="msg" class="msg"></div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('users',this)">用户管理</div>
  <div class="tab" onclick="switchTab('alist',this)">AList 同步</div>
  <div class="tab" onclick="switchTab('audit',this)">登录日志</div>
  <div class="tab" onclick="switchTab('notify',this)">通知推送</div>
  <div class="tab" onclick="switchTab('tools',this)">工具</div>
</div>

<!-- ============ 用户管理 ============ -->
<div id="tab-users" class="tab-content active">
<div class="card">
<h2>添加用户 <span class="sync-arrow">&#8644;</span> <span style="font-size:16px;color:#27ae60;font-weight:normal">自动同步到 AList</span></h2>
<div class="row">
  <label>用户名</label><input id="nu" placeholder="用户名">
  <label>密码</label><input id="np" type="password" placeholder="密码">
</div>
<div class="row">
  <label>AList路径</label><input id="npath" value="/公司文件" placeholder="/公司文件">
  <label>角色</label><select id="nrole" style="max-width:200px"><option value="0">无角色</option></select>
  <label>盘符</label><input id="ndrv" value="Z:" style="max-width:50px">
  <button class="btn-primary" onclick="addUser()">添加</button>
</div>
</div>

<div class="card">
<h2>用户列表 <span id="user-count" style="font-size:16px;color:#999;font-weight:normal"></span>
  <span style="margin-left:auto">
    <button class="btn-sm btn-success" onclick="quickSync()" id="quick-sync-btn">从 AList 一键同步</button>
  </span>
</h2>
<div id="quick-sync-msg" style="display:none;padding:12px 16px;border-radius:8px;margin-bottom:14px;font-size:16px"></div>
<div class="search-box">
  <label style="min-width:auto;font-size:15px;color:#555;font-weight:500">搜索用户</label>
  <input id="user-search" type="text" placeholder="输入用户名搜索..." oninput="filterUsers()">
</div>
<div class="table-scroll">
<table>
<thead><tr><th>用户名</th><th style="white-space:nowrap">AList ID</th><th>AList 路径</th><th>角色</th><th style="white-space:nowrap">盘符</th><th style="white-space:nowrap">磁盘状态</th><th style="white-space:nowrap">账号状态</th><th>最后登录</th><th>操作</th></tr></thead>
<tbody id="tb"></tbody>
</table>
</div>
<div id="user-pages" style="text-align:center;margin-top:8px"></div>
</div>
</div>

<!-- ============ AList 同步 ============ -->
<div id="tab-alist" class="tab-content">
<div class="card">
<h2>AList 连接配置</h2>
<div class="row">
  <label>AList 地址</label><input id="alist-url" placeholder="http://192.168.100.242:5244">
</div>
<div class="row">
  <label>管理员账号</label><input id="alist-admin-user" placeholder="AList 管理员用户名 (用于自动刷新 Token)">
</div>
<div class="row">
  <label>管理员密码</label><input id="alist-admin-pass" type="password" placeholder="AList 管理员密码">
</div>
<div class="row">
  <label>管理员Token</label><input id="alist-token" type="password" placeholder="自动获取，无需手动填写" readonly style="background:#f5f5f5">
  <span id="alist-token-status" style="font-size:16px;color:#999;margin-left:10px;white-space:nowrap"></span>
</div>
<div class="row" style="gap:8px">
  <button class="btn-outline" onclick="testAList()">测试连接</button>
  <button class="btn-success" onclick="syncFromAList()">AList → AuthServer</button>
  <button class="btn-outline" onclick="syncRoleBasePaths()" style="color:#e67e22;border-color:#e67e22">同步角色</button>
  <button class="btn-primary" onclick="saveAListConfig()">保存配置</button>
</div>
<div class="row" style="margin-top:6px">
  <label style="min-width:auto;font-size:16px;color:#999">
    <input type="checkbox" id="alist-sync-login" checked style="width:auto;margin-right:6px">
    登录时代理验证 AList 凭据（本地未匹配时自动尝试 AList 认证）
  </label>
</div>
</div>

<div class="card">
<h2>同步结果</h2>
<div id="sync-stats" style="margin-bottom:8px"></div>
<div id="sync-log" class="sync-log"></div>
<p id="sync-placeholder" style="color:#999;font-size:17px;line-height:1.8">
  点击上方「AList → AuthServer」从 AList 拉取全部用户<br>
  添加/修改/删除用户时会自动双向同步到 AList
</p>
</div>

<div class="card">
<h2>AList 用户预览</h2>
<div id="alist-preview-info" style="font-size:13px;color:#888;margin-bottom:6px"></div>
<table>
<thead><tr><th>ID</th><th>用户名</th><th>路径</th><th>角色</th><th>状态</th></tr></thead>
<tbody id="alist-preview"><tr><td colspan="5" style="color:#999;font-size:17px;padding:20px">点击「测试连接」查看</td></tr></tbody>
</table>
<div id="alist-preview-pages" style="text-align:center;margin-top:8px"></div>
</div>
</div>
</div>

<!-- ============ 登录日志 ============ -->
<div id="tab-audit" class="tab-content">
<div class="card">
<h2>登录日志</h2>
<div class="row" style="gap:8px;align-items:center">
  <label style="min-width:auto">用户</label><input id="audit-user" placeholder="留空查全部" style="max-width:150px">
  <button class="btn-primary" onclick="loadAuditLogs()">查询</button>
  <button class="btn-outline" style="color:#e74c3c;border-color:#e74c3c" onclick="clearAuditLogs()">清空日志</button>
</div>
<div class="table-scroll">
<table>
<thead><tr><th>时间</th><th>用户</th><th>操作</th><th>详情</th><th>IP</th></tr></thead>
<tbody id="audit-tb"><tr><td colspan="5" style="color:#999;padding:20px">点击查询查看登录日志</td></tr></tbody>
</table>
</div>
<div style="margin-top:10px;display:flex;gap:8px;align-items:center">
  <span id="audit-page-info" style="font-size:14px;color:#999"></span>
  <button class="btn-outline" onclick="auditPage(-1)" id="audit-prev">上一页</button>
  <button class="btn-outline" onclick="auditPage(1)" id="audit-next">下一页</button>
</div>
</div>
</div>

<!-- ============ 通知推送 ============ -->
<div id="tab-notify" class="tab-content">
<div class="card">
<h2>推送通知</h2>
<div class="row">
  <label>目标用户</label><input id="notify-user" placeholder="留空则全员推送">
  <label>标题</label><input id="notify-title" placeholder="通知标题">
  <label>显示时长</label><input id="notify-duration" type="number" min="1" max="3600" value="5" placeholder="秒" style="max-width:80px"> 秒
</div>
<div class="row">
  <label style="min-width:auto">内容</label>
  <textarea id="notify-content" placeholder="通知内容" style="flex:1;min-height:60px;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:15px;resize:vertical"></textarea>
</div>
<div class="row" style="gap:8px">
  <button class="btn-primary" onclick="sendNotification()">发送通知</button>
</div>
</div>
<div class="card">
<h2>通知历史</h2>
<div class="row" style="gap:8px;align-items:center">
  <label style="min-width:auto">标题</label><input id="notify-search" placeholder="搜索标题" style="max-width:200px">
  <button class="btn-primary" onclick="searchNotifyHistory()">查询</button>
  <button class="btn-outline" style="color:#e74c3c;border-color:#e74c3c" onclick="clearNotifyHistory()">清空推送</button>
</div>
<div class="table-scroll">
<table>
<thead><tr><th>ID</th><th>用户</th><th>标题</th><th>内容</th><th>已读</th><th>时间</th></tr></thead>
<tbody id="notify-tb"><tr><td colspan="6" style="color:#999;padding:20px">加载中...</td></tr></tbody>
</table>
</div>
<div id="notify-pages" style="text-align:center;margin-top:8px"></div>
</div>
</div>

<!-- ============ 工具 ============ -->
<div id="tab-tools" class="tab-content">
<div class="card">
<h2>批量导入用户</h2>
<p style="color:#666;font-size:15px;margin-bottom:12px">每行一个用户，格式：用户名,密码,AList路径,盘符（逗号分隔）</p>
<textarea id="batch-users" placeholder="zhangsan,pass123,/公司文件/张三,Z:&#10;lisi,pass456,/公司文件/李四,Y:" style="width:100%;min-height:120px;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;resize:vertical;box-sizing:border-box"></textarea>
<div style="margin-top:10px;display:flex;gap:8px">
  <button class="btn-primary" onclick="batchImport()">批量导入</button>
  <span id="batch-result" style="font-size:15px;color:#666;align-self:center"></span>
</div>
</div>
<div class="card">
<h2>用户配额管理</h2>
<div class="row">
  <label>用户名</label><input id="quota-user" placeholder="用户名">
  <label>配额(MB)</label><input id="quota-mb" type="number" placeholder="0=不限" style="max-width:100px">
  <button class="btn-primary" onclick="setUserQuota()">设置</button>
  <button class="btn-outline" onclick="getUserQuota()">查询</button>
</div>
<div id="quota-info" style="margin-top:8px;font-size:15px;color:#666"></div>
</div>
<div class="card">
<h2>回收站管理</h2>
<div class="row">
  <label>用户名</label><input id="recycle-user" placeholder="用户名">
  <label>自动清理(天)</label><input id="recycle-auto-days" type="number" placeholder="0=不清理" style="max-width:90px">
  <button class="btn-outline" onclick="setRecycleAutoCleanup()" style="font-size:13px">设置</button>
  <button class="btn-primary" onclick="loadRecycleBin()">查看</button>
  <button class="btn-outline" onclick="clearRecycleBin()" style="color:#e74c3c;border-color:#e74c3c">清空</button>
  <button class="btn-outline" onclick="showRecycleDeleteLogs()" style="font-size:13px">删除日志</button>
</div>
<div class="table-scroll">
<table>
<thead><tr><th>原路径</th><th>文件名</th><th style="color:#e74c3c">归属用户</th><th style="color:#e74c3c">备注说明</th><th>大小</th><th>删除时间</th><th>操作</th></tr></thead>
<tbody id="recycle-tb"><tr><td colspan="7" style="color:#999;padding:20px">输入用户名查看回收站</td></tr></tbody>
</table>
</div>
</div>
</div>

<!-- 硬件信息弹窗 -->
<div id="hw-modal" onclick="if(event.target===this)closeHardware()" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);z-index:1000;justify-content:center;align-items:center">
<div style="background:#fff;border-radius:14px;padding:32px;max-width:640px;width:90%;max-height:85vh;overflow-y:auto;position:relative;box-shadow:0 12px 40px rgba(0,0,0,.2)">
<button onclick="closeHardware()" style="position:absolute;top:14px;right:18px;background:#f0f0f0;border:none;font-size:22px;cursor:pointer;color:#666;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:all .2s" onmouseover="this.style.background='#e74c3c';this.style.color='#fff'" onmouseout="this.style.background='#f0f0f0';this.style.color='#666'">&times;</button>
<button id="hw-copy-btn" onclick="copyHardwareInfo()" style="position:absolute;top:20px;right:64px;background:#e8f0fe;color:#1a73e8;border:1px solid #1a73e8;border-radius:6px;padding:5px 14px;font-size:13px;cursor:pointer;display:none">复制到剪贴板</button>
<div id="hw-content"></div>
</div>
</div>

<!-- 执行日志弹窗 -->
<div id="cmd-modal" onclick="if(event.target===this)closeCommands()" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);z-index:1000;justify-content:center;align-items:center">
<div style="background:#fff;border-radius:14px;padding:32px;max-width:800px;width:90%;max-height:85vh;overflow-y:auto;position:relative;box-shadow:0 12px 40px rgba(0,0,0,.2)">
<button onclick="closeCommands()" style="position:absolute;top:14px;right:18px;background:#f0f0f0;border:none;font-size:22px;cursor:pointer;color:#666;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:all .2s" onmouseover="this.style.background='#e74c3c';this.style.color='#fff'" onmouseout="this.style.background='#f0f0f0';this.style.color='#666'">&times;</button>
<div id="cmd-content"></div>
</div>
</div>

<!-- 文件日志弹窗 -->
<div id="filelog-modal" onclick="if(event.target===this)closeFileLogs()" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);z-index:1000;justify-content:center;align-items:center">
<div style="background:#fff;border-radius:14px;padding:32px;max-width:900px;width:90%;max-height:85vh;overflow-y:auto;position:relative;box-shadow:0 12px 40px rgba(0,0,0,.2)">
<button onclick="closeFileLogs()" style="position:absolute;top:14px;right:18px;background:#f0f0f0;border:none;font-size:22px;cursor:pointer;color:#666;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:all .2s" onmouseover="this.style.background='#e74c3c';this.style.color='#fff'" onmouseout="this.style.background='#f0f0f0';this.style.color='#666'">&times;</button>
<div id="filelog-content"></div>
</div>
</div>

<!-- 修改密码弹窗 -->
<div id="cp-modal" onclick="if(event.target===this)closeChangePassword()" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);z-index:1000;justify-content:center;align-items:center">
<div style="background:#fff;border-radius:14px;padding:32px;max-width:460px;width:90%;position:relative;box-shadow:0 12px 40px rgba(0,0,0,.2)">
<button onclick="closeChangePassword()" style="position:absolute;top:14px;right:18px;background:#f0f0f0;border:none;font-size:22px;cursor:pointer;color:#666;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:all .2s" onmouseover="this.style.background='#e74c3c';this.style.color='#fff'" onmouseout="this.style.background='#f0f0f0';this.style.color='#666'">&times;</button>
<h3 style="margin:0 0 20px 0;font-size:20px">修改管理员密码</h3>
<div id="cp-err" class="err" style="display:none"></div>
<label style="display:block;margin-bottom:6px;font-size:15px;color:#555">当前密码</label>
<input id="cp-old-pwd" type="password" placeholder="当前密码" style="width:100%;margin-bottom:14px;padding:10px 14px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box;font-size:15px">
<label style="display:block;margin-bottom:6px;font-size:15px;color:#555">新密码</label>
<input id="cp-new-pwd" type="password" placeholder="新密码（至少6位）" style="width:100%;margin-bottom:14px;padding:10px 14px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box;font-size:15px">
<label style="display:block;margin-bottom:6px;font-size:15px;color:#555">确认新密码</label>
<input id="cp-confirm-pwd" type="password" placeholder="再次输入新密码" style="width:100%;margin-bottom:18px;padding:10px 14px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box;font-size:15px"
  onkeydown="if(event.key==='Enter')doChangePassword()">
<button onclick="doChangePassword()" style="width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:16px;font-weight:600">确认修改</button>
</div>
</div>

<!-- 编辑用户弹窗 -->
<div id="edit-user-modal" onclick="if(event.target===this)closeEditUser()" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);z-index:1000;justify-content:center;align-items:center">
<div style="background:#fff;border-radius:14px;padding:32px;max-width:500px;width:90%;position:relative;box-shadow:0 12px 40px rgba(0,0,0,.2)">
<button onclick="closeEditUser()" style="position:absolute;top:14px;right:18px;background:#f0f0f0;border:none;font-size:22px;cursor:pointer;color:#666;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;transition:all .2s" onmouseover="this.style.background='#e74c3c';this.style.color='#fff'" onmouseout="this.style.background='#f0f0f0';this.style.color='#666'">&times;</button>
<h3 style="margin:0 0 20px 0;font-size:20px">编辑用户 - <span id="edit-user-title"></span></h3>
<div id="edit-user-err" class="err" style="display:none"></div>
<input type="hidden" id="edit-username">
<div class="row">
  <label>盘符</label><input id="edit-drive-letter" placeholder="Z:" style="max-width:80px">
  <label>标签</label><input id="edit-label" placeholder="远程磁盘">
</div>
<div style="margin:12px 0">
  <label style="display:block;margin-bottom:8px;font-size:15px;color:#555;font-weight:600">多盘符配置</label>
  <div id="edit-drives-list" style="display:flex;flex-direction:column;gap:8px"></div>
  <button type="button" onclick="addEditDriveRow()" style="margin-top:8px;padding:6px 14px;background:#f0f4ff;color:#1a73e8;border:1px dashed #1a73e8;border-radius:6px;cursor:pointer;font-size:14px">+ 添加盘符</button>
</div>
<div class="row">
  <label>角色</label><select id="edit-role" style="max-width:200px"><option value="0">无角色</option></select>
</div>
<div class="row">
  <label>账号状态</label>
  <select id="edit-active" style="max-width:120px">
    <option value="1">启用</option>
    <option value="0">禁用</option>
  </select>
</div>
<div style="margin-top:18px;text-align:right">
  <button class="btn-outline" onclick="closeEditUser()" style="margin-right:8px">取消</button>
  <button class="btn-primary" onclick="saveEditUser()">保存</button>
</div>
</div>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

let adminToken = localStorage.getItem('admin_token') || '';
let adminTokenExpires = 0;
let _tokenRefreshTimer = null;

if (localStorage.getItem('admin_token_expires')) {
  adminTokenExpires = parseInt(localStorage.getItem('admin_token_expires')) || 0;
}

(async function autoLogin() {
  if (!adminToken) return;
  if (adminTokenExpires && Date.now() / 1000 > adminTokenExpires) {
    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_token_expires');
    adminToken = '';
    adminTokenExpires = 0;
    return;
  }
  try {
    const r = await fetch('/api/admin/users', {headers:{'X-Admin-Auth': adminToken}});
    if (r.status === 200) {
      $('login-overlay').style.display = 'none';
      $('main-wrap').style.display = '';
      scheduleTokenRefresh();
      loadUsers();
      loadAListConfig();
      loadNotifyHistory();
    } else {
      localStorage.removeItem('admin_token');
      localStorage.removeItem('admin_token_expires');
      adminToken = '';
      adminTokenExpires = 0;
    }
  } catch(e) {}
})();

async function doAdminLogin() {
  const pwd = $('login-pwd').value;
  if (!pwd) return;
  try {
    const r = await fetch('/api/admin/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: pwd})
    });
    const d = await r.json();
    if (r.status === 200 && d.token) {
      adminToken = d.token;
      adminTokenExpires = d.expires_at || 0;
      localStorage.setItem('admin_token', adminToken);
      localStorage.setItem('admin_token_expires', String(adminTokenExpires));
      $('login-overlay').style.display = 'none';
      $('main-wrap').style.display = '';
      scheduleTokenRefresh();
      loadUsers();
      loadAListConfig();
      loadNotifyHistory();
    } else {
      const err = $('login-err');
      err.textContent = d.error || '密码错误';
      err.style.display = 'block';
      $('login-pwd').select();
    }
  } catch(e) {
    const err = $('login-err');
    err.textContent = '网络错误: ' + e.message;
    err.style.display = 'block';
  }
}
$('login-pwd').addEventListener('keydown', e => { if (e.key === 'Enter') doAdminLogin(); });

function scheduleTokenRefresh() {
  if (_tokenRefreshTimer) clearTimeout(_tokenRefreshTimer);
  if (!adminTokenExpires) return;
  const now = Date.now() / 1000;
  const refreshAt = adminTokenExpires - 300;
  const delay = Math.max((refreshAt - now) * 1000, 60000);
  _tokenRefreshTimer = setTimeout(async () => {
    try {
      const r = await fetch('/api/admin/refresh-token', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Admin-Auth': adminToken}
      });
      if (r.status === 200) {
        const d = await r.json();
        adminToken = d.token;
        adminTokenExpires = d.expires_at || 0;
        localStorage.setItem('admin_token', adminToken);
        localStorage.setItem('admin_token_expires', String(adminTokenExpires));
        scheduleTokenRefresh();
      } else {
        doLogout();
      }
    } catch(e) {
      scheduleTokenRefresh();
    }
  }, delay);
}

function toggleLoginMode(toChangePwd) {
  $('login-form').style.display = toChangePwd ? 'none' : '';
  $('chpwd-form').style.display = toChangePwd ? '' : 'none';
  $('login-err').style.display = 'none';
  $('chpwd-err').style.display = 'none';
}
async function doLoginChangePassword() {
  const oldPwd = $('chpwd-old').value;
  const newPwd = $('chpwd-new').value;
  const confirmPwd = $('chpwd-confirm').value;
  const errEl = $('chpwd-err');
  errEl.style.display = 'none';
  if (!oldPwd || !newPwd || !confirmPwd) { errEl.textContent = '请填写所有字段'; errEl.style.display = 'block'; return; }
  if (newPwd !== confirmPwd) { errEl.textContent = '两次输入的新密码不一致'; errEl.style.display = 'block'; return; }
  if (newPwd.length < 6) { errEl.textContent = '新密码至少6个字符'; errEl.style.display = 'block'; return; }
  try {
    const r = await fetch('/api/admin/change-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Admin-Auth': oldPwd},
      body: JSON.stringify({old_password: oldPwd, new_password: newPwd})
    });
    const d = await r.json();
    if (d.success) {
      try {
        const lr = await fetch('/api/admin/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({password: newPwd})
        });
        const ld = await lr.json();
        if (lr.status === 200 && ld.token) {
          adminToken = ld.token;
          adminTokenExpires = ld.expires_at || 0;
          localStorage.setItem('admin_token', adminToken);
          localStorage.setItem('admin_token_expires', String(adminTokenExpires));
          scheduleTokenRefresh();
        }
      } catch(e) {}
      $('login-overlay').style.display = 'none';
      $('main-wrap').style.display = '';
      loadUsers();
      loadAListConfig();
      showMsg('密码修改成功', true);
    } else {
      errEl.textContent = d.error || '修改失败，请检查当前密码是否正确';
      errEl.style.display = 'block';
    }
  } catch(e) {
    errEl.textContent = '网络错误: ' + e.message;
    errEl.style.display = 'block';
  }
}

async function doChangePassword() {
  const oldPwd = $('cp-old-pwd').value;
  const newPwd = $('cp-new-pwd').value;
  const confirmPwd = $('cp-confirm-pwd').value;
  const errEl = $('cp-err');
  errEl.style.display = 'none';
  if (!oldPwd || !newPwd || !confirmPwd) { errEl.textContent = '请填写所有字段'; errEl.style.display = 'block'; return; }
  if (newPwd !== confirmPwd) { errEl.textContent = '两次输入的新密码不一致'; errEl.style.display = 'block'; return; }
  if (newPwd.length < 6) { errEl.textContent = '新密码至少6个字符'; errEl.style.display = 'block'; return; }
  try {
    const r = await api('/api/admin/change-password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({old_password: oldPwd, new_password: newPwd})
    });
    const d = await r.json();
    if (d.success) {
      try {
        const lr = await fetch('/api/admin/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({password: newPwd})
        });
        const ld = await lr.json();
        if (lr.status === 200 && ld.token) {
          adminToken = ld.token;
          adminTokenExpires = ld.expires_at || 0;
          localStorage.setItem('admin_token', adminToken);
          localStorage.setItem('admin_token_expires', String(adminTokenExpires));
          scheduleTokenRefresh();
        }
      } catch(e) {}
      $('cp-modal').style.display = 'none';
      showMsg('密码修改成功', true);
    } else {
      errEl.textContent = d.error || '修改失败';
      errEl.style.display = 'block';
    }
  } catch(e) {
    errEl.textContent = '网络错误: ' + e.message;
    errEl.style.display = 'block';
  }
}
function showChangePassword() {
  $('cp-old-pwd').value = '';
  $('cp-new-pwd').value = '';
  $('cp-confirm-pwd').value = '';
  $('cp-err').style.display = 'none';
  $('cp-modal').style.display = 'flex';
}
function closeChangePassword() {
  $('cp-modal').style.display = 'none';
}
function doLogout() {
  adminToken = '';
  adminTokenExpires = 0;
  localStorage.removeItem('admin_token');
  localStorage.removeItem('admin_token_expires');
  if (_tokenRefreshTimer) { clearTimeout(_tokenRefreshTimer); _tokenRefreshTimer = null; }
  $('login-overlay').style.display = '';
  $('main-wrap').style.display = 'none';
  $('login-pwd').value = '';
}

function api(url, opts) {
  opts = opts || {};
  opts.headers = opts.headers || {};
  if (adminToken) opts.headers['X-Admin-Auth'] = adminToken;
  return fetch(url, opts);
}

function showMsg(text, ok) {
  const el = $('msg');
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
  el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', 4000);
}

function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  $('tab-' + name).classList.add('active');
}

// --- 用户管理 ---
let _allUsers = [];

function isOnline(hbTime) {
  if (!hbTime) return false;
  const diff = (Date.now() - new Date(hbTime).getTime()) / 1000;
  return diff < 120;
}
function formatHbTime(hbTime) {
  if (!hbTime) return '-';
  const d = new Date(hbTime);
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 60) return diff + '秒前';
  if (diff < 3600) return Math.floor(diff/60) + '分钟前';
  if (diff < 86400) return Math.floor(diff/3600) + '小时前';
  return d.toLocaleString();
}
function formatLoginTime(s) {
  if (!s) return '-';
  const days = ['周日','周一','周二','周三','周四','周五','周六'];
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  const Y = d.getFullYear();
  const M = String(d.getMonth()+1).padStart(2,'0');
  const D = String(d.getDate()).padStart(2,'0');
  const h = String(d.getHours()).padStart(2,'0');
  const m = String(d.getMinutes()).padStart(2,'0');
  const sec = String(d.getSeconds()).padStart(2,'0');
  return Y+'-'+M+'-'+D+' '+days[d.getDay()]+' '+h+':'+m+':'+sec;
}
let _userPage = 0;
const _userPageSize = 20;
let _filteredUsers = [];

function renderUsers(users) {
  _filteredUsers = users;
  _userPage = 0;
  _renderUserPage();
}

function _renderUserPage() {
  const users = _filteredUsers;
  const page = _userPage;
  const size = _userPageSize;
  const total = users.length;
  const totalPages = Math.max(1, Math.ceil(total / size));
  const start = page * size;
  const slice = users.slice(start, start + size);
  $('user-count').textContent = '(' + total + ' 人，第 ' + (page+1) + '/' + totalPages + ' 页)';
  $('tb').innerHTML = slice.map(u => {
    const online = isOnline(u.last_heartbeat);
    const un = esc(u.username);
    return `<tr>
    <td><b style="font-size:16px">${un}</b></td>
    <td style="color:#888;font-size:15px">${u.alist_id || '-'}</td>
    <td style="color:#888;font-size:15px;white-space:nowrap">${u.alist_role_paths && u.alist_role_paths.length ? u.alist_role_paths.map(p=>'<span style="display:inline-block;background:#eef2ff;color:#4a5eb5;padding:1px 8px;border-radius:4px;margin:0 3px;font-size:13px">'+esc(p)+'</span>').join('') : (esc(u.alist_base_path) || '-')}</td>
    <td><span class="badge badge-alist">${u.alist_role_id || 0}</span></td>
    <td style="font-size:15px">${u.drives&&u.drives.length>1?u.drives.map(d=>'<span style="display:inline-block;background:#eef2ff;color:#4a5eb5;padding:1px 6px;border-radius:4px;margin:0 2px;font-size:13px">'+esc(d.drive_letter)+'</span>').join(''):esc(u.drive_letter)}</td>
    <td style="white-space:nowrap">${u.disk_hidden==='1'||u.disk_hidden===1?'<span class="badge" style="background:#fdebd0;color:#e67e22;font-size:13px">已脱机</span>':'<span class="badge" style="background:#e6f7e6;color:#27ae60;font-size:13px">正常</span>'}</td>
    <td style="white-space:nowrap"><span class="badge ${u.active?'badge-on':'badge-off'}">${u.active?'启用':'禁用'}</span>
        <span style="margin-left:8px;white-space:nowrap"><span class="dot ${online?'dot-on':'dot-off'}"></span><span style="font-size:14px;color:${online?'#27ae60':'#999'}">${online?'在线':'离线'}</span> <span style="font-size:12px;color:#bbb">${formatHbTime(u.last_heartbeat)}</span></span>
    </td>
    <td style="font-size:15px;white-space:nowrap">${formatLoginTime(u.last_login)}</td>
    <td style="white-space:nowrap;line-height:2.2">
      <button class="action-btn btn-warning" data-username="${un}" onclick="openEditUser(this.dataset.username)" title="编辑用户">编辑</button>
      <button class="action-btn btn-outline" data-username="${un}" onclick="showHardware(this.dataset.username)" title="查看硬件信息">硬件</button>
      <button class="action-btn btn-outline" data-username="${un}" onclick="sendCommand(this.dataset.username,'hide_disks')" title="磁盘脱机" style="color:#e67e22;border-color:#e67e22">脱机</button>
      <button class="action-btn btn-outline" data-username="${un}" onclick="sendCommand(this.dataset.username,'restore_disks')" title="磁盘联机" style="color:#27ae60;border-color:#27ae60">联机</button>
      <button class="action-btn btn-outline" data-username="${un}" onclick="showCommands(this.dataset.username)" title="查看命令执行历史">执行日志</button>
      <button class="action-btn btn-outline" data-username="${un}" onclick="showFileLogs(this.dataset.username)" title="查看文件操作日志" style="color:#3498db;border-color:#3498db">文件日志</button>
      <button class="action-btn btn-primary" data-username="${un}" onclick="toggleUser(this.dataset.username,${u.active})">
        ${u.active?'禁用':'启用'}</button>
      ${u.username!=='admin'?`<button class="action-btn btn-danger" data-username="${un}" onclick="delUser(this.dataset.username)">删除</button>`:''}
    </td></tr>`;
  }).join('');
  let ph = '';
  const totalAll = _filteredUsers.length;
  const totalPagesAll = Math.max(1, Math.ceil(totalAll / _userPageSize));
  if (totalPagesAll > 1) {
    ph += `<button onclick="_userPage=Math.max(0,_userPage-1);_renderUserPage()" style="padding:2px 10px;margin:0 4px;cursor:pointer" ${_userPage===0?'disabled':''}>上一页</button>`;
    for (let i = 0; i < totalPagesAll && i < 10; i++) {
      ph += `<button onclick="_userPage=${i};_renderUserPage()" style="padding:2px 8px;margin:0 2px;cursor:pointer;${i===_userPage?'background:#1a73e8;color:#fff':''}">${i+1}</button>`;
    }
    if (totalPagesAll > 10) ph += `<span style="margin:0 4px">...</span>`;
    ph += `<button onclick="_userPage=Math.min(${totalPagesAll-1},_userPage+1);_renderUserPage()" style="padding:2px 10px;margin:0 4px;cursor:pointer" ${_userPage>=totalPagesAll-1?'disabled':''}>下一页</button>`;
  }
  $('user-pages').innerHTML = ph;
}

function filterUsers() {
  const q = $('user-search').value.trim().toLowerCase();
  if (!q) { renderUsers(_allUsers); return; }
  renderUsers(_allUsers.filter(u => u.username.toLowerCase().includes(q)));
}

async function loadUsers() {
  const r = await api('/api/admin/users');
  const users = await r.json();
  _allUsers = users;
  filterUsers();
}

// --- 编辑用户 ---
let _editDrives = [];
function addEditDriveRow(drive_letter, label, webdav_path) {
  const idx = _editDrives.length;
  _editDrives.push({drive_letter: drive_letter||'Z:', label: label||'远程磁盘', webdav_path: webdav_path||''});
  renderEditDrives();
}
function removeEditDriveRow(idx) {
  _editDrives.splice(idx, 1);
  renderEditDrives();
}
function renderEditDrives() {
  const container = $('edit-drives-list');
  if (!container) return;
  container.innerHTML = _editDrives.map((d, i) =>
    `<div style="display:flex;gap:6px;align-items:center">
      <input placeholder="盘符" value="${esc(d.drive_letter)}" style="width:55px;padding:6px 8px;border:1px solid #ddd;border-radius:6px;font-size:14px" onchange="_editDrives[${i}].drive_letter=this.value">
      <input placeholder="标签" value="${esc(d.label)}" style="width:100px;padding:6px 8px;border:1px solid #ddd;border-radius:6px;font-size:14px" onchange="_editDrives[${i}].label=this.value">
      <input placeholder="WebDAV子路径(留空用默认)" value="${esc(d.webdav_path)}" style="flex:1;padding:6px 8px;border:1px solid #ddd;border-radius:6px;font-size:14px" onchange="_editDrives[${i}].webdav_path=this.value">
      <button type="button" onclick="removeEditDriveRow(${i})" style="background:#fee;color:#c0392b;border:1px solid #fcc;border-radius:6px;cursor:pointer;padding:4px 10px;font-size:16px">&times;</button>
    </div>`
  ).join('');
}
function openEditUser(username) {
  const u = _allUsers.find(x => x.username === username);
  if (!u) return;
  $('edit-username').value = u.username;
  $('edit-user-title').textContent = u.username;
  $('edit-drive-letter').value = u.drive_letter || 'Z:';
  $('edit-label').value = u.label || '';
  $('edit-active').value = u.active ? '1' : '0';
  $('edit-user-err').style.display = 'none';
  const roleSelect = $('edit-role');
  roleSelect.innerHTML = $('nrole').innerHTML;
  roleSelect.value = u.alist_role_id || 0;
  $('edit-user-modal').style.display = 'flex';
  // 加载多盘符
  _editDrives = (u.drives && u.drives.length) ? u.drives.map(d => ({
    drive_letter: d.drive_letter||'Z:', label: d.label||'远程磁盘', webdav_path: d.webdav_path||''
  })) : [{drive_letter: u.drive_letter||'Z:', label: u.label||'远程磁盘', webdav_path: ''}];
  renderEditDrives();
}
function closeEditUser() {
  $('edit-user-modal').style.display = 'none';
}
async function saveEditUser() {
  const username = $('edit-username').value;
  const errEl = $('edit-user-err');
  errEl.style.display = 'none';
  const body = {
    drive_letter: $('edit-drive-letter').value.trim(),
    label: $('edit-label').value.trim(),
    alist_role_id: parseInt($('edit-role').value) || 0,
    active: parseInt($('edit-active').value)
  };
  try {
    const r = await api('/api/admin/users/' + encodeURIComponent(username), {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    const d = await r.json();
    if (d.success) {
      // 保存多盘符
      if (_editDrives.length > 0) {
        await api('/api/admin/users/' + encodeURIComponent(username) + '/drives', {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({drives: _editDrives})
        });
      }
      $('edit-user-modal').style.display = 'none';
      showMsg('用户 ' + username + ' 已更新 (已同步到AList)', true);
      loadUsers();
    } else {
      errEl.textContent = d.error || '更新失败';
      errEl.style.display = 'block';
    }
  } catch(e) {
    errEl.textContent = '网络错误: ' + e.message;
    errEl.style.display = 'block';
  }
}

async function addUser() {
  const username = $('nu').value.trim();
  const password = $('np').value;
  if (!username || !password) { showMsg('用户名和密码不能为空', false); return; }
  const r = await api('/api/admin/users', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username, password,
      alist_base_path: $('npath').value, alist_role_id: parseInt($('nrole').value)||0,
      drive_letter: $('ndrv').value})
  });
  const d = await r.json();
  if (d.success) {
    showMsg('用户添加成功' + (d.alist_id ? ' (已同步到AList, ID='+d.alist_id+')' : ''), true);
    $('nu').value=''; $('np').value=''; loadUsers();
  } else showMsg(d.error, false);
}

async function toggleUser(name, current) {
  await api('/api/admin/users/'+name, {
    method:'PUT', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({active: current?0:1})
  });
  showMsg((current?'已禁用':'已启用')+' '+name+' (已同步到AList)', true);
  loadUsers();
}

async function delUser(name) {
  if (!confirm('确认删除用户 "'+name+'" ?\n将同时从 AList 删除！')) return;
  await api('/api/admin/users/'+name, {method:'DELETE'});
  showMsg('已删除 ' + name + ' (已从AList删除)', true);
  loadUsers();
}

// --- 一键同步 (用户管理标签页内) ---
async function quickSync() {
  const btn = $('quick-sync-btn');
  const msg = $('quick-sync-msg');
  btn.disabled = true;
  btn.textContent = '同步中...';
  msg.style.display = 'block';
  msg.style.background = '#e8f0fe';
  msg.style.color = '#1a73e8';
  msg.textContent = '正在从 AList 拉取用户列表...';

  const r = await api('/api/admin/alist/sync', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({})
  });
  const d = await r.json();
  if (d.success) {
    msg.style.background = '#e6f7e6';
    msg.style.color = '#27ae60';
    msg.textContent = '同步完成! 新增 ' + d.created + ' 人, 更新 ' + d.updated + ' 人, 跳过 ' + d.skipped + ' 人' + (d.disabled ? ', 禁用 ' + d.disabled + ' 人' : '');
    showMsg('AList 用户同步完成: 新增' + d.created + ' 更新' + d.updated, true);
    loadUsers();
  } else {
    msg.style.background = '#fde8e8';
    msg.style.color = '#e74c3c';
    msg.textContent = '同步失败: ' + d.error;
  }
  btn.disabled = false;
  btn.textContent = '从 AList 一键同步';
}

// --- AList 同步 ---
async function loadAListConfig() {
  const r = await api('/api/admin/alist/config');
  const c = await r.json();
  $('alist-url').value = c.alist_url || '';
  $('alist-admin-user').value = c.alist_admin_user || '';
  if (c.alist_admin_set) $('alist-admin-pass').placeholder = '已配置 (留空保持不变)';
  $('alist-sync-login').checked = c.alist_sync_on_login;
  const st = $('alist-token-status');
  if (c.alist_token_valid) {
    const exp = new Date(c.alist_token_expire * 1000);
    st.innerHTML = '<span style="color:#16a34a">✓ 有效</span> 到期: ' + exp.toLocaleString();
  } else if (c.alist_token_set) {
    st.innerHTML = '<span style="color:#dc2626">✗ 已过期</span> 保存配置后将自动刷新';
  } else {
    st.textContent = '保存管理员凭据后将自动获取';
  }
  loadAListRoles();
}

async function loadAListRoles() {
  const select = $('nrole');
  select.innerHTML = '<option value="0">无角色</option>';
  try {
    const r = await api('/api/admin/alist/roles');
    const d = await r.json();
    if (d.roles && d.roles.length) {
      d.roles.forEach(role => {
        const opt = document.createElement('option');
        opt.value = role.id;
        opt.textContent = role.name + ' (ID=' + role.id + ')';
        select.appendChild(opt);
      });
    }
  } catch(e) {
    console.log('获取角色列表失败:', e);
  }
}

async function syncRoleBasePaths() {
  showMsg('正在同步角色 base_path...', true);
  const r = await api('/api/admin/alist/role-sync', {method:'POST'});
  const d = await r.json();
  if (d.success) {
    showMsg('同步完成: 修正 ' + d.fixed + ' 个用户的 base_path', true);
  } else {
    showMsg(d.error, false);
  }
}

async function testAList() {
  const token = $('alist-token').value.trim();
  const url = $('alist-url').value.trim();
  showMsg('正在测试 AList 连接...', true);
  const r = await api('/api/admin/alist/test', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({token, alist_url: url})
  });
  const d = await r.json();
  if (d.success) {
    showMsg(d.message, true);
    window._alistUsers = d.users || [];
    window._alistPage = 0;
    renderAlistPreview();
  } else showMsg(d.error, false);
}

function renderAlistPreview() {
  const users = window._alistUsers || [];
  const page = window._alistPage || 0;
  const size = 20;
  const total = users.length;
  const totalPages = Math.max(1, Math.ceil(total / size));
  const start = page * size;
  const slice = users.slice(start, start + size);
  $('alist-preview').innerHTML = slice.map(u =>
    `<tr><td>${u.id}</td><td><b>${esc(u.username)}</b></td>
     <td>${u.role_paths && u.role_paths.length ? u.role_paths.map(p=>'<span style="display:inline-block;background:#eef2ff;color:#4a5eb5;padding:1px 8px;border-radius:4px;margin:0 3px;font-size:13px">'+esc(p)+'</span>').join('') : (esc(u.base_path)||'/')}</td>
     <td>${esc((u.role||[]).join(','))}</td>
     <td><span class="badge ${u.disabled?'badge-off':'badge-on'}">${u.disabled?'禁用':'启用'}</span></td></tr>`
  ).join('') || '<tr><td colspan="5" style="color:#999;padding:10px">无用户</td></tr>';
  $('alist-preview-info').textContent = `共 ${total} 个用户，第 ${page+1}/${totalPages} 页`;
  let ph = '';
  if (totalPages > 1) {
    ph += `<button onclick="window._alistPage=Math.max(0,window._alistPage-1);renderAlistPreview()" style="padding:2px 10px;margin:0 4px;cursor:pointer" ${page===0?'disabled':''}>上一页</button>`;
    for (let i = 0; i < totalPages && i < 10; i++) {
      ph += `<button onclick="window._alistPage=${i};renderAlistPreview()" style="padding:2px 8px;margin:0 2px;cursor:pointer;${i===page?'background:#1a73e8;color:#fff':''}">${i+1}</button>`;
    }
    if (totalPages > 10) ph += `<span style="margin:0 4px">...</span>`;
    ph += `<button onclick="window._alistPage=Math.min(${totalPages-1},window._alistPage+1);renderAlistPreview()" style="padding:2px 10px;margin:0 4px;cursor:pointer" ${page>=totalPages-1?'disabled':''}>下一页</button>`;
  }
  $('alist-preview-pages').innerHTML = ph;
}

async function syncFromAList() {
  const token = $('alist-token').value.trim();
  showMsg('正在从 AList 同步用户...', true);
  const r = await api('/api/admin/alist/sync', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({token})
  });
  const d = await r.json();
  if (d.success) {
    $('sync-stats').innerHTML =
      `<span class="stat stat-ok">新增 ${d.created}</span>`+
      `<span class="stat stat-info">更新 ${d.updated}</span>`+
      `<span class="stat" style="background:#f0f0f0;color:#888">跳过 ${d.skipped}</span>`;
    const log = $('sync-log');
    log.style.display = 'block';
    log.textContent = (d.details||[]).join('\n');
    $('sync-placeholder').style.display = 'none';
    showMsg(`同步完成: 新增${d.created} 更新${d.updated}`, true);
    loadUsers();
  } else showMsg(d.error, false);
}

async function saveAListConfig() {
  const body = {
    alist_url: $('alist-url').value.trim(),
    alist_sync_on_login: $('alist-sync-login').checked,
    alist_admin_user: $('alist-admin-user').value.trim(),
  };
  const adminPass = $('alist-admin-pass').value.trim();
  if (adminPass) body.alist_admin_pass = adminPass;
  const token = $('alist-token').value.trim();
  if (token) body.alist_token = token;
  const r = await api('/api/admin/alist/config', {
    method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const d = await r.json();
  if (d.token_refreshed) {
    showMsg('配置已保存，Token 刷新成功', true);
  } else if (d.refresh_error) {
    showMsg('配置已保存，但 Token 刷新失败: ' + d.refresh_error, false);
  } else if (!$('alist-admin-user').value.trim() || !adminPass) {
    showMsg('配置已保存 (请填写管理员账号密码以自动刷新 Token)', false);
  } else {
    showMsg('配置已保存', true);
  }
  loadAListConfig();
}

// --- 硬件信息 ---
let _hwUsername = '';
async function showHardware(username) {
  _hwUsername = username;
  const modal = document.getElementById('hw-modal');
  const content = document.getElementById('hw-content');
  const copyBtn = document.getElementById('hw-copy-btn');
  copyBtn.style.display = 'none';
  content.innerHTML = '<p style="color:#888;text-align:center;padding:40px;font-size:15px">加载中...</p>';
  modal.style.display = 'flex';
  try {
    const r = await api('/api/admin/users/' + encodeURIComponent(username) + '/hardware');
    if (r.status === 404) {
      content.innerHTML = '<p style="color:#999;text-align:center;padding:40px;font-size:15px">该用户尚未上报硬件信息<br><small style="font-size:13px">用户登录后会自动上报</small></p>';
      return;
    }
    const d = await r.json();
    copyBtn.style.display = '';
    const updated = d.updated_at ? new Date(d.updated_at).toLocaleString() : '未知';
    let ramHtml = '';
    if (d.ram_details) {
      ramHtml = d.ram_details.split('\n').map(s => '<div style="padding-left:16px;color:#555">' + esc(s) + '</div>').join('');
    }
    let gpuHtml = '';
    if (d.gpu_info) {
      gpuHtml = d.gpu_info.split('\n').map(s => '<div style="padding-left:16px;color:#555">' + esc(s) + '</div>').join('');
    }
    let diskHtml = '';
    if (d.disk_info) {
      diskHtml = d.disk_info.split('\n').map(s => '<div style="padding-left:16px;color:#555">' + esc(s) + '</div>').join('');
    }
    let netHtml = '';
    if (d.network_info) {
      netHtml = d.network_info.split('\n').map(s => {
        let color = '#555';
        let html = esc(s);
        if (s.startsWith('[使用中]')) {
          html = '<span style="color:#27ae60;font-weight:bold">[使用中]</span>' + esc(s.substring(5));
        } else if (s.startsWith('[闲置]')) {
          html = '<span style="color:#e67e22;font-weight:bold">[闲置]</span>' + esc(s.substring(4));
        }
        return '<div style="padding-left:16px;color:#555">' + html + '</div>';
      }).join('');
    }
    let monHtml = '';
    if (d.monitor_info) {
      monHtml = d.monitor_info.split('\n').map(s => '<div style="padding-left:16px;color:#555">' + esc(s) + '</div>').join('');
    }
    content.innerHTML = `
      <div style="text-align:center;margin-bottom:20px">
        <h3 style="margin:0;color:#1a73e8;font-size:20px">${esc(username)}</h3>
        <small style="color:#999;font-size:13px">更新于 ${updated}</small>
      </div>
      <div class="hw-section">
        <div class="hw-title">系统信息</div>
        <div class="hw-row"><span class="hw-label">主机名</span><span>${esc(d.hostname)}</span></div>
        <div class="hw-row"><span class="hw-label">操作系统</span><span>${esc(d.os_info)}</span></div>
        <div class="hw-row"><span class="hw-label">SN码</span><span>${esc(d.bios_sn)}</span></div>
        <div class="hw-row"><span class="hw-label">BIOS</span><span>${esc(d.bios_vendor)}</span></div>
      </div>
      <div class="hw-section">
        <div class="hw-title">处理器</div>
        <div class="hw-row"><span class="hw-label">CPU</span><span>${esc(d.cpu_model)}</span></div>
        <div class="hw-row"><span class="hw-label">核心/线程</span><span>${d.cpu_cores}核 ${d.cpu_threads}线程</span></div>
        <div class="hw-row"><span class="hw-label">频率</span><span>${esc(d.cpu_speed)}</span></div>
        ${d.cpu_cache ? `<div class="hw-row"><span class="hw-label">缓存</span><span>${esc(d.cpu_cache)}</span></div>` : ''}
      </div>
      <div class="hw-section">
        <div class="hw-title">内存 (${d.ram_total_gb}GB)</div>
        ${ramHtml || '<div style="color:#999;padding-left:16px">无详细信息</div>'}
      </div>
      <div class="hw-section">
        <div class="hw-title">显卡</div>
        ${gpuHtml || '<div style="color:#999;padding-left:16px">无详细信息</div>'}
      </div>
      <div class="hw-section">
        <div class="hw-title">硬盘</div>
        ${diskHtml || '<div style="color:#999;padding-left:16px">无详细信息</div>'}
      </div>
      <div class="hw-section">
        <div class="hw-title">网卡</div>
        ${netHtml || '<div style="color:#999;padding-left:16px">无详细信息</div>'}
      </div>
      <div class="hw-section">
        <div class="hw-title">显示器</div>
        ${monHtml || '<div style="color:#999;padding-left:16px">无详细信息</div>'}
      </div>
    `;
  } catch (e) {
    content.innerHTML = '<p style="color:red;text-align:center;padding:40px;font-size:15px">获取失败: ' + esc(e.message) + '</p>';
  }
}
function closeHardware() {
  document.getElementById('hw-modal').style.display = 'none';
}
function copyHardwareInfo() {
  const content = document.getElementById('hw-content');
  const text = content.innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById('hw-copy-btn');
    btn.textContent = '已复制';
    btn.style.background = '#e6f7e6';
    btn.style.color = '#27ae60';
    btn.style.borderColor = '#27ae60';
    setTimeout(() => {
      btn.textContent = '复制到剪贴板';
      btn.style.background = '#e8f0fe';
      btn.style.color = '#1a73e8';
      btn.style.borderColor = '#1a73e8';
    }, 2000);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    const btn = document.getElementById('hw-copy-btn');
    btn.textContent = '已复制';
    setTimeout(() => { btn.textContent = '复制到剪贴板'; }, 2000);
  });
}

// 自动刷新用户列表（更新在线状态）
setInterval(() => {
  if (document.getElementById('main-wrap').style.display !== 'none') {
    loadUsers();
  }
}, 30000);

// --- 远程磁盘操作 ---
async function sendCommand(username, cmdType) {
  const label = cmdType === 'hide_disks' ? '脱机' : '联机';
  if (!confirm(`确定要对用户 ${username} 执行【${label}】操作吗？\n\n客户端每60秒自动同步一次指令，将在下一轮同步时执行。`)) return;
  try {
    const r = await api('/api/admin/users/' + encodeURIComponent(username) + '/command', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({command_type: cmdType})
    });
    const d = await r.json();
    if (d.success) {
      showMsg(`命令已下发: ${label}，客户端将在60秒内自动同步执行`, true);
    } else {
      showMsg('命令下发失败: ' + (d.error || '未知错误'), false);
    }
  } catch(e) {
    showMsg('命令下发失败: ' + e.message, false);
  }
}

async function showCommands(username) {
  const modal = document.getElementById('cmd-modal');
  const content = document.getElementById('cmd-content');
  content.innerHTML = '<p style="color:#888;text-align:center;padding:40px;font-size:15px">加载中...</p>';
  modal.style.display = 'flex';
  try {
    const r = await api('/api/admin/users/' + encodeURIComponent(username) + '/commands?limit=10');
    if (r.status === 404) {
      content.innerHTML = '<p style="color:#999;text-align:center;padding:40px;font-size:15px">暂无命令记录</p>';
      return;
    }
    const cmds = await r.json();
    if (!cmds.length) {
      content.innerHTML = '<p style="color:#999;text-align:center;padding:40px;font-size:15px">暂无命令记录</p>';
      return;
    }
    const typeMap = {hide_disks: '脱机', restore_disks: '联机'};
    const statusMap = {pending: '待执行', executing: '执行中', done: '成功', failed: '失败'};
    const statusColor = {pending: '#e67e22', executing: '#3498db', done: '#27ae60', failed: '#e74c3c'};
    content.innerHTML = `
      <div style="text-align:center;margin-bottom:20px">
        <h3 style="margin:0;color:#1a73e8;font-size:20px">${esc(username)} - 执行日志</h3>
      </div>
      <table style="width:100%;font-size:14px">
        <thead><tr><th style="padding:12px 14px">ID</th><th style="padding:12px 14px">执行日志</th><th style="padding:12px 14px">状态</th><th style="padding:12px 14px">下发时间</th><th style="padding:12px 14px">执行时间</th></tr></thead>
        <tbody>
          ${cmds.map(c => `<tr>
            <td style="padding:12px 14px">${c.id}</td>
            <td style="padding:12px 14px">${typeMap[c.command_type] || c.command_type}</td>
            <td style="padding:12px 14px"><span style="color:${statusColor[c.status]||'#888'};font-weight:500">${statusMap[c.status]||c.status}</span></td>
            <td style="padding:12px 14px;font-size:13px">${esc((c.created_at||'-').replace('T',' ').split('.')[0])}</td>
            <td style="padding:12px 14px;font-size:13px">${esc((c.executed_at||'-').replace('T',' ').split('.')[0])}</td>
          </tr>
          ${c.result ? `<tr><td colspan="5" style="padding:8px 16px;font-size:13px;color:#555;white-space:pre-wrap;background:#f9f9f9">${esc(c.result)}</td></tr>` : ''}`).join('')}
        </tbody>
      </table>
    `;
  } catch(e) {
    content.innerHTML = '<p style="color:red;text-align:center;padding:40px;font-size:15px">获取失败: ' + esc(e.message) + '</p>';
  }
}
function closeCommands() {
  document.getElementById('cmd-modal').style.display = 'none';
}

const FILELOG_PAGE_SIZE = 50;
let showFileLogsUser = '';
let showFileLogsFilter = '';
let showFileLogsOffset = 0;
let showFileLogsTotal = 0;

async function showFileLogs(username) {
  const modal = document.getElementById('filelog-modal');
  const content = document.getElementById('filelog-content');
  content.innerHTML = '<p style="color:#888;text-align:center;padding:40px;font-size:15px">加载中...</p>';
  modal.style.display = 'flex';
  showFileLogsUser = username;
  showFileLogsFilter = '';
  showFileLogsOffset = 0;
  await loadFileLogs(content, username, '', 0);
}

async function loadFileLogs(content, username, filter, offset) {
  try {
    let url = '/api/admin/users/' + encodeURIComponent(username) + '/file-logs?limit=' + FILELOG_PAGE_SIZE + '&offset=' + offset;
    if (filter) url += '&event_type=' + encodeURIComponent(filter);
    const r = await api(url);
    const d = await r.json();
    showFileLogsTotal = d.total || 0;
    const currentPage = Math.floor(offset / FILELOG_PAGE_SIZE) + 1;
    const totalPages = Math.max(1, Math.ceil(showFileLogsTotal / FILELOG_PAGE_SIZE));

    if (!d.logs || d.logs.length === 0) {
      const filters = ['','新建','修改','删除','重命名','移动出','打开','复制'];
      const filterBtns = filters.map(f => `<button onclick="filterFileLogs('${f}')" style="padding:4px 12px;border:1px solid ${f===showFileLogsFilter?'#1a73e8':'#ddd'};border-radius:14px;background:${f===showFileLogsFilter?'#1a73e8':'#fff'};color:${f===showFileLogsFilter?'#fff':'#666'};cursor:pointer;font-size:12px;margin:2px">${f||'全部'}</button>`).join('');
      content.innerHTML = `
        <div style="text-align:center;margin-bottom:12px">
          <h3 style="margin:0;color:#1a73e8;font-size:20px">${esc(username)} - 文件操作日志</h3>
        </div>
        <div style="margin-bottom:10px;text-align:center">${filterBtns}</div>
        <div style="text-align:center;padding:40px 20px">
          <div style="font-size:48px;margin-bottom:12px;opacity:0.3">📋</div>
          <p style="color:#999;font-size:15px;margin:0">暂无文件操作记录</p>
          <small style="color:#bbb;font-size:13px">用户登录并操作Z盘文件后会自动记录</small>
        </div>
      `;
      return;
    }
    const typeColor = {'新建':'#27ae60','修改':'#e67e22','删除':'#e74c3c','重命名':'#9b59b6','移动出':'#e74c3c','打开':'#3498db','复制':'#f39c12'};
    const typeBg = {'新建':'#e8f8e8','修改':'#fef0e0','删除':'#fde8e8','重命名':'#f0e8f8','移动出':'#fde8e8','打开':'#e8f0fc','复制':'#fef5e0'};
    const typeIcon = {'新建':'+','修改':'✎','删除':'✕','重命名':'⇄','移动出':'↗','打开':'👁','复制':'📋'};
    const filters = ['','新建','修改','删除','重命名','移动出','打开','复制'];
    const filterBtns = filters.map(f => `<button onclick="filterFileLogs('${f}')" style="padding:4px 12px;border:1px solid ${f===showFileLogsFilter?'#1a73e8':'#ddd'};border-radius:14px;background:${f===showFileLogsFilter?'#1a73e8':'#fff'};color:${f===showFileLogsFilter?'#fff':'#666'};cursor:pointer;font-size:12px;margin:2px">${f||'全部'}</button>`).join('');

    const stats = {};
    d.logs.forEach(l => { stats[l.event_type] = (stats[l.event_type]||0)+1; });
    const statHtml = Object.entries(stats).map(([t,c]) => `<span style="display:inline-block;margin:0 6px 6px 0;padding:3px 10px;border-radius:10px;background:${typeBg[t]};color:${typeColor[t]};font-size:12px;font-weight:500">${typeIcon[t]} ${t} ${c}</span>`).join('');

    function fmtSize(b) {
      if (!b || b <= 0) return '-';
      if (b < 1024) return b + ' B';
      if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
      if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
      return (b/1073741824).toFixed(2) + ' GB';
    }
    function fmtTime(s) {
      if (!s) return '-';
      const parts = s.split('T');
      if (parts.length >= 2) {
        const datePart = parts[0];
        const timePart = parts[1].split('.')[0].substring(0,8);
        return datePart + ' ' + timePart;
      }
      return s.substring(0,19).replace('T', ' ');
    }
    function getFileIcon(path) {
      const p = path.toLowerCase();
      if (p.endsWith('.lnk') || p.endsWith('.exe') || p.endsWith('.msi')) return '📦';
      if (/\.(jpg|jpeg|png|gif|bmp|webp|svg|ico)$/.test(p)) return '🖼';
      if (/\.(mp4|avi|mkv|mov|wmv|flv)$/.test(p)) return '🎬';
      if (/\.(mp3|wav|flac|aac|ogg|wma)$/.test(p)) return '🎵';
      if (/\.(doc|docx|txt|pdf|xls|xlsx|ppt|pptx|csv|md)$/.test(p)) return '📄';
      if (/\.(zip|rar|7z|tar|gz|bz2)$/.test(p)) return '📦';
      if (/\.(py|js|ts|java|c|cpp|h|go|rs|php|html|css|sql|json|xml|yaml|yml)$/.test(p)) return '💻';
      return '📎';
    }

    let tableHtml = '';
    d.logs.forEach(l => {
      const icon = l.is_dir ? '📁' : getFileIcon(l.path);
      const size = fmtSize(l.file_size);
      const time = fmtTime(l.created_at);
      const label = esc(l.event_type);
      const tagHtml = `<span style="display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;background:${typeBg[l.event_type]||'#f5f5f5'};color:${typeColor[l.event_type]||'#888'};font-size:11px;font-weight:500;white-space:nowrap">${esc(typeIcon[l.event_type]||'●')} ${label}</span>`;
      tableHtml += `<tr style="border-bottom:1px solid #f5f5f5">
        <td style="padding:8px 10px;width:70px">${tagHtml}</td>
        <td style="padding:8px 10px;word-break:break-all;font-size:13px"><span style="margin-right:4px;font-size:14px">${icon}</span>${esc(l.path)}${l.dest_path ? '<span style="color:#3498db;margin:0 4px">→</span>' + esc(l.dest_path) : ''}</td>
        <td style="padding:8px 10px;white-space:nowrap;font-size:11px;color:#888;width:80px">${size}</td>
        <td style="padding:8px 10px;white-space:nowrap;font-size:11px;color:#1a73e8;font-weight:500;width:50px;text-align:center">${esc(l.drive_letter||'')}</td>
        <td style="padding:8px 10px;white-space:nowrap;font-size:11px;color:#666;width:140px">${time}</td>
      </tr>`;
    });

    const paginationHtml = `<div class="pagination">
      <button onclick="fileLogPrev()" ${offset===0?'disabled':''}>上一页</button>
      <span>第 ${currentPage} / ${totalPages} 页 (共 ${showFileLogsTotal} 条)</span>
      <button onclick="fileLogNext()" ${offset+FILELOG_PAGE_SIZE>=showFileLogsTotal?'disabled':''}>下一页</button>
    </div>`;

    content.innerHTML = `
      <div style="text-align:center;margin-bottom:12px">
        <h3 style="margin:0;color:#1a73e8;font-size:20px">${esc(username)} - 文件操作日志</h3>
        <small style="color:#999">总计 ${d.total} 条，第 ${currentPage}/${totalPages} 页</small>
        <button onclick="clearFileLogs('${esc(username)}')" style="margin-left:12px;padding:2px 10px;font-size:12px;background:#e74c3c;color:#fff;border:none;border-radius:4px;cursor:pointer">清空日志</button>
      </div>
      <div style="margin-bottom:10px;text-align:center;flex-wrap:wrap">${statHtml}</div>
      <div style="margin-bottom:10px;text-align:center">${filterBtns}</div>
      <table style="width:100%;font-size:13px;border-collapse:collapse">
        <thead><tr style="border-bottom:2px solid #eee">
          <th style="padding:6px 10px;text-align:left;width:70px">类型</th>
          <th style="padding:6px 10px;text-align:left">路径</th>
          <th style="padding:6px 10px;text-align:left;width:80px">大小</th>
          <th style="padding:6px 10px;text-align:center;width:50px">盘符</th>
          <th style="padding:6px 10px;text-align:left;width:140px">时间</th>
        </tr></thead>
        <tbody>${tableHtml}</tbody>
      </table>
      ${paginationHtml}
    `;
  } catch(e) {
    content.innerHTML = '<p style="color:red;text-align:center;padding:40px;font-size:15px">获取失败: ' + esc(e.message) + '</p>';
  }
}

function filterFileLogs(filter) {
  showFileLogsFilter = filter;
  showFileLogsOffset = 0;
  const content = document.getElementById('filelog-content');
  loadFileLogs(content, showFileLogsUser, filter, 0);
}

function fileLogPrev() {
  if (showFileLogsOffset >= FILELOG_PAGE_SIZE) {
    showFileLogsOffset -= FILELOG_PAGE_SIZE;
    const content = document.getElementById('filelog-content');
    loadFileLogs(content, showFileLogsUser, showFileLogsFilter, showFileLogsOffset);
  }
}

function fileLogNext() {
  if (showFileLogsOffset + FILELOG_PAGE_SIZE < showFileLogsTotal) {
    showFileLogsOffset += FILELOG_PAGE_SIZE;
    const content = document.getElementById('filelog-content');
    loadFileLogs(content, showFileLogsUser, showFileLogsFilter, showFileLogsOffset);
  }
}

function closeFileLogs() {
  document.getElementById('filelog-modal').style.display = 'none';
}

async function clearFileLogs(username) {
  if (!confirm('确定要清空 ' + username + ' 的所有文件操作日志吗？此操作不可恢复！')) return;
  try {
    const r = await api('/api/admin/users/' + encodeURIComponent(username) + '/file-logs', {method: 'DELETE'});
    const d = await r.json();
    if (d.success) {
      showFileLogsOffset = 0;
      const content = document.getElementById('filelog-content');
      loadFileLogs(content, username, showFileLogsFilter, 0);
    } else {
      alert('清空失败: ' + (d.message || '未知错误'));
    }
  } catch(e) {
    alert('清空失败: ' + e.message);
  }
}

// 初始化由登录成功后触发

// === 审计日志 ===
let _auditPage = 0;
const _auditLimit = 20;
async function loadAuditLogs() {
  _auditPage = 0;
  await _fetchAuditLogs();
}
async function _fetchAuditLogs() {
  const user = $('audit-user').value.trim();
  const offset = _auditPage * _auditLimit;
  let url = `/api/admin/audit-logs?limit=${_auditLimit}&offset=${offset}`;
  if (user) url += `&username=${encodeURIComponent(user)}`;
  const r = await api(url);
  const d = await r.json();
  if (d.logs) {
    $('audit-tb').innerHTML = d.logs.map(l => `<tr>
      <td style="white-space:nowrap;font-size:14px">${formatLoginTime(l.created_at)}</td>
      <td style="font-size:15px">${esc(l.username)}</td>
      <td><span class="badge badge-alist">${esc(l.action)}</span></td>
      <td style="font-size:14px;color:#666;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l.detail)}</td>
      <td style="font-size:14px;color:#999">${esc(l.ip)}</td>
    </tr>`).join('') || '<tr><td colspan="5" style="color:#999;padding:20px">无记录</td></tr>';
    $('audit-page-info').textContent = `第 ${_auditPage+1} 页`;
  }
}
function auditPage(delta) {
  _auditPage = Math.max(0, _auditPage + delta);
  _fetchAuditLogs();
}
async function clearAuditLogs() {
  if (!confirm('确定要清空所有登录日志吗？此操作不可恢复！')) return;
  const r = await api('/api/admin/audit-logs', {method: 'DELETE'});
  const d = await r.json();
  if (d.success) { showMsg('日志已清空', true); loadAuditLogs(); }
  else { showMsg('清空失败', false); }
}

// === 通知推送 ===
async function sendNotification() {
  const username = $('notify-user').value.trim();
  const title = $('notify-title').value.trim();
  const content = $('notify-content').value.trim();
  const duration = parseInt($('notify-duration').value) || 5;
  if (!title) { showMsg('标题不能为空', false); return; }
  const body = {title, content, duration};
  if (username) body.username = username;
  const r = await api('/api/admin/notifications', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)
  });
  const d = await r.json();
  if (d.success) { showMsg('通知已发送', true); $('notify-title').value=''; $('notify-content').value=''; loadNotifyHistory(); }
  else showMsg(d.error || '发送失败', false);
}
async function loadNotifyHistory() {
  const r = await api('/api/admin/notifications?limit=500');
  const d = await r.json();
  renderNotifyTable(d.notifications || []);
}
async function searchNotifyHistory() {
  const title = $('notify-search').value.trim();
  let url = '/api/admin/notifications?limit=500';
  if (title) url += '&title=' + encodeURIComponent(title);
  const r = await api(url);
  const d = await r.json();
  renderNotifyTable(d.notifications || []);
}
let _notifyPage = 0;
const _notifyPageSize = 20;
let _filteredNotifies = [];

function renderNotifyTable(notifications) {
  _filteredNotifies = notifications;
  _notifyPage = 0;
  _renderNotifyPage();
}

function _renderNotifyPage() {
  const all = _filteredNotifies;
  const page = _notifyPage;
  const size = _notifyPageSize;
  const total = all.length;
  const totalPages = Math.max(1, Math.ceil(total / size));
  const start = page * size;
  const slice = all.slice(start, start + size);
  $('notify-tb').innerHTML = slice.map(n => `<tr>
      <td>${n.id}</td><td>${esc(n.username||'全员')}</td>
      <td style="font-size:15px">${esc(n.title)}</td>
      <td style="font-size:14px;color:#666;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(n.content)}</td>
      <td>${n.is_read?'<span class="badge badge-on">已读</span>':'<span class="badge badge-off">未读</span>'}</td>
      <td style="font-size:14px;color:#999;white-space:nowrap">${formatLoginTime(n.created_at)}</td>
    </tr>`).join('') || '<tr><td colspan="6" style="color:#999;padding:20px">无记录</td></tr>';
  let ph = '';
  if (totalPages > 1) {
    ph += `<button onclick="_notifyPage=Math.max(0,_notifyPage-1);_renderNotifyPage()" style="padding:2px 10px;margin:0 4px;cursor:pointer" ${_notifyPage===0?'disabled':''}>上一页</button>`;
    for (let i = 0; i < totalPages && i < 10; i++) {
      ph += `<button onclick="_notifyPage=${i};_renderNotifyPage()" style="padding:2px 8px;margin:0 2px;cursor:pointer;${i===_notifyPage?'background:#1a73e8;color:#fff':''}">${i+1}</button>`;
    }
    if (totalPages > 10) ph += `<span style="margin:0 4px">...</span>`;
    ph += `<button onclick="_notifyPage=Math.min(${totalPages-1},_notifyPage+1);_renderNotifyPage()" style="padding:2px 10px;margin:0 4px;cursor:pointer" ${_notifyPage>=totalPages-1?'disabled':''}>下一页</button>`;
  }
  $('notify-pages').innerHTML = ph;
}
async function clearNotifyHistory() {
  if (!confirm('确定要清空所有通知吗？此操作不可恢复！')) return;
  const r = await api('/api/admin/notifications', {method: 'DELETE'});
  const d = await r.json();
  if (d.success) { showMsg('通知已清空', true); loadNotifyHistory(); }
  else showMsg('清空失败', false);
}

// === 批量导入 ===
async function batchImport() {
  const text = $('batch-users').value.trim();
  if (!text) { showMsg('请输入用户数据', false); return; }
  const users = text.split('\n').filter(l=>l.trim()).map(l => {
    const parts = l.split(',').map(s=>s.trim());
    return {username:parts[0]||'', password:parts[1]||'', alist_base_path:parts[2]||'/公司文件', drive_letter:parts[3]||'Z:'};
  }).filter(u=>u.username&&u.password);
  if (!users.length) { showMsg('无有效数据', false); return; }
  const r = await api('/api/admin/users/batch-import', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({users})
  });
  const d = await r.json();
  $('batch-result').textContent = d.message || JSON.stringify(d);
  $('batch-result').style.color = d.success ? '#27ae60' : '#e74c3c';
  if (d.success) loadUsers();
}

// === 配额管理 ===
async function setUserQuota() {
  const username = $('quota-user').value.trim();
  const quota_mb = parseInt($('quota-mb').value) || 0;
  if (!username) { showMsg('请输入用户名', false); return; }
  const r = await api('/api/admin/quota/' + encodeURIComponent(username), {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({quota_mb})
  });
  const d = await r.json();
  showMsg(d.success ? '配额已设置' : (d.error||'设置失败'), d.success);
}
async function getUserQuota() {
  const username = $('quota-user').value.trim();
  if (!username) { showMsg('请输入用户名', false); return; }
  const r = await api('/api/admin/quota/' + encodeURIComponent(username));
  const d = await r.json();
  if (d.quota_mb !== undefined) {
    $('quota-info').textContent = `配额: ${d.quota_mb||'不限'} MB | 已用: ${Math.round(d.used_mb||0)} MB`;
  } else {
    $('quota-info').textContent = d.error || '查询失败';
  }
}

// === 回收站 ===
async function loadRecycleBin() {
  const username = $('recycle-user').value.trim();
  if (!username) { showMsg('请输入用户名', false); return; }
  const r = await api('/api/admin/alist-recycle/' + encodeURIComponent(username));
  const d = await r.json();
  if (d.files) {
    $('recycle-tb').innerHTML = d.files.map(f => `<tr>
      <td style="font-size:14px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.original_path || '-')}</td>
      <td style="font-size:15px">${esc(f.name)}</td>
      <td style="font-size:14px;color:#e74c3c">${esc(f.owner || username)}</td>
      <td style="font-size:14px;color:#e74c3c;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.remark || '')}">${esc(f.remark || '-')}<button onclick="editRecycleRemark('${esc(username)}','${esc(f.name)}','${esc(f.remark || '')}')" style="margin-left:4px;font-size:11px;color:#1a73e8;background:none;border:none;cursor:pointer;padding:0">编辑</button></td>
      <td style="font-size:14px">${f.size>1048576?(f.size/1048576).toFixed(1)+'MB':f.size>1024?(f.size/1024).toFixed(1)+'KB':f.size+'B'}</td>
      <td style="font-size:14px;color:#999;white-space:nowrap">${formatLoginTime(f.modified)}</td>
      <td style="white-space:nowrap">
        <button class="action-btn btn-primary" onclick="restoreAlistFile('${esc(username)}','${esc(f.name)}','${esc(f.original_path || '')}')" style="margin-right:4px">还原</button>
        <button class="action-btn btn-danger" onclick="deleteAlistFile('${esc(username)}','${esc(f.name)}')">永久删除</button>
      </td>
    </tr>`).join('') || '<tr><td colspan="7" style="color:#999;padding:20px">回收站为空</td></tr>';
  }
  const ar = await api('/api/admin/recycle-auto-cleanup/' + encodeURIComponent(username));
  const ad = await ar.json();
  if (ad.days !== undefined) $('recycle-auto-days').value = ad.days;
}
async function clearRecycleBin() {
  const username = $('recycle-user').value.trim();
  if (!username) { showMsg('请输入用户名', false); return; }
  const remark = prompt('清空备注说明（可选）:');
  if (remark === null) return;
  if (!confirm('确认清空用户 "'+username+'" 的AList回收站？此操作不可恢复！')) return;
  const r = await api('/api/admin/alist-recycle/' + encodeURIComponent(username) + '/clear', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({remark: remark})
  });
  const d = await r.json();
  showMsg(d.success ? '回收站已清空（'+(d.count||0)+'个文件）' : (d.error||'操作失败'), d.success);
  loadRecycleBin();
}
async function restoreAlistFile(username, fileName, originalPath) {
  const targetDir = prompt('还原到AList目录:', originalPath ? originalPath.substring(0, originalPath.lastIndexOf('/') + 1) : '');
  if (targetDir === null) return;
  if (!targetDir) { showMsg('请输入还原目录', false); return; }
  const r = await api('/api/admin/alist-recycle/' + encodeURIComponent(username) + '/restore', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({file_name: fileName, target_dir: targetDir})
  });
  const d = await r.json();
  showMsg(d.success ? '还原成功' : (d.error||'还原失败'), d.success);
  if (d.success) loadRecycleBin();
}
async function deleteAlistFile(username, fileName) {
  const remark = prompt('永久删除 "'+fileName+'"\n请输入备注说明（可选）:');
  if (remark === null) return;
  if (!confirm('确认永久删除 "'+fileName+'"？此操作不可恢复！')) return;
  const r = await api('/api/admin/alist-recycle/' + encodeURIComponent(username) + '/delete', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({file_name: fileName, remark: remark})
  });
  const d = await r.json();
  showMsg(d.success ? '已永久删除' : (d.error||'删除失败'), d.success);
  if (d.success) loadRecycleBin();
}
async function editRecycleRemark(username, fileName, currentRemark) {
  const remark = prompt('编辑备注说明:', currentRemark);
  if (remark === null) return;
  const r = await api('/api/admin/alist-recycle/' + encodeURIComponent(username) + '/remark', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({file_name: fileName, remark: remark})
  });
  const d = await r.json();
  if (d.success) loadRecycleBin();
}
async function setRecycleAutoCleanup() {
  const username = $('recycle-user').value.trim();
  if (!username) { showMsg('请输入用户名', false); return; }
  const days = $('recycle-auto-days').value;
  const r = await api('/api/admin/recycle-auto-cleanup/' + encodeURIComponent(username), {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({days: parseInt(days) || 0})
  });
  const d = await r.json();
  showMsg(d.success ? '自动清理已设置: ' + (d.days||0) + '天' : '设置失败', d.success);
}
async function showRecycleDeleteLogs() {
  const username = $('recycle-user').value.trim();
  if (!username) { showMsg('请输入用户名', false); return; }
  const r = await api('/api/admin/alist-recycle-delete-logs/' + encodeURIComponent(username));
  const d = await r.json();
  if (!d.logs || !d.logs.length) { showMsg('无删除日志', true); return; }
  let html = '<h3 style="margin:0 0 16px">回收站删除日志 - '+esc(username)+'</h3><table style="width:100%;border-collapse:collapse;font-size:14px"><thead><tr style="background:#f5f5f5"><th style="padding:8px;text-align:left">文件名</th><th style="padding:8px;text-align:left">原路径</th><th style="padding:8px">大小</th><th style="padding:8px">删除者</th><th style="padding:8px">备注</th><th style="padding:8px">删除时间</th><th style="padding:8px">永久删除时间</th></tr></thead><tbody>';
  d.logs.forEach(l => {
    html += '<tr style="border-bottom:1px solid #eee"><td style="padding:6px 8px">'+esc(l.file_name)+'</td><td style="padding:6px 8px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(l.original_path||'-')+'</td><td style="padding:6px 8px;text-align:center">'+(l.file_size>1048576?(l.file_size/1048576).toFixed(1)+'MB':l.file_size>1024?(l.file_size/1024).toFixed(1)+'KB':l.file_size+'B')+'</td><td style="padding:6px 8px;text-align:center">'+esc(l.deleted_by||'-')+'</td><td style="padding:6px 8px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(l.remark||'-')+'</td><td style="padding:6px 8px;white-space:nowrap">'+formatLoginTime(l.deleted_at)+'</td><td style="padding:6px 8px;white-space:nowrap">'+formatLoginTime(l.permanent_deleted_at)+'</td></tr>';
  });
  html += '</tbody></table>';
  const modal = document.createElement('div');
  modal.style.cssText = 'display:flex;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.45);z-index:1000;justify-content:center;align-items:center';
  modal.onclick = e => { if(e.target===modal) modal.remove(); };
  const box = document.createElement('div');
  box.style.cssText = 'background:#fff;border-radius:14px;padding:28px;max-width:900px;width:90%;max-height:80vh;overflow-y:auto;position:relative;box-shadow:0 12px 40px rgba(0,0,0,.2)';
  box.innerHTML = '<button onclick="this.closest(\'div[style]\').parentElement.remove()" style="position:absolute;top:14px;right:18px;background:#f0f0f0;border:none;font-size:22px;cursor:pointer;color:#666;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center">&times;</button>' + html;
  modal.appendChild(box);
  document.body.appendChild(modal);
}
</script>
</body>
</html>
"""


@app.route("/")
def web_admin():
    return render_template_string(ADMIN_HTML)


# ============================================================
# Main / CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="MorongDisk Auth Server v1.16.0")
    parser.add_argument("--port", type=int, default=CONFIG.get("port", 9800))
    parser.add_argument("--host", default=CONFIG.get("host", "0.0.0.0"))
    parser.add_argument("--add-user", nargs=2, metavar=("USER", "PASS"), help="添加用户")
    parser.add_argument("--del-user", metavar="USER", help="删除用户")
    parser.add_argument("--list-users", action="store_true", help="列出所有用户")
    parser.add_argument("--set-password", nargs=2, metavar=("USER", "PASS"), help="修改密码")
    parser.add_argument("--sync-alist", action="store_true", help="从 AList 同步用户")
    parser.add_argument("--alist-token", metavar="TOKEN", help="指定 AList Token")
    args = parser.parse_args()

    init_db()

    if args.add_user:
        ok = create_user(args.add_user[0], args.add_user[1])
        if ok and CONFIG.get("alist_token"):
            push_to_alist(args.add_user[0], args.add_user[1])
        print(f"  {'OK' if ok else 'FAIL'}: 用户 '{args.add_user[0]}'")
        return
    if args.del_user:
        u = get_user(args.del_user)
        if u and u.get("alist_id"):
            alist_delete_user(u["alist_id"])
        delete_user_db(args.del_user)
        print(f"  OK: 已删除用户 '{args.del_user}'")
        return
    if args.set_password:
        update_user(args.set_password[0], password_hash=hash_password(args.set_password[1]))
        u = get_user(args.set_password[0])
        if u and u.get("alist_id") and CONFIG.get("alist_token"):
            alist_update_user(u["alist_id"], args.set_password[0], password=args.set_password[1])
        print(f"  OK: 已更新用户 '{args.set_password[0]}' 的密码")
        return
    if args.list_users:
        for u in list_users():
            st = "启用" if u["active"] else "禁用"
            aid = f"alist_id={u['alist_id']}" if u.get("alist_id") else "无AList"
            print(f"  [{st}] {u['username']:15s}  {aid:15s}  path={u.get('alist_base_path','')}  最后登录={u['last_login'] or '-'}")
        return
    if args.sync_alist:
        token = args.alist_token or CONFIG.get("alist_token", "")
        if not token:
            print("  [!] 请先配置 AList Token: AuthServer.exe --sync-alist --alist-token TOKEN")
            return
        print("  [*] 正在从 AList 同步用户...")
        results, err = sync_from_alist(token=token)
        if err:
            print(f"  [!] 同步失败: {err}")
            return
        print(f"  [OK] 新增: {results['created']}  更新: {results['updated']}  跳过: {results['skipped']}")
        for d in results.get("details", []):
            print(f"       {d}")
        return

    alist_status = "已配置" if CONFIG.get("alist_token") else "未配置"
    admin_set = bool(CONFIG.get("alist_admin_user") and CONFIG.get("alist_admin_pass"))
    auto_refresh = "已启用 (管理员凭据已配置)" if admin_set else "未配置管理员凭据"

    print(f"""
  ╔══════════════════════════════════════╗
  ║   MorongDisk Auth Server v1.16.0       ║
  ║   AList 双向同步已启用              ║
  ╚══════════════════════════════════════╝

  监听地址 : http://{args.host}:{args.port}
  管理面板 : http://{args.host}:{args.port}/
  WebDAV   : {CONFIG['default_webdav_url']}
  AList    : {CONFIG.get('alist_url', '未配置')}  (Token: {alist_status})
  自动刷新 : {auto_refresh}
  数据库   : {DB_PATH}

  双向同步: 添加/修改/删除用户自动同步到 AList
  代理验证: 登录时本地密码不匹配自动尝试 AList 认证

  命令行:
    AuthServer.exe --add-user user pass
    AuthServer.exe --del-user user
    AuthServer.exe --set-password user newpass
    AuthServer.exe --list-users
    AuthServer.exe --sync-alist --alist-token TOKEN
""")
    # 启动 AList token 自动刷新
    alist_auto_init()
    # 启动回收站自动清理线程
    t_cleanup = threading.Thread(target=_recycle_auto_cleanup_loop, daemon=True, name="recycle-auto-cleanup")
    t_cleanup.start()
    logging.info("[回收站自动清理] 后台线程已启动 (每小时检查一次)")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


# ============================================================
# New Feature APIs
# ============================================================

# --- 审计日志 ---
def _audit(username, action, detail="", ip=""):
    try:
        conn = get_db()
        try:
            conn.execute("INSERT INTO audit_logs (username, action, detail, ip, created_at) VALUES (?,?,?,?,?)",
                          (username, action, detail, ip, datetime.now().isoformat()))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass

@app.route("/api/admin/audit-logs", methods=["GET"])
@require_admin
def admin_audit_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    username = request.args.get("username", "").strip()
    action = request.args.get("action", "").strip()
    conn = get_db()
    try:
        where, params = [], []
        if username:
            where.append("username=?")
            params.append(username)
        if action:
            where.append("action=?")
            params.append(action)
        where_clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows = conn.execute(
            f"SELECT * FROM audit_logs{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]).fetchall()
        total = conn.execute(f"SELECT COUNT(*) FROM audit_logs{where_clause}", params).fetchone()[0]
        return jsonify({"logs": [dict(r) for r in rows], "total": total})
    finally:
        conn.close()

@app.route("/api/admin/audit-logs", methods=["DELETE"])
@require_admin
def admin_audit_logs_clear():
    conn = get_db()
    try:
        conn.execute("DELETE FROM audit_logs")
        conn.commit()
        return jsonify({"success": True, "deleted": "all"})
    finally:
        conn.close()

# --- 回收站 ---
@app.route("/api/auth/recycle-bin", methods=["GET"])
@require_auth
def client_recycle_bin_list():
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM recycle_bin WHERE username=? ORDER BY deleted_at DESC LIMIT 100", (username,)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/auth/recycle-bin", methods=["POST"])
@require_auth
def client_recycle_bin_add():
    username = request.user.get("sub", "")
    data = request.get_json(silent=True) or {}
    original_path = data.get("original_path", "")[:512]
    file_name = data.get("file_name", "")[:256]
    try:
        file_size = int(data.get("file_size", 0) or 0)
    except (ValueError, TypeError):
        file_size = 0
    is_dir = 1 if data.get("is_dir") else 0
    if not original_path or not file_name:
        return jsonify({"error": "缺少参数"}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO recycle_bin (username,original_path,file_name,file_size,is_dir,deleted_at) VALUES (?,?,?,?,?,?)",
                      (username, original_path, file_name, file_size, is_dir, datetime.now().isoformat()))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

@app.route("/api/auth/recycle-bin/<int:item_id>", methods=["DELETE"])
@require_auth
def client_recycle_bin_delete(item_id):
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        conn.execute("DELETE FROM recycle_bin WHERE id=? AND username=?", (item_id, username))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

def _get_recycle_dir(username):
    recycle_dir = CONFIG.get("alist_recycle_dir", "")
    if recycle_dir:
        return recycle_dir
    base_path = "/公司文件"
    try:
        user = get_user(username)
        if user:
            bp = user.get("alist_base_path", "")
            if bp:
                base_path = bp
    except Exception:
        pass
    return base_path.rstrip("/") + "/回收站"


def _recycle_auto_cleanup_loop():
    import time as _time
    while True:
        _time.sleep(3600)
        try:
            conn = get_db()
            try:
                rows = conn.execute("SELECT DISTINCT username FROM recycle_bin WHERE file_name='__auto_cleanup__' AND remark LIKE '%days%'").fetchall()
            finally:
                conn.close()
            for (username,) in rows:
                try:
                    conn = get_db()
                    try:
                        cfg_row = conn.execute("SELECT remark FROM recycle_bin WHERE username=? AND file_name='__auto_cleanup__'", (username,)).fetchone()
                    finally:
                        conn.close()
                    if not cfg_row:
                        continue
                    import json as _json
                    cfg = _json.loads(cfg_row[0])
                    days = cfg.get("days", 0)
                    if days <= 0:
                        continue
                    alist_ensure_token()
                    token = CONFIG.get("alist_token", "")
                    base = _alist_base()
                    if not base or not token:
                        continue
                    recycle_dir = _get_recycle_dir(username)
                    r = http_requests.post(f"{base}/api/fs/list",
                        json={"path": recycle_dir, "page": 1, "per_page": 500},
                        headers=_alist_headers(token), timeout=15)
                    d = r.json()
                    if d.get("code") != 200:
                        continue
                    content = d.get("data", {}).get("content") or []
                    now = datetime.now()
                    expired_names = []
                    for f in content:
                        fn = f.get("name", "")
                        mod_str = f.get("modified", "")
                        try:
                            if mod_str:
                                mod_time = datetime.fromisoformat(mod_str.replace("Z", "+00:00").replace("+00:00", ""))
                            else:
                                continue
                        except Exception:
                            continue
                        if (now - mod_time).days >= days:
                            expired_names.append(fn)
                    if not expired_names:
                        continue
                    conn = get_db()
                    try:
                        for fn in expired_names:
                            rb_row = conn.execute("SELECT original_path, file_size, deleted_by, deleted_at FROM recycle_bin WHERE username=? AND file_name=?", (username, fn)).fetchone()
                            rb_info = dict(rb_row) if rb_row else {}
                            conn.execute("INSERT INTO recycle_delete_logs (username,file_name,original_path,file_size,deleted_by,remark,deleted_at) VALUES (?,?,?,?,?,?,?)",
                                (username, fn, rb_info.get("original_path", ""), rb_info.get("file_size", 0), rb_info.get("deleted_by", username), f"自动清理(超过{days}天)", rb_info.get("deleted_at", "")))
                            conn.execute("DELETE FROM recycle_bin WHERE username=? AND file_name=?", (username, fn))
                        conn.commit()
                    finally:
                        conn.close()
                    _alist_temp_disable_recycle(base, token)
                    try:
                        http_requests.post(f"{base}/api/fs/remove",
                            json={"dir": recycle_dir, "names": expired_names},
                            headers=_alist_headers(token), timeout=30)
                    finally:
                        _alist_temp_disable_recycle(base, token, restore=True)
                    logging.info(f"[回收站自动清理] 用户 {username} 清理了 {len(expired_names)} 个过期文件 (>{days}天)")
                except Exception as e:
                    logging.warning(f"[回收站自动清理] 用户 {username} 清理失败: {e}")
        except Exception as e:
            logging.warning(f"[回收站自动清理] 循环异常: {e}")


def _alist_temp_disable_recycle(base, token, restore=False):
    try:
        r = http_requests.get(f"{base}/api/admin/storage/list", headers=_alist_headers(token), timeout=10)
        storages = r.json().get("data", {}).get("content", [])
        for s in storages:
            addition = json.loads(s.get("addition", "{}"))
            rbp = addition.get("recycle_bin_path", "")
            if restore:
                if rbp == "delete permanently" and hasattr(_alist_temp_disable_recycle, '_orig_rbp'):
                    addition["recycle_bin_path"] = _alist_temp_disable_recycle._orig_rbp
                    del _alist_temp_disable_recycle._orig_rbp
                else:
                    return
            else:
                if rbp and rbp != "delete permanently":
                    _alist_temp_disable_recycle._orig_rbp = rbp
                    addition["recycle_bin_path"] = "delete permanently"
                else:
                    return
            s["addition"] = json.dumps(addition, ensure_ascii=False)
            http_requests.post(f"{base}/api/admin/storage/update", json=s, headers=_alist_headers(token), timeout=10)
    except Exception:
        pass


@app.route("/api/admin/alist-recycle/<username>", methods=["GET"])
@require_admin
def admin_alist_recycle_list(username):
    alist_ensure_token()
    token = CONFIG.get("alist_token", "")
    base = _alist_base()
    if not base or not token:
        return jsonify({"files": [], "error": "AList 未配置"})
    recycle_dir = _get_recycle_dir(username)
    try:
        r = http_requests.post(f"{base}/api/fs/list",
            json={"path": recycle_dir, "page": 1, "per_page": 100},
            headers=_alist_headers(token), timeout=15)
        d = r.json()
        if d.get("code") != 200:
            return jsonify({"files": [], "error": d.get("message", "获取失败")})
        content = d.get("data", {}).get("content") or []
        conn = get_db()
        remark_map = {}
        try:
            rows = conn.execute("SELECT file_name, remark, deleted_by FROM recycle_bin WHERE username=?", (username,)).fetchall()
            for row in rows:
                remark_map[row[0]] = {"remark": row[1] or "", "deleted_by": row[2] or username}
        finally:
            conn.close()
        files = []
        for f in content:
            fn = f.get("name", "")
            info = remark_map.get(fn, {"remark": "", "deleted_by": username})
            files.append({
                "name": fn,
                "size": f.get("size", 0),
                "is_dir": f.get("is_dir", False),
                "modified": f.get("modified", ""),
                "original_path": recycle_dir,
                "owner": username,
                "deleted_by": info["deleted_by"],
                "remark": info["remark"],
            })
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"files": [], "error": str(e)})


@app.route("/api/admin/alist-recycle/<username>/restore", methods=["POST"])
@require_admin
def admin_alist_recycle_restore(username):
    data = request.get_json(silent=True) or {}
    file_name = data.get("file_name", "").strip()
    target_dir = data.get("target_dir", "").strip()
    if not file_name:
        return jsonify({"error": "缺少文件名"}), 400
    alist_ensure_token()
    token = CONFIG.get("alist_token", "")
    base = _alist_base()
    if not base or not token:
        return jsonify({"error": "AList 未配置"}), 400
    recycle_dir = _get_recycle_dir(username)
    if not target_dir:
        target_dir = recycle_dir.replace("/回收站", "")
    try:
        r = http_requests.post(f"{base}/api/fs/move",
            json={"src_dir": recycle_dir, "dst_dir": target_dir, "names": [file_name]},
            headers=_alist_headers(token), timeout=30)
        d = r.json()
        if d.get("code") != 200:
            return jsonify({"error": f"还原失败: {d.get('message', '未知错误')}"}), 400
        return jsonify({"success": True, "message": f"已还原到 {target_dir}"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/alist-recycle/<username>/delete", methods=["POST"])
@require_admin
def admin_alist_recycle_delete(username):
    data = request.get_json(silent=True) or {}
    file_name = data.get("file_name", "").strip()
    remark = data.get("remark", "").strip()
    if not file_name:
        return jsonify({"error": "缺少文件名"}), 400
    alist_ensure_token()
    token = CONFIG.get("alist_token", "")
    base = _alist_base()
    if not base or not token:
        return jsonify({"error": "AList 未配置"}), 400
    recycle_dir = _get_recycle_dir(username)
    try:
        conn = get_db()
        rb_row = conn.execute("SELECT original_path, file_size, deleted_by, deleted_at FROM recycle_bin WHERE username=? AND file_name=?", (username, file_name)).fetchone()
        rb_info = dict(rb_row) if rb_row else {}
        conn.close()
        _alist_temp_disable_recycle(base, token)
        try:
            r = http_requests.post(f"{base}/api/fs/remove",
                json={"dir": recycle_dir, "names": [file_name]},
                headers=_alist_headers(token), timeout=30)
        finally:
            _alist_temp_disable_recycle(base, token, restore=True)
        d = r.json()
        if d.get("code") != 200:
            return jsonify({"error": f"删除失败: {d.get('message', '未知错误')}"}), 400
        conn = get_db()
        try:
            conn.execute("DELETE FROM recycle_bin WHERE username=? AND file_name=?", (username, file_name))
            conn.execute("INSERT INTO recycle_delete_logs (username,file_name,original_path,file_size,deleted_by,remark,deleted_at) VALUES (?,?,?,?,?,?,?)",
                (username, file_name, rb_info.get("original_path", ""), rb_info.get("file_size", 0), rb_info.get("deleted_by", username), remark, rb_info.get("deleted_at", "")))
            conn.commit()
        finally:
            conn.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/alist-recycle/<username>/clear", methods=["POST"])
@require_admin
def admin_alist_recycle_clear(username):
    data = request.get_json(silent=True) or {}
    remark = data.get("remark", "").strip()
    alist_ensure_token()
    token = CONFIG.get("alist_token", "")
    base = _alist_base()
    if not base or not token:
        return jsonify({"error": "AList 未配置"}), 400
    recycle_dir = _get_recycle_dir(username)
    try:
        r_list = http_requests.post(f"{base}/api/fs/list",
            json={"path": recycle_dir, "page": 1, "per_page": 500},
            headers=_alist_headers(token), timeout=15)
        d = r_list.json()
        if d.get("code") != 200:
            return jsonify({"error": "获取回收站列表失败"}), 400
        content = d.get("data", {}).get("content") or []
        names = [f.get("name", "") for f in content if f.get("name")]
        conn = get_db()
        try:
            rows = conn.execute("SELECT file_name, original_path, file_size, deleted_by, deleted_at FROM recycle_bin WHERE username=?", (username,)).fetchall()
            for row in rows:
                conn.execute("INSERT INTO recycle_delete_logs (username,file_name,original_path,file_size,deleted_by,remark,deleted_at) VALUES (?,?,?,?,?,?,?)",
                    (username, row[0], row[1], row[2], row[3], remark or "批量清空", row[4]))
            conn.execute("DELETE FROM recycle_bin WHERE username=?", (username,))
            conn.commit()
        finally:
            conn.close()
        if names:
            _alist_temp_disable_recycle(base, token)
            try:
                r_del = http_requests.post(f"{base}/api/fs/remove",
                    json={"dir": recycle_dir, "names": names},
                    headers=_alist_headers(token), timeout=30)
                ddel = r_del.json()
                if ddel.get("code") != 200:
                    return jsonify({"error": f"清空失败: {ddel.get('message', '')}"}), 400
            finally:
                _alist_temp_disable_recycle(base, token, restore=True)
        return jsonify({"success": True, "count": len(names)})
    except Exception as e:
        try:
            _alist_temp_disable_recycle(base, token, restore=True)
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/alist-recycle/<username>/remark", methods=["POST"])
@require_admin
def admin_alist_recycle_remark(username):
    data = request.get_json(silent=True) or {}
    file_name = data.get("file_name", "").strip()
    remark = data.get("remark", "").strip()
    if not file_name:
        return jsonify({"error": "缺少文件名"}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT id FROM recycle_bin WHERE username=? AND file_name=?", (username, file_name)).fetchone()
        if row:
            conn.execute("UPDATE recycle_bin SET remark=? WHERE id=?", (remark, row[0]))
        else:
            conn.execute("INSERT INTO recycle_bin (username,original_path,file_name,remark) VALUES (?,?,?,?)",
                (username, "", file_name, remark))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()


@app.route("/api/admin/alist-recycle-delete-logs/<username>", methods=["GET"])
@require_admin
def admin_recycle_delete_logs(username):
    conn = get_db()
    try:
        rows = conn.execute("SELECT id,file_name,original_path,file_size,deleted_by,remark,deleted_at,permanent_deleted_at FROM recycle_delete_logs WHERE username=? ORDER BY id DESC LIMIT 200", (username,)).fetchall()
        return jsonify({"logs": [dict(r) for r in rows]})
    finally:
        conn.close()


@app.route("/api/admin/recycle-auto-cleanup/<username>", methods=["GET", "POST"])
@require_admin
def admin_recycle_auto_cleanup(username):
    if request.method == "GET":
        conn = get_db()
        try:
            row = conn.execute("SELECT quota_mb FROM user_quotas WHERE username=?", (username,)).fetchone()
            days = 0
            try:
                import json as _json
                cfg = _json.loads(conn.execute("SELECT remark FROM recycle_bin WHERE username=? AND file_name='__auto_cleanup__'", (username,)).fetchone()[0]) if conn.execute("SELECT remark FROM recycle_bin WHERE username=? AND file_name='__auto_cleanup__'", (username,)).fetchone() else {}
                days = cfg.get("days", 0)
            except Exception:
                pass
            return jsonify({"days": days})
        finally:
            conn.close()
    data = request.get_json(silent=True) or {}
    days = data.get("days", 0)
    try:
        days = int(days)
    except (ValueError, TypeError):
        days = 0
    conn = get_db()
    try:
        row = conn.execute("SELECT id FROM recycle_bin WHERE username=? AND file_name='__auto_cleanup__'", (username,)).fetchone()
        import json as _json
        cfg_str = _json.dumps({"days": days})
        if row:
            conn.execute("UPDATE recycle_bin SET remark=? WHERE id=?", (cfg_str, row[0]))
        else:
            conn.execute("INSERT INTO recycle_bin (username,original_path,file_name,remark) VALUES (?,?,?,?)",
                (username, "", "__auto_cleanup__", cfg_str))
        conn.commit()
        return jsonify({"success": True, "days": days})
    finally:
        conn.close()


# --- 磁盘配额 ---
@app.route("/api/admin/quota/<username>", methods=["GET", "POST"])
@require_admin
def admin_quota(username):
    conn = get_db()
    try:
        if request.method == "GET":
            row = conn.execute("SELECT * FROM user_quotas WHERE username=?", (username,)).fetchone()
            if not row:
                return jsonify({"quota_mb": 0, "used_mb": 0})
            return jsonify(dict(row))
        else:
            data = request.get_json(silent=True) or {}
            try:
                quota_mb = int(data.get("quota_mb", 0) or 0)
            except (ValueError, TypeError):
                quota_mb = 0
            conn.execute("INSERT INTO user_quotas (username, quota_mb, updated_at) VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET quota_mb=excluded.quota_mb, updated_at=excluded.updated_at",
                          (username, quota_mb, datetime.now().isoformat()))
            conn.commit()
            _audit("admin", "set_quota", f"设置用户 {username} 配额: {quota_mb}MB")
            return jsonify({"success": True})
    finally:
        conn.close()

@app.route("/api/auth/quota", methods=["GET"])
@require_auth
def client_quota():
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        row = conn.execute("SELECT quota_mb, used_mb FROM user_quotas WHERE username=?", (username,)).fetchone()
        if not row:
            return jsonify({"quota_mb": 0, "used_mb": 0, "unlimited": True})
        return jsonify({"quota_mb": row["quota_mb"], "used_mb": row["used_mb"], "unlimited": row["quota_mb"] == 0})
    finally:
        conn.close()

# --- 书签 ---
@app.route("/api/auth/bookmarks", methods=["GET"])
@require_auth
def client_bookmarks_list():
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM bookmarks WHERE username=? ORDER BY id", (username,)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/auth/bookmarks", methods=["POST"])
@require_auth
def client_bookmarks_add():
    username = request.user.get("sub", "")
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")[:512]
    display_name = data.get("display_name", "")[:128]
    if not path:
        return jsonify({"error": "缺少路径"}), 400
    conn = get_db()
    try:
        existing = conn.execute("SELECT id FROM bookmarks WHERE username=? AND path=?", (username, path)).fetchone()
        if existing:
            return jsonify({"error": "书签已存在"}), 400
        conn.execute("INSERT INTO bookmarks (username, path, display_name) VALUES (?,?,?)", (username, path, display_name))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

@app.route("/api/auth/bookmarks/<int:bm_id>", methods=["DELETE"])
@require_auth
def client_bookmarks_delete(bm_id):
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        conn.execute("DELETE FROM bookmarks WHERE id=? AND username=?", (bm_id, username))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

# --- 消息通知 ---
@app.route("/api/admin/notifications", methods=["GET", "POST", "DELETE"])
@require_admin
def admin_notifications():
    if request.method == "GET":
        limit = min(int(request.args.get("limit", 50)), 200)
        title_search = request.args.get("title", "").strip()
        conn = get_db()
        try:
            if title_search:
                rows = conn.execute("SELECT * FROM notifications WHERE title LIKE ? ORDER BY id DESC LIMIT ?",
                                    (f"%{title_search}%", limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return jsonify({"notifications": [dict(r) for r in rows]})
        finally:
            conn.close()
    if request.method == "DELETE":
        conn = get_db()
        try:
            conn.execute("DELETE FROM notifications")
            conn.commit()
            return jsonify({"success": True})
        finally:
            conn.close()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    title = data.get("title", "").strip()[:128]
    content = data.get("content", "").strip()[:2048]
    duration = max(1, min(3600, int(data.get("duration", 5))))
    if not title:
        return jsonify({"error": "缺少标题"}), 400
    conn = get_db()
    try:
        if username:
            conn.execute("INSERT INTO notifications (username, title, content, duration, created_at) VALUES (?,?,?,?,?)", (username, title, content, duration, datetime.now().isoformat()))
        else:
            for u in conn.execute("SELECT username FROM users WHERE active=1").fetchall():
                conn.execute("INSERT INTO notifications (username, title, content, duration, created_at) VALUES (?,?,?,?,?)", (u["username"], title, content, duration, datetime.now().isoformat()))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

@app.route("/api/auth/notifications", methods=["GET"])
@require_auth
def client_notifications():
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM notifications WHERE (username=? OR username='') ORDER BY id DESC LIMIT 20", (username,)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.route("/api/auth/notifications/<int:nid>/read", methods=["POST"])
@require_auth
def client_notification_read(nid):
    username = request.user.get("sub", "")
    conn = get_db()
    try:
        conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND username=?", (nid, username))
        conn.commit()
        return jsonify({"success": True})
    finally:
        conn.close()

# --- 批量用户导入 ---
@app.route("/api/admin/users/batch-import", methods=["POST"])
@require_admin
def admin_batch_import():
    data = request.get_json(silent=True) or {}
    users = data.get("users", [])
    if not users or not isinstance(users, list):
        return jsonify({"error": "缺少用户列表"}), 400
    results = {"success": 0, "failed": 0, "errors": []}
    alist_results = {}
    if CONFIG.get("alist_token"):
        for u in users[:200]:
            uname = str(u.get("username", "")).strip()
            pwd = str(u.get("password", "")).strip()
            bp = str(u.get("alist_base_path", "/公司文件")).strip()
            if not uname or not pwd:
                continue
            try:
                ok, err = alist_create_user(uname, pwd, base_path=bp, role_id=0)
                if ok:
                    users_alist, _ = alist_get_users()
                    alist_id = 0
                    if users_alist:
                        for au in users_alist:
                            if au.get("username") == uname:
                                alist_id = au.get("id", 0)
                                break
                    alist_results[uname] = alist_id
                else:
                    alist_results[uname] = 0
                    results["errors"].append(f"{uname}: AList同步失败({err})")
            except Exception as e:
                alist_results[uname] = 0
                results["errors"].append(f"{uname}: AList同步失败({e})")
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        for u in users[:200]:
            uname = str(u.get("username", "")).strip()
            pwd = str(u.get("password", "")).strip()
            bp = str(u.get("alist_base_path", "/公司文件")).strip()
            dl = str(u.get("drive_letter", "Z:")).strip()
            lb = str(u.get("label", "远程磁盘")).strip()
            if not uname or not pwd:
                results["failed"] += 1
                results["errors"].append(f"{uname}: 用户名或密码为空")
                continue
            if not _USERNAME_RE.match(uname):
                results["failed"] += 1
                results["errors"].append(f"{uname}: 用户名格式不合法")
                continue
            valid_pwd, pwd_err = validate_password_length(pwd)
            if not valid_pwd:
                results["failed"] += 1
                results["errors"].append(f"{uname}: {pwd_err}")
                continue
            existing = conn.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
            if existing:
                results["failed"] += 1
                results["errors"].append(f"{uname}: 用户已存在")
                continue
            alist_id = alist_results.get(uname, 0)
            conn.execute(
                "INSERT INTO users (username, password_hash, drive_letter, label, alist_base_path, alist_id, alist_role_id)"
                " VALUES (?,?,?,?,?,?,0)",
                (uname, hash_password(pwd), dl, lb, bp, alist_id))
            results["success"] += 1
        conn.commit()
        for u in users[:200]:
            uname = str(u.get("username", "")).strip()
            if uname:
                _audit("admin", "batch_import_user", f"导入用户 {uname}")
        return jsonify(results)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
