@echo off
title 强制卸载并清理环境
%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit

echo [*] 正在断开 Z: 盘...
net use Z: /delete /y >nul 2>&1
taskkill /f /im rclone.exe >nul 2>&1

echo [*] 正在移除“发送到”快捷方式...
del /f /q "%APPDATA%\Microsoft\Windows\SendTo\远程磁盘 (Z).lnk" >nul 2>&1

echo [*] 正在修复 UI...
ie4uinit.exe -ClearIconCache
taskkill /f /im explorer.exe & ping 127.0.0.1 -n 2 >nul & start explorer.exe

exit