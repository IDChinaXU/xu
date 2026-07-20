@echo off
chcp 65001 >nul 2>&1
title MorongDisk 清理工具
echo ============================================
echo   MorongDisk 客户端+服务端清理工具
echo ============================================
echo.

echo [1/8] 正在终止 MorongDisk 进程...
taskkill /F /IM MorongDisk.exe >nul 2>&1
if %errorlevel%==0 (
    echo       已终止 MorongDisk.exe
) else (
    echo       无 MorongDisk 进程
)

echo [2/8] 正在终止 rclone 进程...
taskkill /F /IM rclone.exe >nul 2>&1
if %errorlevel%==0 (
    echo       已终止 rclone.exe
) else (
    echo       无 rclone 进程
)

echo [3/8] 正在终止 AuthServer 进程...
taskkill /F /IM AuthServer.exe >nul 2>&1
if %errorlevel%==0 (
    echo       已终止 AuthServer.exe
) else (
    echo       无 AuthServer 进程
)

echo [4/8] 正在清理单实例锁文件...
if exist "C:\ProgramData\MorongDisk\client.lock" (
    del /F /Q "C:\ProgramData\MorongDisk\client.lock" >nul 2>&1
    if %errorlevel%==0 (
        echo       已删除 client.lock
    ) else (
        echo       删除失败，请以管理员身份运行
    )
) else (
    echo       无锁文件
)

echo [5/8] 正在清理 rclone 临时配置文件...
set "RC_DIR=%APPDATA%\AlistDrive"
if exist "%RC_DIR%" (
    del /F /Q "%RC_DIR%\rclone_z.conf" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone_y.conf" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone_x.conf" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone_w.conf" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone_v.conf" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone.pid" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone_stderr_z.log" >nul 2>&1
    del /F /Q "%RC_DIR%\rclone_stderr_y.log" >nul 2>&1
    echo       已清理 rclone 临时文件
) else (
    echo       无 rclone 临时文件
)

echo [6/8] 正在清理服务端临时文件...
if exist "D:\AlistDrive\server\auth.db-journal" (
    del /F /Q "D:\AlistDrive\server\auth.db-journal" >nul 2>&1
    echo       已清理 auth.db-journal
) else (
    echo       无数据库日志文件
)
if exist "D:\AlistDrive\server\auth.db-wal" (
    del /F /Q "D:\AlistDrive\server\auth.db-wal" >nul 2>&1
    echo       已清理 auth.db-wal
)
if exist "D:\AlistDrive\server\auth.db-shm" (
    del /F /Q "D:\AlistDrive\server\auth.db-shm" >nul 2>&1
    echo       已清理 auth.db-shm
)

echo [7/8] 正在检查磁盘挂载残留...
for %%D in (Z Y X W V) do (
    if exist "%%D:\" (
        echo       警告: %%D: 盘仍存在，可能需要重启后自动释放
    )
)

echo [8/8] 正在清理 ProgramData 日志...
if exist "C:\ProgramData\MorongDisk\server.log" (
    del /F /Q "C:\ProgramData\MorongDisk\server.log" >nul 2>&1
    echo       已清理 server.log
)
if exist "C:\ProgramData\MorongDisk\client.log" (
    del /F /Q "C:\ProgramData\MorongDisk\client.log" >nul 2>&1
    echo       已清理 client.log
)

echo.
echo ============================================
echo   清理完成！现在可以重新启动了
echo ============================================
echo.
pause