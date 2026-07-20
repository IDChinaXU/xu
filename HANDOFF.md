# MorongDisk 远程磁盘挂载系统 - 交接文档

> 最后更新：2026-07-13 | 版本：v1.15.0 | 全量测试 72/72 通过

---

## 一、项目概述

MorongDisk 是一套企业级远程磁盘挂载系统，基于 AList (WebDAV) + rclone + WinFsp 技术，将远程文件系统映射为 Windows 本地磁盘。系统分为三端：

| 端 | 文件 | 功能 | 部署路径 |
|---|------|------|----------|
| 服务端 | `auth_server.py` → `AuthServer.exe` | 用户认证、AList同步、管理后台、配额/审计/通知等8个功能API | `D:\AlistDrive\server\` |
| 客户端 | `alist_drive.py` → `MorongDisk.exe` | 登录界面、rclone挂载、托盘图标、自动重连、文件日志、通知弹窗 | `D:\AlistDrive\client\` |
| 安装程序 | `installer.py` → `MorongDiskSetup.exe` | 一键安装WinFsp+客户端、注册自启动、磁盘图标 | `D:\AlistDrive\setup\` |

**源码目录**：`D:\AlistDrive\AlistDrive\`

**外部依赖**：
- AList 服务器：`http://192.168.100.242:5244/`（管理员 `admin` / `morong@2026`）
- 测试用户：`xu` / `wanmei123`
- 服务端默认管理员密码：`admin123`

---

## 二、已完成的功能

### 核心功能
1. RSA-2048 加密登录、JWT 签名验证、暴力破解防护
2. 管理员会话 Token（含 `expires_at` + `expires_in`）
3. AList 用户双向同步（登录时自动同步 base_path/role）
4. 修改密码（同步到 AList，admin 用户跳过 AList 同步）
5. 客户端 UI：密码可见性切换、加载动画、服务器连通性测试、托盘图标

### 8个新功能
1. **多盘符支持**：`user_drives` 表 + CRUD API + 登录/verify 返回 `drives` 数组
2. **离线文件缓存**：rclone 缓存 72h + `--vfs-read-wait 200ms` + cache-config API
3. **文件回收站**：添加/查询/清空
4. **磁盘容量配额**：管理员设置 + 客户端查询
5. **文件收藏/书签**：添加/查询/删除
6. **批量用户导入**：CSV式批量创建 + AList 同步
7. **操作审计日志**：8种操作类型（login/admin_login/change_password/batch_import_user/delete_user/update_user/set_drives/set_quota）+ 分页/过滤/清空
8. **消息通知推送**：管理员发送 + 客户端60秒轮询 + 右下角5秒弹窗 + 标记已读/标题搜索/清空

### 安全功能
1. RSA 私钥加密存储（AES-CFB8，`rsa_private.pem.enc`）
2. 本地密码加密：AES-256-GCM（PBKDF2 密钥派生，基于机器名+用户名），前缀 `aes:`
3. 管理员端点速率限制、安全响应头、输入验证
4. 禁用账号返回通用错误（不泄露用户存在/禁用状态）
5. webdav_path 路径穿越过滤（`_sanitize_webdav_path` 用 `posixpath.normpath`）
6. SQL 注入防护（参数化查询）
7. 杀软误报风险已处理（替换了 CreateMutexW/DPAPI/GetAsyncKeyState/剪贴板ctypes/VBS自启动/bat自删除/ExecutionPolicy Bypass 共8项）

---

## 三、当前部署状态

### 三端 exe（v1.15.0）

| 文件 | 大小 | SHA256前24位 |
|------|------|-------------|
| `D:\AlistDrive\server\AuthServer.exe` | 18MB | `e54282f74e3d29a3d1d1db79` |
| `D:\AlistDrive\client\MorongDisk.exe` | 20MB | `aacd8c00309268d3f134a61b` |
| `D:\AlistDrive\setup\MorongDiskSetup.exe` | 58MB | `c3a25a381e86a6bf8ee629a0` |

### download 更新目录
`D:\AlistDrive\server\download\` 包含：
- 3个 exe（与上述相同副本）
- 3个 `*_version.txt`（JSON格式，含 version/filename/download_url/changelog/sha256，**无BOM**）

### 客户端依赖
`D:\AlistDrive\client\` 还包含：`rclone.exe`、`winfsp-2.0.23075.msi`

---

## 四、打包流程

### 打包命令（按顺序执行）
```powershell
# 1. 清理 AuthServer 构建缓存（必须！否则可能用旧代码）
Remove-Item "D:\AlistDrive\AlistDrive\build\AuthServer" -Recurse -Force

# 2. 打包三端
cd D:\AlistDrive\AlistDrive
pyinstaller AuthServer.spec --noconfirm
pyinstaller AlistDrive.spec --noconfirm

# 3. 安装程序需要先复制最新客户端到源码目录
Copy-Item "D:\AlistDrive\AlistDrive\dist\MorongDisk.exe" "D:\AlistDrive\AlistDrive\MorongDisk.exe" -Force
Remove-Item "D:\AlistDrive\AlistDrive\build\MorongDiskSetup" -Recurse -Force
pyinstaller MorongDiskSetup.spec --noconfirm

# 4. 部署到对应目录
Copy-Item "dist\AuthServer.exe" "D:\AlistDrive\server\" -Force
Copy-Item "dist\MorongDisk.exe" "D:\AlistDrive\client\" -Force
Copy-Item "dist\MorongDiskSetup.exe" "D:\AlistDrive\setup\" -Force
Copy-Item "dist\AuthServer.exe" "D:\AlistDrive\server\download\" -Force
Copy-Item "dist\MorongDisk.exe" "D:\AlistDrive\server\download\" -Force
Copy-Item "dist\MorongDiskSetup.exe" "D:\AlistDrive\server\download\" -Force

# 5. 生成版本文件（必须用 Python，不能用 PowerShell Out-File，会有 BOM）
python -c "
import json, os, hashlib
d = r'D:\AlistDrive\server\download'
v = '1.15.0'
for name, exe in [('client','MorongDisk.exe'),('server','AuthServer.exe'),('setup','MorongDiskSetup.exe')]:
    info = {'version':v,'filename':exe,'download_url':'/'+exe,'changelog':'Bug修复和安全增强','sha256':''}
    p = os.path.join(d, exe)
    if os.path.exists(p):
        h = hashlib.sha256(open(p,'rb').read()).hexdigest()
        info['sha256'] = h
    with open(os.path.join(d, name+'_version.txt'),'w',encoding='utf-8') as f:
        json.dump(info, f, ensure_ascii=False, indent=2)
    print(name+'_version.txt done')
"
```

---

## 五、绝对不能再踩的坑（⚠️ 重要）

### 打包相关
| # | 坑 | 说明 |
|---|---|------|
| 1 | **AuthServer 构建缓存** | PyInstaller 会缓存旧代码。每次打包 AuthServer.exe 前必须 `Remove-Item build\AuthServer -Recurse -Force`，否则可能用旧代码 |
| 2 | **MorongDiskSetup 嵌入旧客户端** | Setup 的 spec 文件把 `MorongDisk.exe` 作为 datas 嵌入。打包 Setup 前必须先把最新 `dist\MorongDisk.exe` 复制到源码目录 |
| 3 | **版本文件 BOM** | PowerShell `Out-File -Encoding utf8` 会写 UTF-8 BOM（`EF BB BF`），导致 `json.load()` 失败。版本文件必须用 Python 生成 |
| 4 | **中文路径** | PyInstaller 打包的 exe 在中文路径下无法启动。部署到英文路径 `D:\AlistDrive\server\` 等 |
| 5 | **端口冲突** | 测试时可能有多个 python.exe 监听 9800 端口。用 `netstat -ano | findstr :9800` 检查，杀掉多余进程 |

### 服务端代码
| # | 坑 | 说明 |
|---|---|------|
| 6 | **`require_admin` 死锁** | `_ADMIN_TOKEN_LOCK` 是 `threading.Lock()`（非 RLock），在 `with` 块内调用 `f()` 而 `f()` 内部又获取同一把锁会死锁。修复：先提取 `token_valid` 标志，锁释放后再调用 `f()` |
| 7 | **Flask 单线程阻塞** | `app.run()` 默认单线程，AList 同步等慢操作会阻塞所有请求。必须 `app.run(threaded=True)` |
| 8 | **JWT JTI 防重放** | 用户 JWT token 会被频繁复用（多个 API 调用），JTI 防重放机制会导致同一 token 第二次使用被拒。**不要在 `jwt_decode` 中检查 JTI** |
| 9 | **`_audit` 在事务内调用** | `_audit` 用独立数据库连接写 audit_logs，如果外层连接持有 `BEGIN IMMEDIATE` 锁，`_audit` 会被 SQLite WAL 锁阻塞静默失败。**`_audit` 必须在 `conn.commit()` 之后调用** |
| 10 | **AList 不允许修改 admin 角色** | `alist_update_user` 对 admin 用户调用会返回 `cannot change role of admin user`。修改密码时 admin 用户需跳过 AList 同步 |
| 11 | **AList 用户 API 字段** | AList `/api/admin/user/list` 返回的角色字段是 `role`（数组如 `[4]`），**不是** `role_id` |
| 12 | **禁用账号信息泄露** | 禁用用户登录必须返回"用户名或密码错误"，不能返回"账号已被禁用"，否则攻击者可枚举用户 |
| 13 | **密码修改 AList 同步失败** | AList 同步失败不应阻止本地密码修改。先更新本地，AList 失败仅 `logging.warning` |
| 14 | **管理员暴力锁定时间** | `_ADMIN_LOCK_SECONDS = 600`（10分钟），测试暴力锁定功能后管理员会被锁10分钟。**暴力锁定测试必须放在所有测试最后** |

### 客户端代码
| # | 坑 | 说明 |
|---|---|------|
| 15 | **WinFsp 2.1 兼容** | 不能用 `-o VolumePrefix=/MorongDisk`（WinFsp 2.1 返回 `Status=c000000d`），不能用 `--network-mode`（磁盘显示在"网络位置"分组下）。直接用 `--volname` + `-o FileSecurity=D:P(A;;FA;;;WD)` |
| 16 | **磁盘图标** | 必须用注册表 `HKCU\...\Explorer\DriveIcons\{letter}\DefaultIcon` 设置 `imageres.dll,31`（本地磁盘图标），不能用网络驱动器图标 |
| 17 | **`_file_log_uploader_stop` 缺 global** | 4处修改该变量的函数都需声明 `global _file_log_uploader_stop`，否则赋值无效 |
| 18 | **多盘符 `len>1` 忽略单盘符** | 当用户只有1个盘符配置时 `len(drives) > 1` 为 False，导致单盘符用户无法使用多盘符逻辑。必须用 `len(drives) >= 1` |
| 19 | **PID 文件 TOCTOU 竞态** | 读写 PID 文件必须用 `_rclone_lock` 保护。`thorough_unmount` 只删除当前盘符条目，不删除整个 PID 文件 |
| 20 | **bat `for %d` 语法** | bat 脚本中 for 循环变量必须用 `%%d` 而非 `%d`（cmd.exe 批处理模式要求双百分号） |
| 21 | **卸载脚本路径注入** | Python 脚本中嵌入路径必须用 `repr()` 而非 `r'...'` f-string，防止路径含特殊字符 |
| 22 | **密码缓存 key** | `_obscured_pwd_cache` 的 key 不能用明文密码（内存中暴露），必须用 `hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]` |
| 23 | **r.json() 在状态码检查前** | 必须先检查 `r.status_code != 200` 再调用 `r.json()`，否则非200响应可能无JSON体 |
| 24 | **obscure_password 超时** | `proc.communicate(timeout=10)` 超时后必须 `proc.kill()` + `proc.communicate()` 清理子进程 |
| 25 | **单实例锁文件句柄** | `_instance_lock_file = open(...)` 后必须 `_instance_lock_file.close()`，否则文件句柄泄露 |

### API 路径速查（容易写错）
| 正确路径 | 易错写法 |
|---------|---------|
| `/api/auth/hardware-info` | ~~`/api/auth/hardware`~~ |
| `/api/auth/file-log` | ~~`/api/auth/file-logs`~~ |
| `/api/auth/check-update?type=client` | ~~`/api/auth/version?platform=client`~~ |
| `/api/admin/quota/{username}` | ~~`/api/admin/users/{username}/quota`~~ |
| `POST /api/auth/notifications/{id}/read` | ~~`PUT`~~ |
| `/api/auth/verify` 返回 `valid` | 不是 `success` |
| `/api/admin/users/{username}` 只有 PUT/DELETE | 没有 GET 单用户路由，从列表查找 |

---

## 六、测试方法

### 启动服务端（从源码测试）
```powershell
cd D:\AlistDrive\AlistDrive
Remove-Item auth.db -Force -ErrorAction SilentlyContinue
python -c "import subprocess; subprocess.Popen(['python','auth_server.py'], creationflags=0x08000000 | 0x00000008)"
# 等待6秒后测试
Start-Sleep -Seconds 6
python -c "import requests; print(requests.get('http://127.0.0.1:9800/api/health',timeout=5).json())"
```

### 关键测试点
1. 管理员登录 → 获取 token → AList 同步
2. xu 用户登录 → verify → drives → quota → cache-config → notifications → commands
3. 批量导入用户 → 设置多盘符 → 客户端获取盘符
4. 审计日志 8 种操作类型全部覆盖
5. 路径穿越/SQL注入/XSS 安全测试
6. 并发测试（30并发健康检查 + 10并发登录）
7. **暴力锁定测试放最后**（会锁管理员10分钟）

---

## 七、文件结构

```
D:\AlistDrive\
├── AlistDrive\                    # 源码目录
│   ├── auth_server.py             # 服务端（~4747行）
│   ├── alist_drive.py             # 客户端（~4052行）
│   ├── installer.py               # 安装程序
│   ├── AuthServer.spec            # 服务端打包配置
│   ├── AlistDrive.spec            # 客户端打包配置
│   ├── MorongDiskSetup.spec       # 安装程序打包配置
│   ├── version_client.txt         # 客户端版本信息
│   ├── version_server.txt         # 服务端版本信息
│   ├── version_setup.txt          # 安装程序版本信息
│   ├── MorongDisk.exe             # 客户端exe（Setup打包用）
│   ├── rclone.exe                 # rclone（Setup打包用）
│   ├── winfsp-2.0.23075.msi      # WinFsp安装包（Setup打包用）
│   ├── morong.ico                 # 图标
│   ├── dist\                      # 打包产物
│   └── build\                     # 构建缓存
├── server\                        # 服务端部署
│   ├── AuthServer.exe
│   ├── auth.db                    # SQLite数据库（运行时生成）
│   ├── server_config.json         # 服务端配置（运行时生成）
│   ├── rsa_public.pem             # RSA公钥（运行时生成）
│   ├── rsa_private.pem.enc        # RSA私钥加密存储（运行时生成）
│   └── download\                  # 更新文件目录
│       ├── AuthServer.exe
│       ├── MorongDisk.exe
│       ├── MorongDiskSetup.exe
│       ├── client_version.txt
│       ├── server_version.txt
│       └── setup_version.txt
├── client\                        # 客户端部署
│   ├── MorongDisk.exe
│   ├── rclone.exe
│   └── winfsp-2.0.23075.msi
└── setup\                         # 安装程序部署
    └── MorongDiskSetup.exe
```

---

## 八、未完成 / 后续优化

1. **通知弹窗实际效果** — 客户端右下角5秒弹窗需在真实环境验证
2. **登录日志完整性** — 目前只记录8种操作，可扩展文件操作、配额变更等
3. **多盘符边界测试** — 更多极端场景（如3个盘符同时断连重连）
4. **AList token 过期** — AList 管理员 token 会定期失效，`alist_auto_init()` 会自动刷新，但如果 AList 重启可能需要手动重新配置
5. **管理员锁定时间** — `_ADMIN_LOCK_SECONDS = 600` 可能过长，生产环境可考虑缩短到 300 秒