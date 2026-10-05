# npw-dev

开发用命令行：用 `npw-core` + `npw-store-sqlite` 通过 HTTP 驱动一个**正在运行的**服务端，每个 profile 目录就是一台“设备”的本地副本。用于手工验证注册、登录、同步、导入导出，以及多设备并发修改压测和服务端被杀测试。

> 仅供开发测试。profile 目录里明文保存设备密钥（`device.key`），解锁后还保存账户密钥（`unlock.key`），能读到这个目录的人就能解密保管库。只用测试账号。

## 构建

```powershell
cd common
cargo build -p npw-dev          # 产物在 ../target/debug/npw-dev.exe
```

## profile 目录

| 文件 | 内容 |
|---|---|
| `replica.sqlite3` | 本地副本（只有密文） |
| `device.key` | 设备密钥（正式客户端放系统密钥库，这里放文件） |
| `unlock.key` | 解锁后的账户密钥；`register`、`login`、`unlock` 写入，`lock` 删除 |

`--profile DIR`（或环境变量 `NPW_PROFILE`）选择 profile，默认 `./npw-dev-profile`。

## 主密码

按顺序取：`--master-password`（**不安全**，会进 shell 历史和进程列表，只给一次性测试账号用）→ `--password-env` 指定的环境变量（默认 `NPW_PASSWORD`）→ 终端提示输入（不回显；stdin 被重定向时读一行）。

profile 已解锁（有 `unlock.key`）时，大多数命令不需要主密码；`export` 总要主密码。

## 示例

```powershell
$env:NPW_PASSWORD = 'correct horse battery staple'
$url = 'http://127.0.0.1:8087'

# 第一台设备：注册，打印紧急包（Secret Key）
npw-dev --profile dev-a register --server $url --email dev@example.com
# 服务端已有账户时注册需要邀请码：nyapassword-server invite
npw-dev --profile dev-b register --server $url --email dev2@example.com --invite <邀请码>

# 第二台设备：用 Secret Key 登录（也可放环境变量 NPW_SECRET_KEY）
npw-dev --profile dev-c --device-name laptop login --server $url --email dev@example.com --secret-key A1-XXXXXX-...

npw-dev --profile dev-a status
npw-dev --profile dev-a lock              # 删除 unlock.key
npw-dev --profile dev-a unlock            # 用主密码解锁并记住账户密钥

# 条目：修改后默认立即同步；加 --no-sync 只写本地（待同步），用来制造并发冲突
npw-dev --profile dev-a add-login --title GitHub --username dev --password hunter2 --url https://github.example.com
npw-dev --profile dev-a --no-sync edit GitHub --field password=from-a --field pin=1234
npw-dev --profile dev-c --no-sync edit GitHub --field password=from-c --notes "note"
npw-dev --profile dev-a sync
npw-dev --profile dev-c sync
npw-dev --profile dev-a list               # 冲突、待同步、回收站会标出来
npw-dev --profile dev-a get GitHub         # 完整内容（含冲突）JSON
npw-dev --profile dev-a delete GitHub
npw-dev --profile dev-a restore GitHub
npw-dev --profile dev-a vaults
npw-dev --profile dev-a check              # 健康检查 + 本地与服务端摘要比较

# 导入：默认按内容识别格式；--source bitwarden|bitwarden-csv|1pux|1password-csv|kdbx|keepass-csv|csv
# 导入后逐字段对比，发现差异时退出码非 0
npw-dev --profile dev-a import bitwarden_export.json
npw-dev --profile dev-a import vault.kdbx --source kdbx --file-password-env KDBX_PASSWORD

# 导出：native（无损，需主密码 + Secret Key 打开）、kdbx（主密码加密）、csv（明文）
npw-dev --profile dev-a export --format native --out vault.npw
npw-dev --profile dev-a export --format kdbx --out vault.kdbx

npw-dev --profile dev-a logout             # 有未同步修改时拒绝，--force 强制
```

条目可以用完整 id、id 前缀（至少 4 个字符）或标题（不分大小写）指定；保管库用 id、id 前缀或名称。

## 并发压测 `stress`

注册一个新账户（邮箱 `stress-<seed>-<时间>@example.com`），其余设备用 Secret Key 登录，然后各设备**并发**做随机操作：新建、改字段/备注/标签、删除、恢复、离线一段时间、模拟 App 重启（从磁盘重新打开副本）、同步（15% 的同步中途取消，模拟进程被杀）。结束后所有设备反复同步，然后检查：

- 每次**成功完成**的同步开始时设备上已有的值，都能在服务端找到（当前内容、冲突、密码历史或历史修订）；
- 每台设备的副本摘要等于服务端摘要，所有设备内容一致，没有待同步或被拒的修改，所有条目能解密。

只在被取消或失败的同步期间存在过、之后又被本机覆盖的值不算丢失（它从未离开设备），只计数。

```powershell
npw-dev stress --server $url --devices 3 --ops 300 --seed 42
npw-dev stress --server $url --devices 5 --ops 1000 --invite <邀请码>   # 服务端已关闭开放注册时
```

profile 默认放在临时目录，成功后删除（`--keep` 保留）；失败时保留并打印路径，可以直接 `npw-dev --profile <目录>\dev0 list` 查看。`--dir` 指定的目录不会被删除。失败时退出码非 0。

## 服务端被杀测试 `kill-test`

自己启动服务端进程（新数据目录、空闲端口），注册账户后循环：每台设备先离线改若干条，然后同时同步，同步过程中硬杀服务端（Windows 上是 TerminateProcess），有时也“重启”设备，再在同一端口启动服务端。最后同 `stress` 一样检查。

```powershell
# Windows 上运行中的 exe 会锁住文件，先把服务端复制出 target 目录
Copy-Item ..\target\debug\nyapassword-server.exe $env:TEMP\npw-srv.exe
npw-dev kill-test --server-bin $env:TEMP\npw-srv.exe --devices 3 --rounds 15 --edits 8
```

服务端日志在工作目录的 `server.log`。`--data` 可指定服务端数据目录（会被反复杀进程，只用一次性目录）。
