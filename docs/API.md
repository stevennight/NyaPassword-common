# NyaPassword 服务端 API 1.0

> 对应 `npw-api`（common 仓库 `crates/npw-api`，`API_MAJOR = 1`、`API_MINOR = 0`）和服务端实现（server 仓库 `src/`）。本文描述**代码实际的行为**；与 [设计方案.md](设计方案.md) §7 有出入时以本文为准。
> 示例中的地址一律是占位值（`https://vault.example.com`、`203.0.113.x`）。

## 0. 约定

- HTTPS + JSON（`Content-Type: application/json`），UTF-8。服务端只监听本机地址（默认 `127.0.0.1:8087`），TLS 由前面的反向代理（Caddy）负责。
- 二进制值：base64url 无填充（服务端解码时也接受带 `=` 和标准字母表）。下文类型 `B64` 即此。
- 时间：UTC 毫秒整数。ID：UUID 字符串（账户、保险库、条目、附件、设备）。
- 认证：`Authorization: Bearer <access_token>`。下表“认证”列：**无** = 不需要；**用户** = 用户 access token；**管理** = 管理会话 token（§10）。
- 成功时返回 200 和 JSON；没有内容的成功返回 `{}`。
- `/v1/` 下未定义的路径返回 404 纯文本 `not found`；`/v1/` 以外的路径由内嵌的网页版 / 管理后台处理（`/admin`、`/admin/…` → `admin.html`，其他 → `index.html`）。
- 没有 CORS 头：网页版与 API 同源；浏览器扩展的 Service Worker 凭主机权限访问。
- 请求体上限：`/v1/vaults/{v}/items/batch` 128 MiB；附件 `max_attachment_mb`（默认 100）MiB + 64 KiB；其他 axum 默认（2 MiB）。

## 1. 版本与功能协商

`GET /v1/server-info`（无认证）→ `ServerInfo`：

```json
{
  "api": "1.0",
  "server_version": "0.1.0",
  "features": ["events", "attachments", "revisions", "atomic-batch"],
  "registration_open": true,
  "time": 1759536000000,
  "epoch": "0192f0c0-0000-7000-8000-000000000abc"
}
```

| 键 | 说明 |
|---|---|
| `api` | `MAJOR.MINOR` |
| `features` | 服务端支持的功能（下表）。客户端按功能开启行为，**不比较版本号** |
| `registration_open` | 还没有任何账户且配置允许首个账户免邀请注册（`open_first_registration`，默认开） |
| `time` | 服务端时钟，用于 TOTP 时钟偏差提示 |
| `epoch` | 服务端数据库的标识（UUIDv7）。首次启动生成，**从备份恢复时更换**；客户端发现它变了就做一次全量对账（§6.6） |

| 功能名 | 含义 | 当前服务端 |
|---|---|---|
| `events` | WebSocket `/v1/events`（§9） | 宣告 |
| `attachments` | 附件 blob（§7） | 宣告 |
| `revisions` | 修订历史（§6.4） | 宣告 |
| `atomic-batch` | 推送的 `atomic: true`（§6.2） | 宣告 |
| `recovery-code` | 恢复码（§12） | 常量已定义，**不宣告**（未实现） |

兼容规则：同一 MAJOR 内请求和响应只增加可选字段，不删、不改名、不改类型；客户端忽略不认识的字段（`serde` 默认行为）；新行为只通过功能列表开启。

`GET /v1/health`（无认证）→ 200 纯文本 `ok`（Docker `HEALTHCHECK` 用）。

## 2. 错误

错误响应体是 `ApiError`：

```json
{ "code": "conflict", "message": "vault metadata changed meanwhile" }
```

`message` 是给人看的英文，不属于接口；客户端只看 `code` 和 HTTP 状态。

| `code` | HTTP | 何时 |
|---|---|---|
| `invalid_request` | 400 | 参数不合法：登录名为空 / 超过 200 字符 / 含控制字符、ID 不是 UUID、base64 错误、KDF 参数越界（message `invalid key derivation parameters`）、OPAQUE 消息无法解析（`OPAQUE protocol error`）、单次推送超过 1000 条、备份设置不合法等 |
| `unauthorized` | 401 | 缺少 / 无效 / 过期的 token；refresh token 无效或过期 |
| `device_revoked` | 401 | 设备已被吊销：该设备的 access / refresh token（吊销不删除会话，它们自然过期），以及登录时 `device.id` 是本账户已吊销的设备（见 §3.2、§8） |
| `login_failed` | 401 | 登录失败（密码、Secret Key、登录名错误不可区分；`login_id` 过期或已用过）；管理口令或 TOTP 错误 |
| `forbidden` | 403 | 尚未设置管理口令时的管理登录 |
| `registration_closed` | 403 | 注册需要邀请码，或邀请码无效、过期、已用过 |
| `not_found` | 404 | 资源不存在，**或不是该保险库的成员**（不区分，避免泄露存在性） |
| `conflict` | 409 | 登录名或账户 ID 已注册、保险库 ID 已存在、保险库元数据并发修改、附件 ID 已存在且内容不同 |
| `rate_limited` | 429 | 登录、prelogin、注册、管理登录尝试过多 |
| `server_error` | 500 | 内部错误（细节只写服务端日志） |
| `too_large` | — | 常量已定义，目前没有接口返回它 |

框架层面的拒绝**不是** `ApiError` JSON，而是 axum 的纯文本：JSON 无法解析（400 / 422）、缺少 `Content-Type: application/json`（415）、请求体超过上限（413）、路径或查询参数类型错误（400）。`npw-core` 把非 JSON 的错误映射为 `code = "http"`。

## 3. 认证与会话

### 3.1 注册

`POST /v1/auth/register/start`（无认证）

```json
{ "login": "alice@example.com", "invite": "ABCDEFGH-IJKLMNOP", "account_id": "<客户端生成的 UUIDv7>", "opaque_request": "<B64>" }
```

→ `{ "opaque_response": "<B64>" }`

- 限速：`register/start` 与 `register/finish` 合计每个 IP 每分钟 30 次，超过返回 429。
- `invite` 可省略：还没有账户且 `open_first_registration` 时不需要，否则必须是有效、未过期、未使用的邀请码（此步只检查不消耗）。
- 服务端以 `account_id` 的 16 字节作为 OPAQUE 凭据标识（[加密规格.md](加密规格.md) §7）。

`POST /v1/auth/register/finish`（无认证）→ `Session`

```json
{
  "login": "alice@example.com",
  "invite": "ABCDEFGH-IJKLMNOP",
  "account_id": "<同上>",
  "opaque_upload": "<B64>",
  "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4 },
  "account_salt": "<B64，16 字节>",
  "encrypted_account_key": "<B64，信封：AUK 封装 AK>",
  "public_key": "<B64，X25519 公钥 32 字节>",
  "encrypted_private_key": "<B64，信封：AK 加密 X25519 私钥>",
  "vault": { "id": "<UUIDv7>", "wrapped_key": "<B64>", "encrypted_meta": "<B64>" },
  "device": { "name": "我的笔记本", "platform": "windows", "client_version": "0.1.0" }
}
```

- 校验：登录名、两个 UUID、`kdf.validate()`、`account_salt` 解码后 16–64 字节、OPAQUE upload 可解析、所有 B64 字段可解码。
- 在一个事务里：消耗邀请码 → 登录名（不区分大小写，`COLLATE NOCASE`）或账户 ID 已存在则 409 → 写账户、第一个保险库（`seq = 0`、`meta_revision = 1`）、`owner` 成员关系 → 新建设备和会话 → 审计 `register`。
- 登录名在服务端去首尾空白后保存。

### 3.2 登录

`POST /v1/auth/prelogin`（无认证）`{ "login": "…" }` → `PreloginResp`

```json
{ "account_id": "<UUID>", "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4 }, "account_salt": "<B64>" }
```

不存在的登录名返回由服务端秘密派生的、稳定的伪造值（[加密规格.md](加密规格.md) §9），不能用来探测账户是否存在。客户端必须先 `kdf.validate()` 再派生。

限速与 `login/start` 相同但计数独立：每个 IP 每分钟 30 次、每个登录名每小时 20 次，超过返回 429。

`POST /v1/auth/login/start`（无认证）

```json
{ "login": "alice@example.com", "method": "password", "opaque_request": "<B64>" }
```

→ `{ "login_id": "<UUID>", "opaque_response": "<B64>" }`

- `method`：`password`（缺省）或 `recovery_code`（§12）。
- 限速（固定窗口，内存中）：每个 IP 每分钟 30 次、每个登录名（去空白、小写）每小时 20 次，超过返回 429。登录成功清除该 IP 的计数。IP 取 `X-Forwarded-For` 的第一个地址（`trust_proxy`，默认开，因为前面必有反向代理），否则取连接地址。
- 不存在的账户也返回正常形式的响应和 `login_id`（OPAQUE 伪造响应）。服务端状态存 `login_attempts`，5 分钟内有效。

`POST /v1/auth/login/finish`（无认证）

```json
{ "login_id": "<UUID>", "opaque_finalization": "<B64>", "device": { "id": "<之前的设备 ID，可省略>", "name": "…", "platform": "android", "client_version": "0.1.0" } }
```

→ `Session`；失败一律 401 `login_failed`。`login_id` 无论成败只能用一次。`device.id` 属于该账户且未吊销时复用该设备（更新名称等）；**属于该账户但已吊销时拒绝登录，返回 401 `device_revoked`**（被吊销的设备不能用内存里的 LOGIN 悄悄回来）；省略或不属于该账户时新建设备（名称截到 100 字符、平台 20、版本 40）。审计 `login` / `login_failed`。

`DeviceInfo.platform`：`windows`、`macos`、`linux`、`android`、`chrome`、`web`、`cli`。

### 3.3 会话

```json
{ "account_id": "…", "device_id": "…", "access_token": "<B64>", "refresh_token": "<B64>", "access_expires_at": 1759539600000 }
```

| | 有效期 | 说明 |
|---|---|---|
| access token | 1 小时 | 每次请求的 bearer；服务端只存其 SHA-256 |
| refresh token | 30 天 | `POST /v1/auth/refresh` `{ "refresh_token": "…" }`（无认证）→ 新的 `Session`；旧 refresh token 立即作废（无论是否过期），旧 access token 自然过期 |

- 设备被吊销后，它的 access token 和 refresh token 都返回 401 `device_revoked`（吊销不删除会话，会话到期后按普通过期清理）。
- `POST /v1/auth/logout`（用户）→ `{}`：删除本设备的所有会话。
- 用 access token 的请求每 5 分钟最多更新一次设备的 `last_seen_at`。
- `npw-core`：access token 离过期不到 1 分钟时先 refresh；请求得到 401 `unauthorized`（或 refresh 得到 `unauthorized`）时，如果本机处于解锁状态（内存里有 LOGIN），静默重新走一遍 OPAQUE 登录（带上本机的设备 ID）。得到 `device_revoked`（任何请求、refresh 或重新登录）时**不再重试**：本机视为丢失，`npw-core` 立即在本地退出并清除该账户的一切——账户状态、Secret Key、会话、整个本地副本（含未推送的修改）、缓存的附件——然后返回 `device_revoked` 错误；之后宿主调用 `sign_out` 也会成功。

## 4. 账户

| 方法 | 路径 | 认证 | 请求 | 响应 |
|---|---|---|---|---|
| GET | `/v1/account` | 用户 | — | `AccountResp` |
| POST | `/v1/account/password/start` | 用户 | `{ "opaque_request" }` | `{ "opaque_response" }` |
| POST | `/v1/account/password/finish` | 用户 | `ChangePasswordFinishReq` | `{}` |
| GET | `/v1/account/audit` | 用户 | — | `[AuditEntry]` |

`AccountResp`：

```json
{
  "account_id": "…", "login": "alice@example.com",
  "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4 }, "account_salt": "<B64>",
  "encrypted_account_key": "<B64>", "public_key": "<B64>", "encrypted_private_key": "<B64>",
  "vaults": [
    { "id": "…", "wrapped_key": "<B64>", "encrypted_meta": "<B64>", "meta_revision": 1, "seq": 57, "role": "owner", "created_at": 1759536000000 }
  ],
  "created_at": 1759536000000
}
```

`encrypted_account_key_recovery` 只在设置了恢复码时出现（目前不会）。`vaults[].wrapped_key` 是**该成员**的那一份 VK 封装；`seq` 是保险库当前的最大序号。

改主密码：`password/start` 与注册第一步相同（凭据标识 = account_id）；`password/finish`：

```json
{ "opaque_upload": "<B64>", "kdf": { … }, "account_salt": "<B64，新盐>", "encrypted_account_key": "<B64，新 AUK 封装的同一个 AK>" }
```

服务端校验 `kdf`、`account_salt`（可解码且 16–64 字节）、`encrypted_account_key`（可解码且非空）——校验在替换任何东西之前，不合格返回 400——然后替换 OPAQUE 记录、KDF 参数、盐和 `encrypted_account_key`，**删除本账户其他设备的所有会话**（它们要用新密码重新登录），向该账户推送 `account_changed`，审计 `password_change`。

客户端（`npw-core` `apply_account_resp`）不无条件接受 `AccountResp` 里的 `kdf` / `account_salt` / `encrypted_account_key`：参数必须通过 `kdf.validate()`、盐 16–64 字节、封装的 AK 可解码，否则保留本地的并在 `SyncReport.account_key_update_refused` 报告；接受新值时把上一份**确认能解锁**的值留作备用，离线解锁先试当前的、再试备用的；当前的值在本机成功解锁一次后丢弃备用。

审计日志：最近 500 条，新的在前，`{ "at", "action", "device_id", "ip", "detail" }`。账户可见的 `action`：`register`、`login`、`login_failed`、`vault_create`、`device_revoke`、`password_change`、`import`（原子推送写入了条目，`detail` = `N items`）、`purge`。

## 5. 保险库

| 方法 | 路径 | 认证 | 请求 | 响应 |
|---|---|---|---|---|
| POST | `/v1/vaults` | 用户 | `{ "id", "wrapped_key", "encrypted_meta" }` | `{}`；ID 已存在 409 |
| PUT | `/v1/vaults/{vault}/meta` | 用户 | `{ "encrypted_meta", "base_revision" }` | `{}` |

- 新保险库 `seq = 0`、`meta_revision = 1`，调用者成为 `owner`，向该账户推送 `account_changed`，审计 `vault_create`。
- 改元数据（名称、图标）用乐观并发：`base_revision` 必须等于当前 `meta_revision`，否则 409；成功后 `meta_revision + 1`，并向该账户推送 `account_changed` 事件。
- 删除保险库没有接口。所以 `GET /v1/account` 里少了一个保险库时，客户端**不会**清空它的本地副本：保留全部条目和未推送的修改，暂停同步该保险库，并在 `SyncReport.vaults_missing_on_server` 报告；保险库重新出现时恢复同步（服务端 `seq` 小于本地时全量对账）。

## 6. 条目与同步

服务端对每个保险库维护单调递增的 `seq`，对每个条目维护修订号（从 1 开始）。**修订只追加**：编辑、移入回收站、从回收站恢复都是新修订；只有 §6.5 的永久删除会删掉行。

### 6.1 拉取变更

`GET /v1/vaults/{vault}/changes?since=<seq>&limit=<n>`（用户；非成员 404）→ `ChangesResp`

- `since` 缺省 0，`limit` 缺省 500，限制在 1–1000。
- 返回 `seq > since` 的条目的**当前修订**（每个条目最多一条，中间修订不返回），按 `seq` 升序。

```json
{
  "items": [
    { "item_id": "…", "revision": 3, "seq": 58, "deleted": false, "format_major": 1,
      "wrapped_key": "<B64>", "ciphertext": "<B64>", "hash": "<hex>", "updated_at": 1759536000000, "device_id": "…" }
  ],
  "next_seq": 58,
  "has_more": false,
  "vault_seq": 60,
  "purged": ["<item_id>"]
}
```

| 键 | 说明 |
|---|---|
| `items[]` | `ItemRecord`。`deleted` 为 `false` 时省略；`hash` = SHA-256(`wrapped_key` 字节 ‖ `ciphertext` 字节) 的 hex，客户端收到后重算比对；`updated_at` 是该修订写入服务端的时间；`device_id` 是写入它的设备 |
| `has_more` | 返回条数等于 `limit` |
| `next_seq` | 下一页的 `since`。`has_more` 时是最后一条的 `seq`；否则是 `max(vault_seq, 最后一条的 seq)`，即可以直接记为“已同步到” |
| `vault_seq` | 保险库当前最大序号 |
| `purged` | 墓碑 `seq` 落在这一页范围内的永久删除条目 ID：`has_more` 时为 `since < seq ≤ next_seq`，最后一页为 `seq > since`。按 `next_seq` 逐页拉取时每个墓碑恰好送达一次。客户端据此删掉本地副本，而不是把“服务端没有了”当作服务端丢数据去重新上传（全量对账时汇总所有页的墓碑）。为空时省略 |

### 6.2 推送

`POST /v1/vaults/{vault}/items/batch`（用户）

```json
{
  "items": [
    { "op_id": "<客户端生成，≤ 100 字节>", "item_id": "<UUID>", "base_revision": 2, "deleted": false,
      "format_major": 1, "wrapped_key": "<B64>", "ciphertext": "<B64>" }
  ],
  "atomic": false
}
```

→ `PushResp`：

```json
{
  "results": [
    { "op_id": "…", "item_id": "…", "status": "ok", "revision": 3, "seq": 61 },
    { "op_id": "…", "item_id": "…", "status": "conflict", "current_revision": 4 },
    { "op_id": "…", "item_id": "…", "status": "rejected", "reason": "item too large" }
  ],
  "vault_seq": 61
}
```

`results` 与 `items` 一一对应、顺序相同。每条的处理：

1. **逐条校验**（不合格 → `rejected` + `reason`）：同一请求里 `item_id` 重复（`item appears twice in one request`）、`item_id` 不是 UUID（`bad item id`）、`op_id` 为空或超过 100 字节（`bad op id`）、`base_revision < 0` 或 `format_major = 0`（`bad revision or format`）、base64 错（`bad base64`）、`wrapped_key` 或 `ciphertext` 为空（`empty ciphertext`）、两者解码后合计超过 `max_item_kb`（默认 1024 KiB，`item too large`）。超过 1000 条整个请求 400。
2. 不是保险库成员 → 整个请求 404。
3. 在一个事务里依次处理：
   - **幂等**：同一账户在同一保险库里的 `op_id` 已处理过 → 直接返回当时的结果（`ok`、`item_id`、当时的 `revision`、`seq`），不再写入。客户端重试同一操作不会产生重复修订。幂等记录按（保险库，账户，`op_id`）区分：别的账户或别的保险库用了相同的 `op_id` 不影响本次写入；同一账户同一保险库用同一 `op_id` 写**另一个**条目 → `rejected`（`op id already used for another item`），绝不把它当作“已完成”。
   - **乐观并发**：条目当前修订号（不存在为 0）≠ `base_revision` → `conflict` + `current_revision`。客户端应拉取、合并、以新的 `base_revision` 和**新的 `op_id`** 重推。`base_revision = 0` 表示新建。
   - 否则：`revision = 当前 + 1`，`seq = 保险库 seq + 1`，追加修订、更新条目头、记录 `op_id`。新建（当前为 0）时顺便删除该条目的永久删除墓碑（条目被重新创建）。
4. `atomic: true`（导入）：任何一条校验不合格 → 其余全部 `rejected`（`batch aborted`），什么都不写；任何一条 `conflict` → 回滚，原本 `ok` 的改成 `rejected`（`batch aborted`）。全部成功时审计 `import`。
5. 有写入时向保险库所有成员推送 `vault_changed` 事件（`seq` = 本次之后的 `vault_seq`）。

“删除”（移入回收站）就是一次 `deleted: true` 的推送，仍然携带完整密文；从回收站恢复是 `deleted: false` 的新修订。服务端不解释 `deleted` 的变化，也不校验密文内容。

### 6.3 摘要

`GET /v1/vaults/{vault}/digest`（用户）→ `{ "digest": "<hex>", "count": 120, "vault_seq": 61 }`

`digest` = `vault_digest`：对保险库里每个条目的当前修订（**包括回收站里的**，不含已永久删除的），按 `item_id` 字符串升序，拼接 `item_id ‖ 0x00 ‖ revision（i64 大端）‖ deleted（1 字节）‖ hash（hex ASCII）`，取 SHA-256 的 hex。客户端用本地保存的服务端修订头算同一个值比较。`count` 是条目数。

### 6.4 修订历史

| 方法 | 路径 | 响应 |
|---|---|---|
| GET | `/v1/vaults/{vault}/items/{item}/revisions` | `{ "revisions": [ { "revision", "deleted"?, "created_at", "device_id", "size", "hash" } ] }`，新的在前；`size` = 两段密文字节数之和；没有任何修订 404 |
| GET | `/v1/vaults/{vault}/items/{item}/revisions/{rev}` | 该修订的 `ItemRecord`（`seq` 是写入它时的序号）；不存在 404 |

“恢复旧版本”在客户端完成：解密旧修订，作为新修订推送（历史不改写）。

### 6.5 永久删除（清空回收站）

`POST /v1/vaults/{vault}/purge`（用户）`{ "item_ids": ["…"] }` → `{ "purged": ["…"] }`

- 只处理**当前在回收站**（最新修订 `deleted = true`）的条目，其他 ID 静默跳过。
- 每个被删条目：删除它的全部修订、条目头、附件记录和附件文件；保险库 `seq + 1`，写一条墓碑 `(vault_id, item_id, seq, at)`（已有则更新），供 §6.1 的 `purged` 使用。审计 `purge`。
- 服务端从不自动清空回收站，必须由客户端发起（界面要求用户确认）。
- 有条目被删除时向保险库所有成员推送 `vault_changed`；其他设备在同步时从 `purged` 得知。

### 6.6 同步语义（`npw-core` `sync.rs`）

客户端对每个保险库：

1. `GET /v1/server-info` 取 `epoch`，`GET /v1/account` 取各保险库的 `seq` 并更新密钥和元数据。
2. 需要全量对账的情况：本地记录的 `epoch` 非空且与服务端不同（服务端从备份恢复过）、服务端 `seq` 小于本地已同步到的 `seq`（回滚）、或第 4 步摘要不一致。全量对账 = 从 `since=0` 拉取全部条目头逐条比较：服务端缺失的（且不在墓碑里）或停在本设备见过的旧修订上的，以本设备的版本作为新修订重新推送；历史分叉的，无 base 合并、两边的值都保留。
3. 否则增量拉取（`since` = 本地 `seq`，每页 500，直到 `has_more = false`），把远端修订并入本地：收到的修订号小于本地已知的视为回滚，计数并忽略；本地有未推送修改时三方合并（[条目格式.md](条目格式.md) §7）；解不开的记录原样保存并报告，不合并。然后推送待发修改（每批 100 条，`atomic: false`）；有 `conflict` 就再拉取合并、再推送，最多 8 轮。
4. `GET …/digest` 与本地计算的摘要比较。不一致而摘要响应里的 `vault_seq` 大于本地已同步到的 `seq`（拉取之后服务端又有写入：其他设备，或本机刚推送的）时，先再拉取、推送一轮再比较（每次同步每个保险库最多比较 3 次）；在同一 `seq` 上仍不一致，或 3 次都不一致，才全量对账后再推一次。
   - `GET /v1/account` 不再列出的保险库跳过（本地副本保留，见 §5）。
5. 保存服务端 `epoch` 和同步时间。

不变量：本地待发修改只有在服务端确认了**这一次**操作（相同 `op_id`）后才删除；合并从不丢值；无法解密的记录不会被覆盖。

## 7. 附件

| 方法 | 路径 | 认证 | 请求 | 响应 |
|---|---|---|---|---|
| PUT | `/v1/vaults/{vault}/attachments/{att}?item=<item_id>` | 用户 | 请求体 = 加密后的 blob（[加密规格.md](加密规格.md) §8），`application/octet-stream` | `{ "id", "size", "sha256" }` |
| GET | `/v1/vaults/{vault}/attachments/{att}` | 用户 | — | blob，`application/octet-stream` |

- `att`、`item` 必须是 UUID，blob 不能为空，大小上限 `max_attachment_mb`（默认 100 MiB）。
- blob 不可变：同一个 `att` 再次上传相同内容（SHA-256 相同）直接返回成功（幂等），内容不同返回 409。
- 附件 ID 全局唯一：同一个 `att` 已存在于**另一个**保险库时返回 409。
- 服务端先写到每次上传独有的临时文件 `data/attachments/<att>.<随机>.part`、刷盘、读回比对 SHA-256，然后在数据库锁内检查该 ID 是否已登记：已登记（并发上传中别人先完成）则丢弃临时文件、按上一条处理；否则原子改名为 `data/attachments/<att>` 并登记所属保险库、条目、大小、SHA-256。所以并发上传同一 ID 时只有一个成功，文件内容与登记的校验和一致。服务端不检查条目是否存在，也不解密。
- 客户端流程：生成附件 ID（UUIDv4）和 FK → 加密 → 上传 → 比对返回的 `sha256` → 把附件元数据（含 FK 和 `blob_sha256`）写进条目内容，随下一次同步推送。下载后先比对 `blob_sha256` 并解密成功，**才**存入本地缓存；不一致返回错误、不缓存。本地缓存的副本校验失败时丢弃并重新下载。
- 附件只在其条目被永久删除时删除（§6.5）。

## 8. 设备

| 方法 | 路径 | 认证 | 响应 |
|---|---|---|---|
| GET | `/v1/devices` | 用户 | `[DeviceRecord]`，按最后在线时间倒序 |
| DELETE | `/v1/devices/{device}` | 用户 | `{}`；不存在或已吊销 404 |

`DeviceRecord`：`{ "id", "name", "platform", "client_version", "created_at", "last_seen_at", "revoked_at"?, "current" }`，`current` 表示发出请求的设备。吊销：设置 `revoked_at`（设备行保留）、向该账户推送 `device_revoked` 事件、审计 `device_revoke`。该设备的会话**不删除**：它的 access / refresh token 此后都返回 401 `device_revoked`，会话到期后按普通过期清理。登录时出示已吊销的设备 ID 也返回 `device_revoked`（§3.2）。

`npw-core` 收到 `device_revoked` 后不重新登录，而是在本地退出并清除该账户的全部本地数据（§3.3）——吊销是给丢失的设备用的。用户在同一台设备上重新输入 Secret Key 登录会得到一个新设备。

## 9. 事件（WebSocket）

`GET /v1/events?token=<access token>`，WebSocket 升级。token 放在查询参数里（浏览器的 WebSocket 不能设请求头），升级前校验，无效返回 401 JSON。

服务端发送文本消息，每条是一个 `Event` JSON：

```json
{ "kind": "vault_changed", "vault_id": "…", "seq": 61 }
{ "kind": "account_changed" }
{ "kind": "device_revoked", "device_id": "…" }
```

| 事件 | 何时 | 客户端 |
|---|---|---|
| `vault_changed` | 推送写入了条目（发给该保险库所有成员账户的连接，包括写入者自己） | 同步该保险库 |
| `vault_changed` | 永久删除了条目（§6.5） | 同步该保险库 |
| `account_changed` | 保险库元数据被修改、新建了保险库、改了主密码；或服务端事件队列溢出（连接落后太多，发它代替丢失的事件） | 全部同步 |
| `device_revoked` | 该账户有设备被吊销 | 如果是本设备：清除会话；服务端发完这条后关闭本设备的连接 |

- 服务端每 30 秒发一次 Ping；客户端关闭或出错即结束。
- 事件只是“该同步了”的提示，不携带数据；断线期间客户端每隔几分钟轮询兜底。

## 10. 管理 API

供内嵌的管理后台使用，与用户账户无关。认证：`POST /v1/admin/login` 得到的 token，`Authorization: Bearer <token>`；会话只在服务端内存中（12 小时，重启失效）。管理口令用 `nyapassword-server admin-password` 设置（或首次启动时的 `NYAPASSWORD_ADMIN_PASSWORD`），TOTP 用 `nyapassword-server admin-totp` 或管理后台“管理员”页开启。修改管理员密码、开关 TOTP 都要在请求里再带一次当前管理员密码，错误时 403 `forbidden`。

| 方法 | 路径 | 请求 | 响应 / 说明 |
|---|---|---|---|
| POST | `/v1/admin/login` | `{ "password", "totp"? }` | `{ "token", "expires_at" }`。每 IP 15 分钟 10 次，超过 429；未设口令 403 `forbidden`；错误 401 `login_failed`。审计 `admin_login` / `admin_login_failed` |
| GET | `/v1/admin/health` | — | `Health`：版本、启动时间、`db_ok`（`PRAGMA quick_check`）、账户 / 有效设备 / 条目 / 修订 / 附件数、附件和数据库字节数 |
| GET | `/v1/admin/accounts` | — | `[{ "account_id", "login", "created_at", "items", "devices": [DeviceRecord] }]`，`items` 不含回收站 |
| DELETE | `/v1/admin/devices/{device}` | — | `{}`，吊销任意设备（不存在也返回成功），推送 `device_revoked` |
| GET | `/v1/admin/invites` | — | 最近 50 个邀请码的 `{ "code": "", "expires_at", "used_at"? }`（服务端只存哈希，`code` 恒为空） |
| POST | `/v1/admin/invites` | `{ "hours" }` | `{ "code", "expires_at" }`，有效期限制在 1–720 小时；明文邀请码只在这里出现一次 |
| GET | `/v1/admin/audit` | — | 全部账户的最近 500 条审计，`detail` 后附 ` [账户 ID 前 8 位]` |
| GET | `/v1/admin/backup` | — | `BackupStatus`：设置（含 `recipient_info`：每个接收者一项，顺序同 `recipients`，没有记录时 `label` 为空、`created_at` 为 0；含通知渠道的配置；已设置的 `smtp_password`、`telegram_bot_token` 显示为掩码 `••••••••`，即 `npw_api::admin::SECRET_MASK`）、服务端 age 公钥、每个目标及其最后成功 / 尝试时间和错误、最近 30 次备份、20 次演练、最后成功时间、最后一次手动演练确认时间、是否有未备份的变更 |
| PUT | `/v1/admin/backup/settings` | `BackupSettings` | `{}`。`recipients` 必须都是 age X25519 公钥（`age1…`），`daily_hour_utc ≤ 23`，`debounce_minutes ≤ 1440`。`smtp_password` / `telegram_bot_token` 原样传回掩码表示保留已存的值，空字符串表示清除。`notify.off` / `notify.muted_events` 只能是已知的渠道 / 事件名，否则 400。`recipient_info` 可省略（旧版后台）：已有接收者保留存储的标签和时间，新接收者记当前时间；带了非空 `label` 就更新标签。接收者有增减时写审计 `admin_recipient_add` / `admin_recipient_remove`。整个设置用 `server.key` 加密后存库 |
| PUT | `/v1/admin/backup/targets/{id}` | `BackupTarget` | 保存后的目标（`secret` 清空，`has_secret` 表示是否有密钥）。名称、endpoint 必填；OSS 必须有 bucket；`fs` 必须是绝对路径；其他必须是 http(s) URL。`secret` 为空表示保留原密钥；密钥用 `server.key` 加密存库 |
| DELETE | `/v1/admin/backup/targets/{id}` | — | `{}` |
| POST | `/v1/admin/backup/targets/{id}/test` | — | `{ "steps": [{ "step": "write"/"read"/"delete", "ok", "error"?, "expected_to_fail"? }] }`：写、读、删一个探测对象；防删模式下删除失败才是对的 |
| POST | `/v1/admin/backup/test-target` | `BackupTarget` | 同上一行的 `{ "steps" }`，但测试的是请求里的（未保存的）目标，校验规则同保存；`secret` 为空时用同 `id` 的已存目标的密钥。“添加目标”向导用它在保存前测试 |
| POST | `/v1/admin/backup/recipients` | `{ "recipient": "age1…", "label" }` | 登记一个离线恢复密钥（已存在时只更新标签），返回 `[RecipientInfo]`。不是 age X25519 公钥或是服务器自己的公钥时 400 |
| DELETE | `/v1/admin/backup/recipients/{recipient}` | — | 删除这个接收者，返回 `[RecipientInfo]`（不存在也成功）。已有的备份不受影响 |
| GET | `/v1/admin/backup/targets/{id}/objects` | — | `[{ "name", "size", "modified_at" }]`，新的在前（时间取自对象名） |
| POST | `/v1/admin/backup/run` | — | `BackupRun`（立即备份到所有启用的目标） |
| POST | `/v1/admin/backup/drill` | `{ "target_id"? }` | `DrillRun`（下载最新备份、用服务端 age 私钥解密、`integrity_check`、比对条目数和修订数、抽查 20 个附件存在） |
| POST | `/v1/admin/backup/manual-drill` | — | `{}`，记录“已用离线私钥手动演练过” |
| POST | `/v1/admin/notify/test` | 可选 `{ "channel"?, "notify"? }` | `{ "failed": ["渠道: 错误"] }`。没有请求体：用已存设置向所有开启的渠道发测试通知。`channel`（`webhook` / `telegram` / `bark` / `email`）：只发这一个，不管开关；未配置时 `failed` 为 `["<渠道>: not configured"]`；未知渠道 400。`notify`：用这份未保存的设置（掩码表示用已存的密钥） |
| GET | `/v1/admin/security` | — | `{ "totp_enabled" }` |
| POST | `/v1/admin/password` | `{ "current", "new" }` | `{}`。新密码至少 12 个字符（400）；当前密码错误 403。成功后除本会话外的管理会话全部失效。审计 `admin_password_change` |
| POST | `/v1/admin/totp/setup` | `{ "password" }` | `{ "secret", "uri" }`：新的 TOTP 密钥（base32）和 `otpauth://` 地址；此时还没有生效 |
| POST | `/v1/admin/totp/enable` | `{ "password", "secret", "code" }` | `{}`。`code` 必须是这个密钥当前（±30 秒）的验证码，否则 400，什么都不变。审计 `admin_totp_on` |
| POST | `/v1/admin/totp/disable` | `{ "password" }` | `{}`。审计 `admin_totp_off` |

`BackupTarget`：

```json
{ "id": "oss-1", "kind": "oss", "name": "阿里云 OSS", "enabled": true, "protect_mode": true,
  "endpoint": "https://oss-cn-hangzhou.aliyuncs.com", "bucket": "example-backup", "root": "nyapassword",
  "username": "<AccessKey ID>", "secret": "<只在请求里>", "has_secret": true }
```

`kind`：`oss`、`webdav`、`fs`（服务器上的目录，如 NAS 挂载点）。`protect_mode`：凭据没有删除权限，服务端不对该目标做保留清理（交给存储端生命周期规则）。

`BackupSettings`：`{ "retention": { "recent": 48, "daily": 30, "weekly": 12, "monthly": 24 }, "recipients": ["age1…"], "recipient_info": [{ "recipient": "age1…", "label": "保险柜里的纸", "created_at": 1791158400000 }], "debounce_minutes": 10, "daily_hour_utc": 19, "notify": { "webhook_url", "telegram_bot_token", "telegram_chat_id", "bark_url", "smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from", "smtp_to", "off": ["bark"], "muted_events": ["stale"] } }`。

- `recipients` 是权威列表（备份加密给服务器自己的公钥 + 这些公钥）；`recipient_info` 只是标签和登记时间。
- `notify.off`：已配置但关掉的渠道。`notify.muted_events`：不发通知的事件：`backup_failed`（某个目标写入或读回失败，含连不上）、`check_failed`（自动备份校验失败）、`stale`（超过 26 小时没有成功的备份）。两者缺省为空 = 全部开启。
- `daily_hour_utc` 是 UTC 小时；管理后台按浏览器时区显示和选择。

备份归档格式见 [加密规格.md](加密规格.md) §11。

## 11. 为共享预留的字段

v1 只有单账户、每个保险库只有一个成员，但数据结构已经按“多成员保险库”设计，加共享不需要迁移数据：

| 位置 | 预留内容 |
|---|---|
| `VaultInfo.role` | v1 恒为 `owner`；计划中的 `member`、`reader` |
| `VaultInfo.wrapped_key` | 已是“该成员的那一份”VK 封装（数据库 `vault_members(vault_id, account_id, role, wrapped_key)`，主键为保险库 + 账户） |
| `AccountResp.public_key` / `encrypted_private_key` | 每个账户注册时就有 X25519 密钥对，共享时用 HPKE 把 VK 封装给成员公钥 |
| 权限检查 | 服务端所有保险库接口都按“是否成员”判断（`require_member`），事件发给保险库的所有成员账户 |
| AAD | `npw/vault-key/v1` 只绑定保险库 ID，不绑定账户，同一 VK 可以封装给多个成员 |

尚未定义：邀请 / 移除成员的接口、按角色限制写入、HPKE 封装格式（会使用新的信封算法号或新的 AAD 标签，见加密规格 §5）。

## 12. 已定义但未实现 / 未使用

| 项 | 状态 |
|---|---|
| 恢复码：`ReRegisterStartReq`（文档注释提到 `/v1/account/recovery/start`）、`SetRecoveryFinishReq`（`/v1/account/recovery/finish`）、`AccountResp.encrypted_account_key_recovery`、数据库 `opaque_recovery` 列、`feature::RECOVERY_CODE` | 路由**未注册**，功能不宣告。`login/start` 接受 `method: "recovery_code"`，但因为没有办法设置恢复码，它的行为与“账户不存在”相同 |
| 错误码 `too_large` | 未使用（超限由框架返回 413 纯文本，单条条目过大是推送结果里的 `rejected`） |
| 服务端配置 `keep_revisions` | 未使用：修订目前全部保留，没有修订清理。有意不实现：修剪会删掉旧密码的唯一服务端副本，并让全量对账的“服务端历史里有本机的头”（`server_has`）判断失效，使本来只是“服务端更新”的条目被当成历史分叉做无 base 合并 |
| `Field.generator` 等 | 见条目格式 |
