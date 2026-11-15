# peer-device 原型

「设备连接」的传输与授权内核：身份、一次性配对码、双向 mTLS 指纹固定、连接票据、工作区策略、请求桥接。

**不含** DSH 会话桥接与 UI——那属于插件阶段。

## 设计约束（重要）

**传输层只认「可达的 IPv4 地址」**，不包含任何 tailscale / VPN / 特定网络的判断。

绑定 `0.0.0.0`，谁连上算谁；是否允许由**配对码 + 证书指纹 + 票据**决定，而不是由网络类型决定。

tailnet 的作用只是「每台机器恰好都有一个稳定地址」，和 192.168.x.x 没有区别。启动时会把所有网卡地址列出来给你选：

```
可达地址   :
    172.18.0.1 (singbox_tun)
    100.64.0.1 (Tailscale)
    192.168.1.5 (以太网)
```

## 命令

```bash
npm install

# 被控端
node main.js allow      --name srv --port 41234 --workspaces "D:\proj1,D:\proj2"
node main.js policy     --name srv --device <设备id前缀> --mode all
node main.js policy     --name srv --device <设备id前缀> --mode selected --workspaces <wsid,wsid>
node main.js revoke     --name srv --device <设备id前缀>
node main.js status     --name srv

# 控制端
node main.js pair       --name cli --addr <ip>:41234 --code <8位码>
node main.js hello      --name cli --addr <ip>:41234
node main.js workspaces --name cli --addr <ip>:41234
```

## 三层认证

```
第 1 层：配对码    8 位 / 120 秒 / 一次性       → 建立信任
第 2 层：证书指纹  双向 mTLS，比对配对时固定值   → 确认"还是那台机器"
第 3 层：连接票据  HMAC-SHA256，绑定指纹与设备   → 确认"这次连接被授权"
```

票据载荷：

```json
{ "v":1, "sub":"<控制端 deviceId>", "cfp":"<该设备证书指纹>", "iss":"<被控端 deviceId>",
  "iat":…, "exp":…, "jti":"<随机>" }
```

签名：`HMAC-SHA256(base64url(payload), masterSecret)`，比较时用 `timingSafeEqual`。

## 已验证的行为

| # | 场景 | 结果 |
|---|---|---|
| 1 | 错误配对码 | `code-mismatch` 拒绝 |
| 2 | 正确配对码 | 成功，签发 24h 票据 |
| 3 | 重放同一码 | `code-used` 拒绝 |
| 4 | 票据 + 指纹认证 | 通过 |
| 5 | **篡改票据** | `ticket-bad-signature` 拒绝 |
| 6 | 恢复票据 | 通过 |
| 7 | 全量策略下列工作区 | 返回 2 个 |
| 8 | 改 `selected` 策略 | 只返回 1 个 |
| 9 | 撤销授权后重连 | `revoked` 拒绝 |
| 10 | 请求入队 | `queue` 记录 method/stage/来源设备 |

## 协议

TLS 之上按行分隔 JSON。

### 配对

```
→ {"type":"pair-request","code":"12345678","deviceId":"…","displayName":"cli","fingerprint":"<sha256 der>"}
← {"type":"pair-accepted","deviceId":"…","displayName":"srv","fingerprint":"…","ticket":"<body.mac>","ticketExpiresAt":…}
← {"type":"pair-rejected","reason":"code-mismatch|code-used|code-expired|no-active-code"}
```

### 认证 + 请求

```
→ {"type":"hello","deviceId":"…","displayName":"cli","ticket":"…"}
← {"type":"welcome","deviceId":"…","displayName":"srv","workspaces":2}
← {"type":"rejected","reason":"not-granted|revoked|fingerprint-mismatch|ticket-*"}

→ {"type":"request","deviceId":"…","ticket":"…","requestId":"…","method":"workspaces.list","payload":null}
← {"type":"result","requestId":"…","ok":true,"workspaces":[…],"policy":{…}}
← {"type":"result","requestId":"…","ok":false,"error":"unknown-method|not-allowed"}
```

支持的方法：`ping`、`workspaces.list`、`workspaces.get`。

## 与 Qoder 的对应

| Qoder | 本原型 |
|---|---|
| `peer_devices` | `peers`（含 `fingerprint`、`ticket`） |
| `peer_grants` | `grants`（含 `revokedAt`、`policy`） |
| `peer_access_policies` | `grants.policy`（mode/ids/syncAllSessions） |
| `peer_ingress_queue` | `queue`（requestId/method/stage） |
| `X-Peer-Link-Ticket` | `ticket` 字段 |
| `X-Peer-Relay-Owner`（云中继） | **不实现**：直连即可 |

## 局限

- 票据 24h 过期需重新配对（插件阶段要做续签）
- 无心跳、无断线重连
- 工作区只是路径字符串，没有和 DSH 会话绑定
- 请求队列只在内存 + 落盘，没有并发控制
- 明文存私钥（依赖文件系统权限）

## 下一步

1. **DSH 插件化**：协议层不变，加 Host 侧监听 + Client 侧 UI
2. **会话桥接**：`session.list` / `session.open` / `session.send` 三个方法
3. **票据续签**：`ticket.refresh`
4. **共享状态目录**：`desktop` 与 `web` 两个 profile 共用一份身份
