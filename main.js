// Peer device prototype — ticket / policy / bridge
//
// 设计约束：
//   * 传输层只认「可达的 IPv4 地址」，不感知 tailscale / VPN / 任何特定网络。
//     tailnet 只是一个恰好每台机器都有稳定地址的普通 LAN，代码里不含任何相关判断。
//   * 绑定 0.0.0.0，任何来源能连上都能配对（是否允许由配对码 + 指纹决定）。
//
// 命令：
//   node main.js allow   --name srv --port 41234 [--workspaces "D:\a,D:\b"]
//   node main.js pair    --name cli --addr 127.0.0.1:41234 --code 12345678
//   node main.js hello   --name cli --addr 127.0.0.1:41234
//   node main.js workspaces --name cli --addr 127.0.0.1:41234
//   node main.js policy  --name srv --device <deviceId 前缀> --mode selected --workspaces <id,id>
//   node main.js policy  --name srv --device <deviceId 前缀> --mode all
//   node main.js revoke  --name srv --device <deviceId 前缀>
//   node main.js status  --name srv

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import selfsigned from "selfsigned";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(HERE, "data");
const CODE_TTL_MS = 120_000;
const TICKET_TTL_MS = 24 * 3600 * 1000;
const MAX_QUEUE = 500;
// ---------------- 基础工具 ----------------

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true;
      out[k] = v;
    } else out._.push(a);
  }
  return out;
}

const b64u = (buf) => Buffer.from(buf).toString("base64url");
const fpOf = (rawDer) => crypto.createHash("sha256").update(rawDer).digest("hex");
const fpOfPem = (pem) => fpOf(new crypto.X509Certificate(pem).raw);
const short = (s) => (s ? s.slice(0, 16) + "…" : "");

function lanAddresses() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === "IPv4" && !a.internal) out.push(`${a.address} (${name})`);
    }
  }
  return out;
}

// ---------------- 状态 ----------------

function stateFile(name) {
  return path.join(DATA_DIR, `${name}.json`);
}

function loadState(name) {
  const f = stateFile(name);
  if (fs.existsSync(f)) {
    const st = JSON.parse(fs.readFileSync(f, "utf8"));
    st.queue = st.queue || [];
    return st;
  }
  const pems = selfsigned.generate(
    [{ name: "commonName", value: `peer-${name}-${crypto.randomUUID().slice(0, 8)}` }],
    { keySize: 2048, days: 3650, algorithm: "sha256" }
  );
  const st = {
    name,
    deviceId: crypto.randomUUID(),
    key: pems.private,
    cert: pems.cert,
    fingerprint: fpOfPem(pems.cert),
    masterSecret: crypto.randomBytes(32).toString("hex"),
    peers: {},
    grants: {},
    pairing: null,
    workspaces: [],
    queue: [],
    createdAt: Date.now(),
  };
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(f, JSON.stringify(st, null, 2));
  return st;
}

function saveState(st) {
  fs.writeFileSync(stateFile(st.name), JSON.stringify(st, null, 2));
}

// ---------------- 票据 ----------------

function sign(payloadB64, secretHex) {
  return crypto.createHmac("sha256", Buffer.from(secretHex, "hex")).update(payloadB64).digest("base64url");
}

function issueTicket(st, grant) {
  const payload = {
    v: 1,
    sub: grant.deviceId,                       // 票据持有者
    cfp: grant.fingerprint,                    // 绑定的客户端证书指纹
    iss: st.deviceId,
    iat: Date.now(),
    exp: Date.now() + TICKET_TTL_MS,
    jti: crypto.randomUUID(),
  };
  const body = b64u(JSON.stringify(payload));
  return { ticket: `${body}.${sign(body, st.masterSecret)}`, expiresAt: payload.exp, payload };
}

function verifyTicket(st, grant, token, peerFp) {
  if (typeof token !== "string" || !token.includes(".")) return { ok: false, reason: "ticket-malformed" };
  const [body, mac] = token.split(".");
  const expect = sign(body, st.masterSecret);
  const a = Buffer.from(mac || "");
  const b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { ok: false, reason: "ticket-bad-signature" };

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "ticket-malformed" };
  }
  if (payload.v !== 1) return { ok: false, reason: "ticket-version" };
  if (payload.iss !== st.deviceId) return { ok: false, reason: "ticket-issuer" };
  if (payload.sub !== grant.deviceId) return { ok: false, reason: "ticket-subject" };
  if (payload.cfp !== grant.fingerprint) return { ok: false, reason: "ticket-fingerprint" };
  if (peerFp && payload.cfp !== peerFp) return { ok: false, reason: "ticket-not-this-cert" };
  if (Date.now() > payload.exp) return { ok: false, reason: "ticket-expired" };
  return { ok: true, payload };
}

// ---------------- 工作区与策略 ----------------

function workspaceId(p) {
  return crypto.createHash("sha256").update(path.resolve(p)).digest("hex").slice(0, 16);
}

function allowedWorkspaces(st, grant) {
  const policy = grant.policy || { mode: "all", ids: [], syncAllSessions: false };
  const all = st.workspaces.map((p) => ({ id: workspaceId(p), name: path.basename(p), path: p }));
  if (policy.mode === "all") return all;
  return all.filter((w) => policy.ids.includes(w.id));
}

// ---------------- DSH 会话读取 ----------------

function dshSessionsDir(st) {
  const home = st.dshHome || path.join(os.homedir(), ".dsh");
  return path.join(home, "storages", "session_projcache", "sessions");
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// 会话文件命名随 DSH 版本变化：
//   旧: session-<uuid>.json
//   新: <uuid>.json
// 同目录下还混有 mnemon-run-* / mnemon-task-* 等运行态文件，必须排除。
function sessionIdFromFile(name) {
  if (!name.endsWith(".json")) return null;
  const stem = name.slice(0, -".json".length);
  const bare = stem.startsWith("session-") ? stem.slice("session-".length) : stem;
  return UUID_RE.test(bare) ? bare : null;
}

function readSessionFile(full) {
  // 文件可能带 UTF-8 BOM（Windows 上常见），JSON.parse 遇到会直接报错
  const text = fs.readFileSync(full, "utf8").replace(/^\uFEFF/, "");
  const j = JSON.parse(text);
  const rows = j?.record?.rows || j?.rows || {};
  const pick = (k) => rows[k]?.val;
  return {
    title: pick("title") || "(未命名)",
    cwd: pick("workingDirectory") || j?.record?.identity?.cwd || j?.identity?.cwd || "",
    lastPromptAt: pick("sessionListMetadata")?.lastPromptAt || 0,
  };
}

function listSessions(st, grant) {
  const dir = dshSessionsDir(st);
  if (!fs.existsSync(dir)) return [];
  const allowed = allowedWorkspaces(st, grant).map((w) => path.resolve(w.path));
  const out = [];
  for (const name of fs.readdirSync(dir)) {
    const id = sessionIdFromFile(name);
    if (!id) continue;
    const full = path.join(dir, name);
    let info;
    try {
      info = readSessionFile(full);
    } catch {
      continue;
    }
    // 策略过滤：cwd 必须落在允许的工作区里
    if (allowed.length && !allowed.some((a) => path.resolve(info.cwd).startsWith(a))) continue;
    out.push({
      id,
      title: info.title,
      cwd: info.cwd,
      updatedAt: info.lastPromptAt || fs.statSync(full).mtimeMs,
    });
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

// ---------------- socket 工具 ----------------

function sendLine(sock, obj) {
  sock.write(JSON.stringify(obj) + "\n");
}

function readLines(sock, onMessage) {
  let buf = "";
  sock.setEncoding("utf8");
  sock.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      try {
        onMessage(JSON.parse(line));
      } catch (e) {
        console.error("[warn] bad json:", e.message);
      }
    }
  });
}

// ---------------- 被控端 ----------------

function cmdAllow(args) {
  const name = args.name || "default";
  const port = Number(args.port || 41234);
  const host = args.host || "0.0.0.0";
  const st = loadState(name);
  if (args.workspaces) {
    st.workspaces = String(args.workspaces).split(",").map((s) => s.trim()).filter(Boolean);
  }
  st.dshHome = args["dsh-home"] || process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
  saveState(st);

  const code = String(crypto.randomInt(10000000, 99999999));
  const ttlMs = Math.max(30, Number(args.ttl || 120)) * 1000; // --ttl 秒，默认 120
  st.pairing = { code, expiresAt: Date.now() + ttlMs, consumed: false };
  saveState(st);

  const server = tls.createServer(
    { key: st.key, cert: st.cert, requestCert: true, rejectUnauthorized: false },
    (sock) => {
      const peerCert = sock.getPeerCertificate(true);
      const peerFp = peerCert && peerCert.raw ? fpOf(peerCert.raw) : null;

      readLines(sock, (msg) => {
        const cur = loadState(name);

        // ---- 配对 ----
        if (msg.type === "pair-request") {
          const pairing = cur.pairing;
          const ok = pairing && !pairing.consumed && Date.now() < pairing.expiresAt && msg.code === pairing.code;
          if (!ok) {
            const reason = !pairing ? "no-active-code"
              : pairing.consumed ? "code-used"
              : Date.now() >= pairing.expiresAt ? "code-expired" : "code-mismatch";
            sendLine(sock, { type: "pair-rejected", reason });
            console.log(`[pair] rejected (${reason})`);
            return;
          }
          cur.pairing = { ...pairing, consumed: true };
          cur.grants[msg.deviceId] = {
            deviceId: msg.deviceId,
            displayName: msg.displayName || "unknown",
            fingerprint: msg.fingerprint,
            grantedAt: Date.now(),
            lastSeenAt: null,
            revokedAt: null,
            policy: { mode: "all", ids: [], syncAllSessions: false },
          };
          const t = issueTicket(cur, cur.grants[msg.deviceId]);
          saveState(cur);
          console.log(`[pair] granted ${msg.displayName} (${msg.deviceId.slice(0, 8)}…) fp=${short(msg.fingerprint)}`);
          sendLine(sock, {
            type: "pair-accepted",
            deviceId: cur.deviceId,
            displayName: cur.name,
            fingerprint: cur.fingerprint,
            ticket: t.ticket,
            ticketExpiresAt: t.expiresAt,
          });
          return;
        }

        // ---- 重连（票据 + 指纹）----
        if (msg.type === "hello" || msg.type === "request") {
          const grant = cur.grants[msg.deviceId];
          if (!grant || grant.revokedAt) {
            sendLine(sock, { type: "rejected", reason: grant ? "revoked" : "not-granted" });
            console.log(`[auth] rejected: ${grant ? "revoked" : "not granted"}`);
            return;
          }
          if (!peerFp || grant.fingerprint !== peerFp) {
            sendLine(sock, { type: "rejected", reason: "fingerprint-mismatch" });
            console.log("[auth] rejected: cert fingerprint mismatch");
            return;
          }
          const tv = verifyTicket(cur, grant, msg.ticket, peerFp);
          if (!tv.ok) {
            sendLine(sock, { type: "rejected", reason: tv.reason });
            console.log(`[auth] rejected: ${tv.reason}`);
            return;
          }
          grant.lastSeenAt = Date.now();
          saveState(cur);

          if (msg.type === "hello") {
            sendLine(sock, {
              type: "welcome",
              deviceId: cur.deviceId,
              displayName: cur.name,
              workspaces: allowedWorkspaces(cur, grant).length,
            });
            console.log(`[auth] ok ${grant.displayName} (ticket + 指纹 + 授权 均通过)`);
            return;
          }

          // ---- 请求处理（bridge 的雏形）----
          const requestId = msg.requestId || crypto.randomUUID();
          const entry = {
            requestId,
            deviceId: msg.deviceId,
            method: msg.method,
            payload: msg.payload ?? null,
            receivedAt: Date.now(),
            stage: "received",
          };
          let reply;
          switch (msg.method) {
            case "ping":
              reply = { ok: true, pong: Date.now() };
              break;
            case "workspaces.list": {
              const list = allowedWorkspaces(cur, grant);
              reply = { ok: true, workspaces: list, policy: grant.policy };
              break;
            }
            case "workspaces.get": {
              const list = allowedWorkspaces(cur, grant);
              const w = list.find((x) => x.id === msg.payload?.id);
              reply = w ? { ok: true, workspace: w } : { ok: false, error: "not-allowed" };
              break;
            }
            case "session.list": {
              const sessions = listSessions(cur, grant);
              reply = { ok: true, sessions, policy: grant.policy };
              break;
            }
            case "session.open": {
              const sessions = listSessions(cur, grant);
              const s = sessions.find((x) => x.id === msg.payload?.id);
              reply = s ? { ok: true, session: s } : { ok: false, error: "not-allowed" };
              break;
            }
            default:
              reply = { ok: false, error: "unknown-method" };
          }
          entry.stage = reply.ok ? "done" : "rejected";
          cur.queue.push(entry);
          if (cur.queue.length > MAX_QUEUE) cur.queue = cur.queue.slice(-MAX_QUEUE);
          saveState(cur);
          console.log(`[req] ${grant.displayName} ${msg.method} -> ${reply.ok ? "ok" : reply.error}`);
          sendLine(sock, { type: "result", requestId, ...reply });
        }
      });

      sock.on("error", () => {});
    }
  );

  server.listen(port, host, () => {
    console.log("=== 允许连接本机 ===");
    console.log("device id  :", st.deviceId);
    console.log("cert fp    :", st.fingerprint);
    console.log("listen     :", `${host}:${port}`);
    console.log("可达地址   :");
    for (const a of lanAddresses()) console.log("   ", a);
    console.log("工作区     :", st.workspaces.length ? st.workspaces.join(", ") : "(未配置，用 --workspaces 指定)");
    console.log("配对码     :", code, `（${Math.round(ttlMs / 1000)} 秒内有效，一次性）`);
    console.log("");
  });
}

// ---------------- 控制端 ----------------

function connect(name, target, onReady) {
  const st = loadState(name);
  const [host, portStr] = target.split(":");
  const sock = tls.connect(
    { host, port: Number(portStr), rejectUnauthorized: false, key: st.key, cert: st.cert },
    () => onReady(sock, st)
  );
  sock.on("error", (e) => {
    console.error("连接失败:", e.message);
    process.exit(1);
  });
  return sock;
}

function findPeer(st, addr) {
  if (addr) {
    const hit = Object.values(st.peers).find((p) => p.address === addr);
    if (hit) return hit;
  }
  return Object.values(st.peers)[0];
}

function cmdPair(args) {
  const name = args.name || "default";
  const addr = args.addr;
  const code = String(args.code || "");
  if (!addr || !code) {
    console.error("用法: node main.js pair --name cli --addr host:port --code 12345678");
    process.exit(1);
  }
  const st = loadState(name);
  const sock = connect(name, addr, () => {
    sendLine(sock, { type: "pair-request", code, deviceId: st.deviceId, displayName: name, fingerprint: st.fingerprint });
  });
  readLines(sock, (msg) => {
    if (msg.type === "pair-accepted") {
      const cur = loadState(name);
      cur.peers[msg.deviceId] = {
        deviceId: msg.deviceId,
        displayName: msg.displayName,
        address: addr,
        fingerprint: msg.fingerprint,
        ticket: msg.ticket,
        ticketExpiresAt: msg.ticketExpiresAt,
        pairedAt: Date.now(),
      };
      saveState(cur);
      console.log("=== 配对成功 ===");
      console.log("对端设备 :", msg.displayName, `(${msg.deviceId.slice(0, 8)}…)`);
      console.log("对端指纹 :", short(msg.fingerprint), "（已固定）");
      console.log("连接票据 :", short(msg.ticket), `有效期至 ${new Date(msg.ticketExpiresAt).toLocaleString()}`);
      sock.end();
    } else if (msg.type === "pair-rejected") {
      console.error("配对被拒:", msg.reason);
      sock.end();
      process.exitCode = 2;
    }
  });
}

function authedRequest(args, method, payload, label) {
  const name = args.name || "default";
  const st = loadState(name);
  const peer = findPeer(st, args.addr);
  if (!peer) {
    console.error("没有已配对设备，先执行 pair");
    process.exit(1);
  }
  const sock = connect(name, peer.address, () => {
    const peerCert = sock.getPeerCertificate(true);
    const actual = peerCert && peerCert.raw ? fpOf(peerCert.raw) : "";
    if (actual !== peer.fingerprint) {
      console.error("对端指纹不匹配:", short(peer.fingerprint), "vs", short(actual));
      sock.end();
      process.exitCode = 3;
      return;
    }
    const requestId = crypto.randomUUID();
    sendLine(sock, {
      type: "request",
      deviceId: st.deviceId,
      displayName: name,
      ticket: peer.ticket,
      requestId,
      method,
      payload,
    });
  });
  readLines(sock, (msg) => {
    if (msg.type === "result") {
      console.log(`--- ${label} ---`);
      console.log(JSON.stringify(msg, null, 2));
      sock.end();
    } else if (msg.type === "rejected") {
      console.error("被拒:", msg.reason);
      sock.end();
      process.exitCode = 2;
    } else if (msg.type === "welcome") {
      sendLine(sock, {
        type: "request",
        deviceId: st.deviceId,
        displayName: name,
        ticket: peer.ticket,
        requestId: crypto.randomUUID(),
        method,
        payload,
      });
    }
  });
}

function cmdHello(args) {
  const name = args.name || "default";
  const st = loadState(name);
  const peer = findPeer(st, args.addr);
  if (!peer) {
    console.error("没有已配对设备，先执行 pair");
    process.exit(1);
  }
  const sock = connect(name, peer.address, () => {
    const peerCert = sock.getPeerCertificate(true);
    const actual = peerCert && peerCert.raw ? fpOf(peerCert.raw) : "";
    if (actual !== peer.fingerprint) {
      console.error("对端指纹不匹配");
      sock.end();
      process.exitCode = 3;
      return;
    }
    console.log("对端指纹校验通过:", short(actual));
    sendLine(sock, { type: "hello", deviceId: st.deviceId, displayName: name, ticket: peer.ticket });
  });
  readLines(sock, (msg) => {
    if (msg.type === "welcome") {
      console.log("=== 认证成功 ===");
      console.log("对端:", msg.displayName, "| 可见工作区:", msg.workspaces);
    } else if (msg.type === "rejected") {
      console.error("被拒:", msg.reason);
      process.exitCode = 2;
    }
    sock.end();
  });
}

// ---------------- 管理 ----------------

function cmdPolicy(args) {
  const name = args.name || "default";
  const st = loadState(name);
  const key = Object.keys(st.grants).find((k) => k.startsWith(String(args.device || "")));
  if (!key) {
    console.error("找不到该设备。已授权:", Object.keys(st.grants).map((k) => k.slice(0, 8)).join(", ") || "(无)");
    process.exit(1);
  }
  const g = st.grants[key];
  const mode = args.mode === "selected" ? "selected" : "all";
  const ids = args.workspaces ? String(args.workspaces).split(",").map((s) => s.trim()).filter(Boolean) : [];
  g.policy = { mode, ids, syncAllSessions: String(args["sync-all"] || "false") === "true" };
  saveState(st);
  console.log(`已更新 ${g.displayName} 的访问策略:`);
  console.log("  mode      :", mode);
  console.log("  workspaces:", ids.length ? ids.join(", ") : "(全部)");
  console.log("  syncAll   :", g.policy.syncAllSessions);
}

function cmdRevoke(args) {
  const name = args.name || "default";
  const st = loadState(name);
  const key = Object.keys(st.grants).find((k) => k.startsWith(String(args.device || "")));
  if (!key) {
    console.error("找不到该设备");
    process.exit(1);
  }
  st.grants[key].revokedAt = Date.now();
  saveState(st);
  console.log("已撤销:", st.grants[key].displayName);
}

function cmdStatus(args) {
  const name = args.name || "default";
  const st = loadState(name);
  console.log("=== 本机 ===");
  console.log("name      :", st.name);
  console.log("device id :", st.deviceId);
  console.log("cert fp   :", st.fingerprint);
  console.log("工作区    :", st.workspaces.length ? st.workspaces.join(", ") : "(未配置)");
  console.log("队列条目  :", st.queue.length);

  console.log("\n=== 我配对的对端 (peers) ===");
  const peers = Object.values(st.peers);
  if (!peers.length) console.log("  (无)");
  for (const p of peers) {
    const left = p.ticketExpiresAt ? Math.round((p.ticketExpiresAt - Date.now()) / 60000) : 0;
    console.log(`  ${p.displayName} ${p.deviceId.slice(0, 8)}… ${p.address} fp=${short(p.fingerprint)} ticket=${left > 0 ? left + "min" : "过期"}`);
  }

  console.log("\n=== 允许控制我的设备 (grants) ===");
  const grants = Object.values(st.grants);
  if (!grants.length) console.log("  (无)");
  for (const g of grants) {
    const pol = g.policy || {};
    console.log(`  ${g.displayName} ${g.deviceId.slice(0, 8)}… fp=${short(g.fingerprint)} policy=${pol.mode}${pol.mode === "selected" ? "[" + (pol.ids || []).join(",") + "]" : ""}${g.revokedAt ? " REVOKED" : ""}`);
  }

  if (st.queue.length) {
    console.log("\n=== 最近请求 ===");
    for (const q of st.queue.slice(-5)) console.log(`  ${new Date(q.receivedAt).toLocaleTimeString()} ${q.method} ${q.stage} by ${q.deviceId.slice(0, 8)}…`);
  }
}

// ---------------- main ----------------

const [, , cmd, ...rest] = process.argv;
const args = parseArgs(rest);
switch (cmd) {
  case "allow": cmdAllow(args); break;
  case "pair": cmdPair(args); break;
  case "hello": cmdHello(args); break;
  case "workspaces": authedRequest(args, "workspaces.list", null, "远端工作区"); break;
  case "sessions": authedRequest(args, "session.list", null, "远端会话"); break;
  case "policy": cmdPolicy(args); break;
  case "revoke": cmdRevoke(args); break;
  case "status": cmdStatus(args); break;
  default:
    console.log(`用法:
  allow      --name srv --port 41234 [--ttl 120] [--dsh-home ~/.dsh] [--workspaces "D:\\a,D:\\b"]
  pair       --name cli --addr host:port --code 12345678
  hello      --name cli --addr host:port
  workspaces --name cli --addr host:port
  sessions   --name cli --addr host:port
  policy     --name srv --device <id> --mode all|selected --workspaces id1,id2
  revoke     --name srv --device <id>
  status     --name srv`);
}
