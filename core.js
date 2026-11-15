// core.js — 协议与状态内核，CLI（main.js）和网页界面（web.js）共用。
//
// 设计约束：
//   * 传输层只认「可达的 IPv4 地址」，不感知 tailscale / VPN / 任何特定网络。
//     tailnet 只是恰好每台机器都有稳定地址的普通 LAN，这里没有任何相关判断。
//   * 绑定 0.0.0.0；是否允许连接由配对码 + 证书指纹 + 票据决定，与网络类型无关。

import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import selfsigned from "selfsigned";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DATA_DIR = process.env.PEER_DATA_DIR || path.join(HERE, "data");
export const TICKET_TTL_MS = 24 * 3600 * 1000;
export const MAX_QUEUE = 500;

// ---------------- 基础工具 ----------------

export const b64u = (buf) => Buffer.from(buf).toString("base64url");
export const fpOf = (rawDer) => crypto.createHash("sha256").update(rawDer).digest("hex");
export const fpOfPem = (pem) => fpOf(new crypto.X509Certificate(pem).raw);
export const short = (s) => (s ? s.slice(0, 16) + "…" : "");

export function lanAddresses() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === "IPv4" && !a.internal) out.push({ address: a.address, iface: name });
    }
  }
  return out;
}

// ---------------- 状态 ----------------

export function stateFile(name) {
  return path.join(DATA_DIR, `${name}.json`);
}

export function loadState(name) {
  const f = stateFile(name);
  if (fs.existsSync(f)) {
    const st = JSON.parse(fs.readFileSync(f, "utf8"));
    st.queue = st.queue || [];
    st.peers = st.peers || {};
    st.grants = st.grants || {};
    st.workspaces = st.workspaces || [];
    if (!st.dshPort) st.dshPort = 12790;
    if (!st.dshHost) st.dshHost = "127.0.0.1";
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
    dshHome: null,
    dshPort: 12790,
    dshHost: "127.0.0.1",
    tokenFile: null,
    queue: [],
    createdAt: Date.now(),
  };
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(f, JSON.stringify(st, null, 2));
  return st;
}

export function saveState(st) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(stateFile(st.name), JSON.stringify(st, null, 2));
}

// ---------------- 票据 ----------------

function sign(payloadB64, secretHex) {
  return crypto.createHmac("sha256", Buffer.from(secretHex, "hex")).update(payloadB64).digest("base64url");
}

export function issueTicket(st, grant) {
  const payload = {
    v: 1,
    sub: grant.deviceId, // 票据持有者
    cfp: grant.fingerprint, // 绑定的客户端证书指纹
    iss: st.deviceId,
    iat: Date.now(),
    exp: Date.now() + TICKET_TTL_MS,
    jti: crypto.randomUUID(),
  };
  const body = b64u(JSON.stringify(payload));
  return { ticket: `${body}.${sign(body, st.masterSecret)}`, expiresAt: payload.exp, payload };
}

export function verifyTicket(st, grant, token, peerFp) {
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

// ---------------- 配对码 ----------------

export function setPairingCode(name, ttlSec = 120) {
  const st = loadState(name);
  const ttlMs = Math.max(30, Number(ttlSec)) * 1000;
  const code = String(crypto.randomInt(10000000, 99999999));
  st.pairing = { code, expiresAt: Date.now() + ttlMs, consumed: false };
  saveState(st);
  return { code, expiresAt: st.pairing.expiresAt, ttlSec: Math.round(ttlMs / 1000) };
}

export function activePairing(st) {
  const p = st.pairing;
  if (!p || p.consumed || Date.now() >= p.expiresAt) return null;
  return { code: p.code, expiresAt: p.expiresAt, secondsLeft: Math.max(0, Math.round((p.expiresAt - Date.now()) / 1000)) };
}

// ---------------- 工作区与策略 ----------------

export function workspaceId(p) {
  return crypto.createHash("sha256").update(path.resolve(p)).digest("hex").slice(0, 16);
}

export function allWorkspaces(st) {
  return st.workspaces.map((p) => ({ id: workspaceId(p), name: path.basename(p), path: p }));
}

export function allowedWorkspaces(st, grant) {
  const policy = grant.policy || { mode: "all", ids: [], syncAllSessions: false };
  const all = allWorkspaces(st);
  if (policy.mode === "all") return all;
  return all.filter((w) => policy.ids.includes(w.id));
}

export function setPolicy(name, devicePrefix, { mode, ids = [], syncAllSessions = false }) {
  const st = loadState(name);
  const key = Object.keys(st.grants).find((k) => k.startsWith(String(devicePrefix || "")));
  if (!key) return { ok: false, error: "device-not-found" };
  st.grants[key].policy = { mode: mode === "selected" ? "selected" : "all", ids, syncAllSessions: !!syncAllSessions };
  saveState(st);
  return { ok: true, grant: st.grants[key] };
}

export function revokeGrant(name, devicePrefix) {
  const st = loadState(name);
  const key = Object.keys(st.grants).find((k) => k.startsWith(String(devicePrefix || "")));
  if (!key) return { ok: false, error: "device-not-found" };
  st.grants[key].revokedAt = Date.now();
  saveState(st);
  return { ok: true, grant: st.grants[key] };
}

export function removePeer(name, devicePrefix) {
  const st = loadState(name);
  const key = Object.keys(st.peers).find((k) => k.startsWith(String(devicePrefix || "")));
  if (!key) return { ok: false, error: "peer-not-found" };
  const gone = st.peers[key];
  delete st.peers[key];
  saveState(st);
  return { ok: true, peer: gone };
}

// ---------------- DSH 自带信息（端口 / launchToken） ----------------

export function dshHomeDir(st) {
  return st.dshHome || process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
}

/**
 * 找 dsh web 的 launchToken。
 * `dsh web` 启动时会把带 token 的地址写进 <dsh home>/web/web-url-*.txt；
 * 找不到就返回 null，调用方退化为让用户手工粘贴令牌。
 */
export function findLaunchToken(st) {
  const candidates = [];
  if (st.tokenFile) candidates.push(st.tokenFile);

  const webDir = path.join(dshHomeDir(st), "web");
  try {
    for (const name of fs.readdirSync(webDir)) {
      if (/^web-url-.*\.txt$/.test(name)) candidates.push(path.join(webDir, name));
    }
  } catch {
    /* 目录不存在 */
  }

  // 取最近修改的那个
  const files = candidates
    .filter((f) => {
      try {
        return fs.statSync(f).isFile();
      } catch {
        return false;
      }
    })
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);

  for (const f of files) {
    try {
      const text = fs.readFileSync(f, "utf8");
      const m = text.match(/[?&]token=([A-Za-z0-9_\-]+)/);
      if (m) return { token: m[1], source: f };
    } catch {
      /* 下一个 */
    }
  }
  return null;
}

/** 该 grant 允许隧道到哪些端口。默认只放行 DSH 自身端口。 */
export function allowedPorts(st, grant) {
  const fromPolicy = grant?.policy?.ports;
  if (Array.isArray(fromPolicy) && fromPolicy.length) return fromPolicy;
  return [st.dshPort || 12790];
}

// ---------------- DSH 会话读取 ----------------

export function dshSessionsDir(st) {
  const home = st.dshHome || process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
  return path.join(home, "storages", "session_projcache", "sessions");
}
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// 会话文件命名随 DSH 版本变化：旧 session-<uuid>.json，新 <uuid>.json。
// 同目录还混有 mnemon-run-* / mnemon-task-* 运行态文件，必须排除。
export function sessionIdFromFile(name) {
  if (!name.endsWith(".json")) return null;
  const stem = name.slice(0, -".json".length);
  const bare = stem.startsWith("session-") ? stem.slice("session-".length) : stem;
  return UUID_RE.test(bare) ? bare : null;
}

export function readSessionFile(full) {
  // 文件可能带 UTF-8 BOM，JSON.parse 遇到会直接报错
  const text = fs.readFileSync(full, "utf8").replace(/^\uFEFF/, "");
  const j = JSON.parse(text);
  const rows = j?.record?.rows || j?.rows || {};
  const pick = (k) => rows[k]?.val;
  const meta = pick("sessionListMetadata") || {};
  const turns = pick("turnOutline")?.turns;
  return {
    title: pick("title") || null,
    cwd: pick("workingDirectory") || j?.record?.identity?.cwd || j?.identity?.cwd || "",
    lastPromptAt: meta.lastPromptAt || 0,
    // 建了但从未输入过内容：DSH 自己标 blank，标题为 null
    blank: meta.blank === true || (Array.isArray(turns) && turns.length === 0 && !pick("title")),
  };
}

export function listSessions(st, grant) {
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
      title: info.title || "(空白会话)",
      cwd: info.cwd,
      updatedAt: info.lastPromptAt || fs.statSync(full).mtimeMs,
      blank: info.blank === true,
    });
  }
  // 有内容的排前面，空白会话沉底
  return out.sort((a, b) => (a.blank === b.blank ? b.updatedAt - a.updatedAt : a.blank ? 1 : -1));
}

// ---------------- socket 工具 ----------------

export function sendLine(sock, obj) {
  sock.write(JSON.stringify(obj) + "\n");
}

/**
 * 按行读取 JSON。二进制安全：内部用 Buffer 累积，只把完整行按 UTF-8 解码。
 * 返回 { detach }：切到隧道模式时调用，摘下监听器并交回尚未消费的原始字节。
 */
export function readLines(sock, onMessage) {
  let buf = Buffer.alloc(0);
  const handler = (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    let idx;
    while ((idx = buf.indexOf(0x0a)) >= 0) {
      const line = buf.subarray(0, idx).toString("utf8").trim();
      buf = buf.subarray(idx + 1);
      if (!line) continue;
      try {
        onMessage(JSON.parse(line));
      } catch {
        /* 忽略坏行 */
      }
    }
  };
  sock.on("data", handler);
  return {
    detach() {
      sock.off("data", handler);
      const rest = buf;
      buf = Buffer.alloc(0);
      return rest;
    },
  };
}

// ---------------- 被控端：监听 ----------------

export function startPeerServer({ name, port = 41234, host = "0.0.0.0", log = () => {} }) {
  const st = loadState(name);
  return new Promise((resolve, reject) => {
    const server = tls.createServer(
      { key: st.key, cert: st.cert, requestCert: true, rejectUnauthorized: false },
      (sock) => {
        const peerCert = sock.getPeerCertificate(true);
        const peerFp = peerCert && peerCert.raw ? fpOf(peerCert.raw) : null;
        const readerRef = { detach: null };

        const reader = readLines(sock, (msg) => {
          const cur = loadState(name);

          // ---- 配对 ----
          if (msg.type === "pair-request") {
            const pairing = cur.pairing;
            const ok = pairing && !pairing.consumed && Date.now() < pairing.expiresAt && msg.code === pairing.code;
            if (!ok) {
              const reason = !pairing
                ? "no-active-code"
                : pairing.consumed
                  ? "code-used"
                  : Date.now() >= pairing.expiresAt
                    ? "code-expired"
                    : "code-mismatch";
              sendLine(sock, { type: "pair-rejected", reason });
              log(`配对被拒 (${reason}) 来自 ${msg.displayName || "?"}`);
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
            log(`已授权 ${msg.displayName} (${msg.deviceId.slice(0, 8)}…) fp=${short(msg.fingerprint)}`);
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

          // ---- 重连（票据 + 指纹 + 授权）----
          if (msg.type === "hello" || msg.type === "request" || msg.type === "tunnel") {
            const grant = cur.grants[msg.deviceId];
            if (!grant || grant.revokedAt) {
              sendLine(sock, { type: "rejected", reason: grant ? "revoked" : "not-granted" });
              log(`认证被拒: ${grant ? "已撤销" : "未授权"}`);
              return;
            }
            if (!peerFp || grant.fingerprint !== peerFp) {
              sendLine(sock, { type: "rejected", reason: "fingerprint-mismatch" });
              log("认证被拒: 证书指纹不匹配");
              return;
            }
            const tv = verifyTicket(cur, grant, msg.ticket, peerFp);
            if (!tv.ok) {
              sendLine(sock, { type: "rejected", reason: tv.reason });
              log(`认证被拒: ${tv.reason}`);
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
              log(`认证通过 ${grant.displayName}`);
              return;
            }

            // ---- 隧道：校验端口白名单后，该连接退化为原始字节管道 ----
            if (msg.type === "tunnel") {
              const wantPort = Number(msg.port);
              const ports = allowedPorts(cur, grant);
              if (!ports.includes(wantPort)) {
                sendLine(sock, { type: "rejected", reason: "port-not-allowed" });
                log(`隧道被拒: 端口 ${wantPort} 不在白名单 [${ports.join(",")}]`);
                return;
              }
              const leftover = readerRef.detach ? readerRef.detach() : Buffer.alloc(0);
              // DSH 可能绑在特定网卡上（例如只绑 tailnet 地址），所以出口主机可配置
              const exitHost = cur.dshHost || "127.0.0.1";
              const upstream = net.connect({ host: exitHost, port: wantPort });
              upstream.setNoDelay(true);
              sock.setNoDelay(true);
              upstream.on("connect", () => {
                sendLine(sock, { type: "tunnel-ready", connId: msg.connId || null, port: wantPort });
                if (leftover.length) upstream.write(leftover);
                sock.pipe(upstream);
                upstream.pipe(sock);
                log(`${grant.displayName} 隧道 → ${exitHost}:${wantPort}`);
              });
              upstream.on("error", (e) => {
                log(`隧道出口失败 ${exitHost}:${wantPort}: ${e.code}`);
                try {
                  sendLine(sock, { type: "rejected", reason: "upstream-" + (e.code || "error") });
                } catch {}
                sock.destroy();
              });
              sock.on("close", () => upstream.destroy());
              return;
            }

            // ---- 请求处理 ----
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
              case "workspaces.list":
                reply = { ok: true, workspaces: allowedWorkspaces(cur, grant), policy: grant.policy };
                break;
              case "workspaces.get": {
                const w = allowedWorkspaces(cur, grant).find((x) => x.id === msg.payload?.id);
                reply = w ? { ok: true, workspace: w } : { ok: false, error: "not-allowed" };
                break;
              }
              case "device.info": {
                const tk = findLaunchToken(cur);
                reply = {
                  ok: true,
                  device: { id: cur.deviceId, name: cur.name, fingerprint: cur.fingerprint },
                  platform: process.platform,
                  dsh: { port: cur.dshPort || 12790, tokenAvailable: !!tk },
                  workspaces: allowedWorkspaces(cur, grant),
                };
                break;
              }
              case "dsh.token": {
                const tk = findLaunchToken(cur);
                reply = tk ? { ok: true, token: tk.token, source: tk.source } : { ok: false, error: "token-unavailable" };
                break;
              }
              case "session.list":
                reply = { ok: true, sessions: listSessions(cur, grant), policy: grant.policy };
                break;
              case "session.open": {
                const s = listSessions(cur, grant).find((x) => x.id === msg.payload?.id);
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
            log(`${grant.displayName} 请求 ${msg.method} → ${reply.ok ? "ok" : reply.error}`);
            sendLine(sock, { type: "result", requestId, ...reply });
          }
        });

        readerRef.detach = reader.detach;
        sock.on("error", () => {});
      }
    );

    server.on("error", reject);
    server.listen(port, host, () => resolve(server));
  });
}

// ---------------- 控制端：连接 ----------------

const CONNECT_TIMEOUT_MS = 12_000;

function openTls(st, host, port) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect(
      { host, port: Number(port), rejectUnauthorized: false, key: st.key, cert: st.cert },
      () => resolve(sock)
    );
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`连接超时 ${host}:${port}`));
    }, CONNECT_TIMEOUT_MS);
    sock.once("secureConnect", () => clearTimeout(timer));
    sock.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

function peerFingerprint(sock) {
  const c = sock.getPeerCertificate(true);
  return c && c.raw ? fpOf(c.raw) : "";
}

export function resolvePeer(st, addr) {
  if (addr) {
    const hit = Object.values(st.peers).find((p) => p.address === addr || p.deviceId.startsWith(addr));
    if (hit) return hit;
  }
  return Object.values(st.peers)[0] || null;
}

/** 配对。resolve {ok, peer} 或 {ok:false, reason} */
export async function pairTo({ name, addr, code }) {
  const st = loadState(name);
  const [host, port] = String(addr).split(":");
  if (!host || !port) return { ok: false, reason: "bad-address" };

  let sock;
  try {
    sock = await openTls(st, host, port);
  } catch (e) {
    return { ok: false, reason: "connect-failed", detail: e.message };
  }

  return new Promise((resolve) => {
    const done = (r) => {
      try {
        sock.end();
      } catch {}
      resolve(r);
    };
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
        done({ ok: true, peer: cur.peers[msg.deviceId] });
      } else if (msg.type === "pair-rejected") {
        done({ ok: false, reason: msg.reason });
      }
    });
    sendLine(sock, { type: "pair-request", code, deviceId: st.deviceId, displayName: name, fingerprint: st.fingerprint });
  });
}

/** 带认证的请求。resolve {ok, ...serverReply} 或 {ok:false, reason} */
export async function requestTo({ name, addr, method, payload = null }) {
  const st = loadState(name);
  const peer = resolvePeer(st, addr);
  if (!peer) return { ok: false, reason: "no-peer" };

  const [host, port] = String(peer.address).split(":");
  let sock;
  try {
    sock = await openTls(st, host, port);
  } catch (e) {
    return { ok: false, reason: "connect-failed", detail: e.message };
  }

  // 客户端也校验对端指纹，防中间人
  const actual = peerFingerprint(sock);
  if (actual !== peer.fingerprint) {
    sock.destroy();
    return { ok: false, reason: "fingerprint-mismatch" };
  }

  return new Promise((resolve) => {
    const done = (r) => {
      try {
        sock.end();
      } catch {}
      resolve(r);
    };
    readLines(sock, (msg) => {
      if (msg.type === "result") {
        const { type, requestId, ...rest } = msg;
        done(rest);
      } else if (msg.type === "rejected") {
        done({ ok: false, reason: msg.reason });
      }
    });
    sendLine(sock, {
      type: "request",
      deviceId: st.deviceId,
      displayName: name,
      ticket: peer.ticket,
      requestId: crypto.randomUUID(),
      method,
      payload,
    });
  });
}

/** 认证握手。resolve {ok, welcome} 或 {ok:false, reason} */
export async function helloTo({ name, addr }) {
  const st = loadState(name);
  const peer = resolvePeer(st, addr);
  if (!peer) return { ok: false, reason: "no-peer" };

  const [host, port] = String(peer.address).split(":");
  let sock;
  try {
    sock = await openTls(st, host, port);
  } catch (e) {
    return { ok: false, reason: "connect-failed", detail: e.message };
  }
  const actual = peerFingerprint(sock);
  if (actual !== peer.fingerprint) {
    sock.destroy();
    return { ok: false, reason: "fingerprint-mismatch" };
  }
  return new Promise((resolve) => {
    const done = (r) => {
      try {
        sock.end();
      } catch {}
      resolve(r);
    };
    readLines(sock, (msg) => {
      if (msg.type === "welcome") done({ ok: true, welcome: msg });
      else if (msg.type === "rejected") done({ ok: false, reason: msg.reason });
    });
    sendLine(sock, { type: "hello", deviceId: st.deviceId, displayName: name, ticket: peer.ticket });
  });
}

// ---------------- 控制端：隧道 ----------------

/**
 * 向对端开一条隧道并完成握手。
 * resolve { ok:true, sock, leftover } —— 之后 sock 上流的是原始字节；
 * leftover 是握手期间可能已经到达的字节，必须先写给调用方再开始 pipe。
 */
export async function openTunnel({ name, addr, remotePort }) {
  const st = loadState(name);
  const peer = resolvePeer(st, addr);
  if (!peer) return { ok: false, reason: "no-peer" };

  const port = Number(remotePort || peer.dshPort || 12790);
  const [host, p] = String(peer.address).split(":");

  let sock;
  try {
    sock = await openTls(st, host, p);
  } catch (e) {
    return { ok: false, reason: "connect-failed", detail: e.message };
  }
  const actual = peerFingerprint(sock);
  if (actual !== peer.fingerprint) {
    sock.destroy();
    return { ok: false, reason: "fingerprint-mismatch" };
  }

  const readerRef = { detach: null };
  return new Promise((resolve) => {
    const reader = readLines(sock, (msg) => {
      if (msg.type === "tunnel-ready") {
        const leftover = readerRef.detach ? readerRef.detach() : Buffer.alloc(0);
        resolve({ ok: true, sock, leftover, port });
      } else if (msg.type === "rejected") {
        sock.destroy();
        resolve({ ok: false, reason: msg.reason });
      }
    });
    readerRef.detach = reader.detach;
    sendLine(sock, {
      type: "tunnel",
      deviceId: st.deviceId,
      displayName: name,
      ticket: peer.ticket,
      port,
      connId: crypto.randomUUID(),
    });
  });
}

/**
 * 本地隧道服务器：127.0.0.1:<localPort> 的每个连接都开一条到对端的隧道。
 * 本地端口固定不随重连改变，iframe 的地址因此保持稳定。
 */
export async function startTunnelServer({ name, addr, localPort, remotePort, log = () => {} }) {
  const server = net.createServer(async (client) => {
    client.setNoDelay(true);
    const r = await openTunnel({ name, addr, remotePort });
    if (!r.ok) {
      log(`隧道建立失败: ${r.reason}`);
      client.destroy();
      return;
    }
    if (r.leftover && r.leftover.length) client.write(r.leftover);
    client.pipe(r.sock);
    r.sock.pipe(client);
    const kill = () => {
      client.destroy();
      r.sock.destroy();
    };
    client.on("error", kill);
    r.sock.on("error", kill);
    client.on("close", () => r.sock.destroy());
    r.sock.on("close", () => client.destroy());
  });

  await new Promise((res, rej) => {
    server.once("error", rej);
    server.listen(localPort, "127.0.0.1", res);
  });
  const actualPort = server.address().port;
  log(`本地隧道 127.0.0.1:${actualPort} → ${addr} (远端 ${remotePort || 12790})`);
  return { server, port: actualPort };
}

// ---------------- 状态摘要（给 UI 用） ----------------

export function stateSummary(name) {
  const st = loadState(name);
  return {
    name: st.name,
    deviceId: st.deviceId,
    fingerprint: st.fingerprint,
    dshHome: dshSessionsDir(st),
    workspaces: allWorkspaces(st),
    pairing: activePairing(st),
    peers: Object.values(st.peers).map((p) => ({
      deviceId: p.deviceId,
      displayName: p.displayName,
      address: p.address,
      fingerprint: p.fingerprint,
      pairedAt: p.pairedAt,
      ticketExpiresAt: p.ticketExpiresAt,
      ticketValid: (p.ticketExpiresAt || 0) > Date.now(),
    })),
    grants: Object.values(st.grants).map((g) => ({
      deviceId: g.deviceId,
      displayName: g.displayName,
      fingerprint: g.fingerprint,
      grantedAt: g.grantedAt,
      lastSeenAt: g.lastSeenAt,
      revokedAt: g.revokedAt,
      policy: g.policy || { mode: "all", ids: [], syncAllSessions: false },
      allowedWorkspaceIds: allowedWorkspaces(st, g).map((w) => w.id),
    })),
    recentRequests: st.queue.slice(-10).reverse(),
  };
}
