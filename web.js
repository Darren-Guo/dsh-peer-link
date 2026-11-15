// web.js — 网页交互原型。一个进程同时做两件事：
//   1. 在 41234 提供被控端 TLS 服务（和 CLI 的 allow 等价）
//   2. 在 41700 提供网页界面与 JSON API
//
//   node web.js --name local --port 41234 --http 41700 [--dsh-home ~/.dsh]

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";
import {
  allWorkspaces,
  lanAddresses,
  loadState,
  pairTo,
  removePeer,
  requestTo,
  revokeGrant,
  saveState,
  setPairingCode,
  setPolicy,
  startPeerServer,
  stateSummary,
} from "./core.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) out[a.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const STATE = args.name || "default";
const PEER_PORT = Number(args.port || 41234);
const HTTP_PORT = Number(args.http || 41700);
const HOST = args.host || "0.0.0.0";

// 内存日志，给界面显示
const logs = [];
function log(msg) {
  const line = { at: Date.now(), msg };
  logs.push(line);
  if (logs.length > 200) logs.shift();
  console.log(`[${new Date().toLocaleTimeString()}] ${msg}`);
}

// 初始化状态（工作区、DSH 目录）
{
  const st = loadState(STATE);
  if (args.workspaces) st.workspaces = String(args.workspaces).split(",").map((s) => s.trim()).filter(Boolean);
  if (args["dsh-home"]) st.dshHome = args["dsh-home"];
  saveState(st);
}

// ---------------- HTTP ----------------

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (c) => (buf += c));
    req.on("end", () => {
      try {
        resolve(buf ? JSON.parse(buf) : {});
      } catch {
        resolve({});
      }
    });
  });
}

const API = {
  async "GET /api/state"() {
    const s = stateSummary(STATE);
    return { ...s, addresses: lanAddresses(), peerPort: PEER_PORT, httpPort: HTTP_PORT };
  },

  async "GET /api/logs"() {
    return { logs: logs.slice(-60).reverse() };
  },

  async "POST /api/code"({ ttl }) {
    const r = setPairingCode(STATE, ttl || 120);
    log(`已生成新配对码（${r.ttlSec} 秒有效）`);
    return r;
  },

  async "POST /api/workspaces"({ list }) {
    const st = loadState(STATE);
    st.workspaces = (list || []).filter(Boolean);
    saveState(st);
    log(`工作区已更新：${st.workspaces.length} 个`);
    return { ok: true, workspaces: allWorkspaces(st) };
  },

  async "POST /api/pair"({ addr, code }) {
    const r = await pairTo({ name: STATE, addr, code: String(code || "") });
    if (r.ok) log(`配对成功：${r.peer.displayName} @ ${addr}`);
    else log(`配对失败：${r.reason}${r.detail ? " (" + r.detail + ")" : ""}`);
    return r;
  },

  async "POST /api/policy"({ device, mode, ids }) {
    const r = setPolicy(STATE, device, { mode, ids: ids || [] });
    if (r.ok) log(`策略已更新：${r.grant.displayName} → ${r.grant.policy.mode}`);
    return r;
  },

  async "POST /api/revoke"({ device }) {
    const r = revokeGrant(STATE, device);
    if (r.ok) log(`已撤销授权：${r.grant.displayName}`);
    return r;
  },

  async "POST /api/unpair"({ device }) {
    const r = removePeer(STATE, device);
    if (r.ok) log(`已移除对端：${r.peer.displayName}`);
    return r;
  },

  async "POST /api/peer/workspaces"({ addr }) {
    const r = await requestTo({ name: STATE, addr, method: "workspaces.list" });
    if (!r.ok) log(`读取远端工作区失败：${r.reason}`);
    else log(`读取远端工作区：${(r.workspaces || []).length} 个`);
    return r;
  },

  async "POST /api/peer/sessions"({ addr }) {
    const r = await requestTo({ name: STATE, addr, method: "session.list" });
    if (!r.ok) log(`读取远端会话失败：${r.reason}`);
    else log(`读取远端会话：${(r.sessions || []).length} 条`);
    return r;
  },

  async "POST /api/peer/hello"({ addr }) {
    const r = await requestTo({ name: STATE, addr, method: "ping" });
    log(r.ok ? `连通性测试通过 ${addr}` : `连通性测试失败：${r.reason}`);
    return r;
  },
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  if (pathname === "/" || pathname === "/index.html") {
    const html = fs.readFileSync(path.join(HERE, "ui.html"));
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(html);
    return;
  }

  const key = `${req.method} ${pathname}`;
  const handler = API[key];
  if (!handler) {
    json(res, 404, { ok: false, error: "not-found" });
    return;
  }
  try {
    const body = req.method === "POST" ? await readBody(req) : {};
    json(res, 200, await handler(body));
  } catch (e) {
    log(`接口错误 ${key}: ${e.message}`);
    json(res, 500, { ok: false, error: e.message });
  }
});

// ---------------- 启动 ----------------

await startPeerServer({ name: STATE, port: PEER_PORT, host: HOST, log });
server.listen(HTTP_PORT, HOST, () => {
  const st = loadState(STATE);
  console.log("");
  for (const a of lanAddresses()) console.log(`  界面  http://${a.address}:${HTTP_PORT}`);
  console.log(`  本机  http://127.0.0.1:${HTTP_PORT}`);
  console.log("");
  log(`被控端已监听 ${HOST}:${PEER_PORT}，网页界面在 ${HOST}:${HTTP_PORT}`);
  console.log(`  设备 ${st.deviceId.slice(0, 8)}…  指纹 ${st.fingerprint.slice(0, 16)}…`);
  console.log("");
});
