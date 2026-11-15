// Host 半侧的服务：被控端 TLS 监听 + 控制 API + 按需代理。
// 客户端（插件面板）通过 127.0.0.1:<apiPort> 读取状态、配对、连接。

import http from "node:http";
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
} from "./lib/core.js";
import { startProxy } from "./lib/proxy-server.js";

const API_PORTS = [41730, 41731, 41732, 41733, 41734, 41735];

const logs = [];
function pushLog(msg) {
  const line = { at: Date.now(), msg };
  logs.push(line);
  if (logs.length > 300) logs.shift();
  console.log(`[peer-link] ${msg}`);
}

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  });
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

export async function startHost({ stateName = "local", peerPort = 41234, dshPort = 12790, dshHost = "127.0.0.1" } = {}) {
  // 状态初始化
  const st0 = loadState(stateName);
  st0.dshPort = dshPort;
  st0.dshHost = dshHost;
  saveState(st0);

  // 被控端 TLS（端口可能被上一个实例短暂占用，重试几次）
  let peerReady = false;
  for (let attempt = 1; attempt <= 6 && !peerReady; attempt++) {
    try {
      await startPeerServer({ name: stateName, port: peerPort, host: "0.0.0.0", log: pushLog });
      peerReady = true;
      pushLog(`被控端监听 0.0.0.0:${peerPort}`);
    } catch (e) {
      const code = e.code || e.message;
      if (attempt === 6) pushLog(`被控端启动失败（端口 ${peerPort}）: ${code}`);
      else {
        pushLog(`被控端端口 ${peerPort} 不可用（${code}），2 秒后重试 ${attempt}/6`);
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
  }

  /** deviceId → proxy 句柄 */
  const proxies = new Map();

  async function connectDevice(devicePrefix, tokenOverride) {
    const st = loadState(stateName);
    const peer = Object.values(st.peers).find((p) => p.deviceId.startsWith(devicePrefix));
    if (!peer) return { ok: false, error: "peer-not-found" };

    if (proxies.has(peer.deviceId)) {
      return { ok: true, ...proxies.get(peer.deviceId).info() };
    }

    // 取对端 DSH 端口与 token
    let token = tokenOverride || peer.dshToken || null;
    let remotePort = peer.dshPort || dshPort;
    if (!token) {
      const tk = await requestTo({ name: stateName, addr: peer.address, method: "dsh.token" });
      if (tk.ok) {
        token = tk.token;
        peer.dshToken = token;
        saveState(loadState(stateName));
        // 重新读一遍再写，避免覆盖并发改动
        const st2 = loadState(stateName);
        if (st2.peers[peer.deviceId]) {
          st2.peers[peer.deviceId].dshToken = token;
          saveState(st2);
        }
      }
    }
    const info = await requestTo({ name: stateName, addr: peer.address, method: "device.info" });
    if (info.ok && info.dsh?.port) remotePort = info.dsh.port;

    if (!token) {
      pushLog(`连接 ${peer.displayName} 需要手工提供 token`);
      return { ok: false, error: "token-required", needToken: true };
    }

    try {
      const p = await startProxy({ name: stateName, addr: peer.address, remotePort, token, log: pushLog });
      proxies.set(peer.deviceId, p);
      pushLog(`已连接 ${peer.displayName} → ${p.url}`);
      return { ok: true, ...p.info() };
    } catch (e) {
      pushLog(`连接 ${peer.displayName} 失败: ${e.message}`);
      return { ok: false, error: e.message };
    }
  }

  async function disconnectDevice(devicePrefix) {
    const key = [...proxies.keys()].find((k) => k.startsWith(devicePrefix));
    if (!key) return { ok: true, already: true };
    const p = proxies.get(key);
    proxies.delete(key);
    await p.close();
    pushLog("已断开一个设备");
    return { ok: true };
  }

  const API = {
    async "GET /api/state"() {
      const s = stateSummary(stateName);
      return {
        ...s,
        addresses: lanAddresses(),
        peerPort,
        dshPort,
        connections: [...proxies.entries()].map(([deviceId, p]) => ({ deviceId, ...p.info() })),
        peerReady,
      };
    },
    async "GET /api/logs"() {
      return { logs: logs.slice(-80).reverse() };
    },
    async "POST /api/code"({ ttl }) {
      const r = setPairingCode(stateName, ttl || 600);
      pushLog(`已生成配对码（${r.ttlSec} 秒）`);
      return r;
    },
    async "POST /api/workspaces"({ list }) {
      const st = loadState(stateName);
      st.workspaces = (list || []).filter(Boolean);
      saveState(st);
      pushLog(`工作区已更新：${st.workspaces.length} 个`);
      return { ok: true, workspaces: allWorkspaces(st) };
    },
    async "POST /api/pair"({ addr, code }) {
      const r = await pairTo({ name: stateName, addr, code: String(code || "") });
      pushLog(r.ok ? `配对成功：${r.peer.displayName} @ ${addr}` : `配对失败：${r.reason}`);
      return r.ok ? { ok: true, peer: { deviceId: r.peer.deviceId, displayName: r.peer.displayName, address: r.peer.address } } : r;
    },
    async "POST /api/policy"({ device, mode, ids }) {
      const r = setPolicy(stateName, device, { mode, ids: ids || [] });
      if (r.ok) pushLog(`策略已更新：${r.grant.displayName} → ${r.grant.policy.mode}`);
      return r.ok ? { ok: true } : r;
    },
    async "POST /api/revoke"({ device }) {
      const r = revokeGrant(stateName, device);
      if (r.ok) pushLog(`已撤销：${r.grant.displayName}`);
      return r.ok ? { ok: true } : r;
    },
    async "POST /api/unpair"({ device }) {
      await disconnectDevice(device);
      const r = removePeer(stateName, device);
      if (r.ok) pushLog(`已移除对端：${r.peer.displayName}`);
      return r.ok ? { ok: true } : r;
    },
    async "POST /api/connect"({ device, token }) {
      return await connectDevice(device, token);
    },
    async "POST /api/disconnect"({ device }) {
      return await disconnectDevice(device);
    },
  };

  const server = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") {
      res.writeHead(204, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      });
      res.end();
      return;
    }
    const url = new URL(req.url, "http://127.0.0.1");
    const handler = API[`${req.method} ${url.pathname}`];
    if (!handler) return json(res, 404, { ok: false, error: "not-found" });
    try {
      const body = req.method === "POST" ? await readBody(req) : {};
      json(res, 200, await handler(body));
    } catch (e) {
      pushLog(`接口错误: ${e.message}`);
      json(res, 500, { ok: false, error: e.message });
    }
  });

  let apiPort = null;
  for (const p of API_PORTS) {
    try {
      await new Promise((res, rej) => {
        server.once("error", rej);
        server.listen(p, "127.0.0.1", res);
      });
      apiPort = p;
      break;
    } catch {
      /* 换下一个 */
    }
  }
  if (apiPort) pushLog(`控制 API 127.0.0.1:${apiPort}`);
  else pushLog("控制 API 未能监听（端口都被占用）");

  return {
    apiPort,
    async dispose() {
      for (const p of proxies.values()) await p.close();
      proxies.clear();
      await new Promise((res) => server.close(() => res()));
    },
  };
}
