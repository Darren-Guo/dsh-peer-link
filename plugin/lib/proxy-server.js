// 可复用的 L7 反代：每个对端一个，cookie 由自己持有并注入。
// 浏览器（iframe）不需要任何 cookie，因此跨站 iframe 也能工作。

import http from "node:http";
import { openTunnel, loadState } from "./core.js";

/**
 * 起一个代理。
 * @returns {Promise<{url:string, port:number, close:()=>Promise<void>, info:()=>object}>}
 */
export async function startProxy({ name, addr, remotePort = 12790, token = null, preferredPort = 0, log = () => {} }) {
  const st = loadState(name);
  const peer = Object.values(st.peers).find((p) => p.address === addr) || Object.values(st.peers)[0];
  const TOKEN = token || peer?.dshToken || null;

  let cookie = null;

  /** 优先用固定端口，被占用再退回随机 —— 固定端口让 iframe 地址稳定 */
  async function bind() {
    const tryPort = (p) =>
      new Promise((res, rej) => {
        const s = http.createServer();
        s.once("error", rej);
        s.listen(p, "127.0.0.1", () => res(s));
      });
    if (preferredPort) {
      try {
        const s = await tryPort(preferredPort);
        log(`代理使用固定端口 ${preferredPort}`);
        return s;
      } catch {
        log(`固定端口 ${preferredPort} 被占用，改用随机端口`);
      }
    }
    return await tryPort(0);
  }

  const server = await bind();
  const port = server.address().port;
  const AUTHORITY = `127.0.0.1:${port}`;

  function agentFor(sock) {
    const a = new http.Agent({ keepAlive: false, maxSockets: 1 });
    a.createConnection = () => sock;
    return a;
  }

  async function newTunnelSocket() {
    const r = await openTunnel({ name, addr, remotePort });
    if (!r.ok) throw new Error("tunnel:" + r.reason);
    return r;
  }

  async function ensureCookie() {
    if (cookie) return cookie;
    if (!TOKEN) throw new Error("no-token");
    const { sock, leftover } = await newTunnelSocket();
    if (leftover && leftover.length) sock.write(leftover);
    return await new Promise((resolve, reject) => {
      const req = http.request({
        method: "GET",
        path: `/?token=${encodeURIComponent(TOKEN)}`,
        headers: { host: AUTHORITY, connection: "close" },
        agent: agentFor(sock),
      });
      req.on("response", (res) => {
        const set = res.headers["set-cookie"];
        res.resume();
        if (set && set.length) {
          cookie = set.map((c) => c.split(";")[0]).join("; ");
          log(`已取得认证 cookie（authority=${AUTHORITY}）`);
          resolve(cookie);
        } else {
          reject(new Error("no-set-cookie(status " + res.statusCode + ")"));
        }
      });
      req.on("error", (e) => reject(new Error(e.message || e.code || "request-failed")));
      req.end();
    });
  }

  function handleHttp(req, res) {
    (async () => {
      let tunnel;
      try {
        tunnel = await newTunnelSocket();
        await ensureCookie();
      } catch (e) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
        res.end("代理失败: " + e.message);
        log("上游失败: " + e.message);
        return;
      }
      const headers = { ...req.headers, host: AUTHORITY, cookie };
      delete headers["accept-encoding"];
      if (tunnel.leftover && tunnel.leftover.length) tunnel.sock.write(tunnel.leftover);

      const up = http.request(
        { method: req.method, path: req.url, headers, agent: agentFor(tunnel.sock) },
        (upRes) => {
          const outHeaders = { ...upRes.headers };
          delete outHeaders["transfer-encoding"];
          res.writeHead(upRes.statusCode || 502, outHeaders);
          upRes.pipe(res);
        }
      );
      up.on("error", (e) => {
        if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
        res.end("上游错误: " + (e.message || e.code));
        log("上游错误: " + (e.message || e.code));
      });
      req.pipe(up);
    })();
  }

  server.on("request", handleHttp);

  server.on("upgrade", async (req, clientSock, head) => {
    let tunnel;
    try {
      tunnel = await newTunnelSocket();
      await ensureCookie();
    } catch (e) {
      clientSock.destroy();
      return;
    }
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase();
      if (lk === "host" || lk === "cookie") continue;
      lines.push(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
    }
    lines.push(`host: ${AUTHORITY}`);
    lines.push(`cookie: ${cookie}`);
    tunnel.sock.write(lines.join("\r\n") + "\r\n\r\n");
    if (head && head.length) tunnel.sock.write(head);
    if (tunnel.leftover && tunnel.leftover.length) tunnel.sock.write(tunnel.leftover);

    tunnel.sock.pipe(clientSock);
    clientSock.pipe(tunnel.sock);
    const kill = () => {
      clientSock.destroy();
      tunnel.sock.destroy();
    };
    clientSock.on("error", kill);
    tunnel.sock.on("error", kill);
    clientSock.on("close", () => tunnel.sock.destroy());
    tunnel.sock.on("close", () => clientSock.destroy());
    log(`WebSocket 已转发 → ${addr}`);
  });

  return {
    url: `http://${AUTHORITY}/`,
    port,
    info: () => ({ url: `http://${AUTHORITY}/`, port, hasCookie: !!cookie, hasToken: !!TOKEN }),
    close: () =>
      new Promise((res) => {
        server.closeAllConnections?.();
        server.close(() => res());
      }),
  };
}
