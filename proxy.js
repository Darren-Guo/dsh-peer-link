// L7 反向代理：跨站 iframe 的正确解法。
//
// 为什么需要 L7 而不是纯 L4 隧道：
//   DSH 的认证 cookie 是 SameSite=Strict。当 iframe 的站点与父页面不同时，
//   浏览器不会把这个 cookie 发出去，哪怕我们已经换过票。纯 L4 隧道无法补救。
//   改成代理后，cookie 由代理在服务端注入，浏览器一个 cookie 都不需要持有。
//
// 关键点：cookie 与 Host 头绑定的 authority 一致。因此代理固定用
//   Host: 127.0.0.1:<本地端口>
// 既用于换票，也用于后续所有上游请求。
//
// 用法：node proxy.js --name c1 --addr host:port --local 54340 [--remote 12790]

import http from "node:http";
import net from "node:net";
import { openTunnel, loadState } from "./core.js";

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) out[a.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const NAME = args.name || "default";
const ADDR = args.addr;
const LOCAL = Number(args.local || 54340);
const REMOTE_PORT = Number(args.remote || 12790);

if (!ADDR) {
  console.error("用法: node proxy.js --name c1 --addr host:port --local 54340 [--remote 12790]");
  process.exit(1);
}

const log = (m) => console.log(`[${new Date().toLocaleTimeString()}] ${m}`);

const st = loadState(NAME);
const peer = Object.values(st.peers).find((p) => p.address === ADDR) || Object.values(st.peers)[0];
const TOKEN = args.token || peer?.dshToken || null;

const AUTHORITY = `127.0.0.1:${LOCAL}`;

let cookie = null; // 服务端持有的认证 cookie，浏览器不需要知道

/** 让 http.request 复用我们已有的隧道 socket（agent:false 会忽略 createConnection）。 */
function agentFor(sock) {
  const a = new http.Agent({ keepAlive: false, maxSockets: 1 });
  a.createConnection = () => sock;
  return a;
}

async function newTunnelSocket() {
  const r = await openTunnel({ name: NAME, addr: ADDR, remotePort: REMOTE_PORT });
  if (!r.ok) throw new Error("tunnel:" + r.reason);
  return { sock: r.sock, leftover: r.leftover };
}

/** 用 token 换一次 cookie，之后一直复用。 */
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
        reject(new Error("no-set-cookie (status " + res.statusCode + ")"));
      }
    });
    req.on("error", (e) => reject(new Error(e.message || e.code || "request-failed")));
    req.end();
  });
}

/** 把一个客户端请求转发到上游，返回上游响应。 */
function forward(req, res, bodyStream) {
  return new Promise(async (resolve) => {
    let tunnel;
    try {
      tunnel = await newTunnelSocket();
      await ensureCookie();
    } catch (e) {
      res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      res.end("代理失败: " + e.message);
      log("上游失败: " + e.message);
      return resolve();
    }

    const headers = { ...req.headers, host: AUTHORITY, cookie };
    delete headers["accept-encoding"]; // 避免压缩带来的转发复杂度
    if (tunnel.leftover && tunnel.leftover.length) tunnel.sock.write(tunnel.leftover);

    const up = http.request(
      {
        method: req.method,
        path: req.url,
        headers,
        agent: agentFor(tunnel.sock),
      },
      (upRes) => {
        const outHeaders = { ...upRes.headers };
        delete outHeaders["transfer-encoding"];
        res.writeHead(upRes.statusCode || 502, outHeaders);
        upRes.pipe(res);
        upRes.on("end", () => resolve());
      }
    );
    up.on("error", (e) => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      res.end("上游错误: " + (e.message || e.code));
      log("上游错误: " + (e.message || e.code));
      resolve();
    });
    (bodyStream || req).pipe(up);
  });
}

const server = http.createServer((req, res) => {
  if (req.url === "/__peer-link/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, authority: AUTHORITY, hasCookie: !!cookie }));
    return;
  }
  forward(req, res, null);
});

// WebSocket / 其它升级请求：手工转发升级请求后双向原始转发
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
    if (k.toLowerCase() === "host") continue;
    if (k.toLowerCase() === "cookie") continue;
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
  log("升级请求已转发（WebSocket）");
});

server.listen(LOCAL, "127.0.0.1", () => {
  console.log("");
  console.log(`代理地址   http://${AUTHORITY}/`);
  console.log(`上游       ${ADDR} (远端端口 ${REMOTE_PORT})`);
  console.log(`token      ${TOKEN ? TOKEN.slice(0, 8) + "…" : "缺失（请用 --token 传入）"}`);
  console.log("");
  log("就绪。这个地址不需要带 token，认证由代理在服务端完成。");
});
