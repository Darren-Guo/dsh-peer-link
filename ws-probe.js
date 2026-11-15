// 经隧道测试 WebSocket 升级，确认实时通道能过 L4 转发。
// 用法：node ws-probe.js 54321 <cookie值>
import net from "node:net";
import crypto from "node:crypto";

const [, , port = "54321", cookie = ""] = process.argv;
const paths = ["/api", "/typert", "/rpc", "/ws", "/api/gateway", "/"];

function probe(p) {
  return new Promise((resolve) => {
    const key = crypto.randomBytes(16).toString("base64");
    const sock = net.connect({ host: "127.0.0.1", port: Number(port) });
    let buf = "";
    const done = (r) => {
      sock.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => done("timeout"), 6000);
    sock.on("connect", () => {
      sock.write(
        `GET ${p} HTTP/1.1\r\n` +
          `Host: 127.0.0.1:${port}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Version: 13\r\n` +
          `Sec-WebSocket-Key: ${key}\r\n` +
          (cookie ? `Cookie: ${cookie}\r\n` : "") +
          `\r\n`
      );
    });
    sock.on("data", (c) => {
      buf += c.toString("latin1");
      const line = buf.split("\r\n")[0];
      if (line) {
        clearTimeout(timer);
        done(line);
      }
    });
    sock.on("error", (e) => {
      clearTimeout(timer);
      done("error:" + e.code);
    });
  });
}

for (const p of paths) {
  const r = await probe(p);
  console.log(`${p.padEnd(14)} → ${r}`);
}
