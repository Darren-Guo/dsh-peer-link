// P0 SPIKE：纯 TCP 端口转发（L4），不做任何 HTTP 解析。
//   本地 127.0.0.1:<localPort>  →  <host>:<targetPort>
// 用法：node tunnel-spike.js 54321 100.64.0.1 12790
//
// 之所以不写 HTTP 反代：L4 原样转发时，Host 头由浏览器自己填写为
// 127.0.0.1:<localPort>，远端按 Host 计算 authority 并据此签发 cookie，
// 换票与 cookie 全部自然成立，无需改写任何头。

import net from "node:net";

const [, , localPort = "54321", host = "100.64.0.1", targetPort = "12790"] = process.argv;

let opened = 0;

const server = net.createServer((client) => {
  opened++;
  const id = opened;
  const started = Date.now();
  const upstream = net.connect({ host, port: Number(targetPort) });

  client.setNoDelay(true);
  upstream.setNoDelay(true);

  // 双向原样拷贝
  client.pipe(upstream);
  upstream.pipe(client);

  const teardown = (why) => {
    client.destroy();
    upstream.destroy();
    console.log(`[#${id}] closed (${why}) ${Date.now() - started}ms`);
  };

  client.on("error", (e) => teardown("client:" + e.code));
  upstream.on("error", (e) => teardown("upstream:" + e.code));
  client.on("close", () => teardown("client-close"));
  upstream.on("close", () => teardown("upstream-close"));

  upstream.on("connect", () => console.log(`[#${id}] open → ${host}:${targetPort}`));
});

server.listen(Number(localPort), "127.0.0.1", () => {
  console.log(`tunnel  127.0.0.1:${localPort} → ${host}:${targetPort}`);
});
