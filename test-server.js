// P0 测试页服务器：把 test-iframe.html 以 http://127.0.0.1:<port>/ 提供，
// 这样父页面与隧道地址（127.0.0.1:54321）同为 127.0.0.1 站点，
// 才等价于真实场景（DSH 窗口自己跑在 127.0.0.1:8147）。
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.argv[2] || 54322);

http
  .createServer((req, res) => {
    if (req.url === "/" || req.url.startsWith("/index")) {
      const html = fs.readFileSync(path.join(HERE, "test-iframe.html"));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      res.end(html);
      return;
    }
    res.writeHead(404).end("not found");
  })
  .listen(port, "127.0.0.1", () => {
    console.log(`测试页  http://127.0.0.1:${port}/`);
  });
