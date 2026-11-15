/**
 * Host 半侧入口。
 *
 * 职责：
 *   1. 本机作为「被控端」监听 TLS，接受已配对设备的请求与隧道
 *   2. 本机作为「控制端」按需为每个对端起一个 L7 代理（cookie 服务端注入）
 *   3. 通过 127.0.0.1:<apiPort> 向插件面板提供状态与操作
 *
 * 协议内核在 lib/core.js，代理实现在 lib/proxy-server.js。
 */
import { startHost } from "./host.js";

let host = null;

export async function apply(ctx) {
  try {
    host = await startHost({
      stateName: "local",
      peerPort: Number(process.env.PEER_LINK_PORT || 41234),
      dshPort: Number(process.env.PEER_LINK_DSH_PORT || 12790),
      dshHost: process.env.PEER_LINK_DSH_HOST || "127.0.0.1",
    });
    if (ctx && typeof ctx.effect === "function") {
      ctx.effect(() => () => {
        host?.dispose?.();
        host = null;
      });
    }
  } catch (e) {
    console.error("[peer-link] host 启动失败:", e);
  }
}
