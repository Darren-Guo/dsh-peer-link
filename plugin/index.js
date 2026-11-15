/**
 * Host 半侧入口。
 *
 * 职责：
 *   1. 本机作为「被控端」监听 TLS，接受已配对设备的请求与隧道
 *   2. 本机作为「控制端」按需为每个对端起一个 L7 代理（cookie 服务端注入）
 *   3. 把对端的工作区注册成本地真实工作区（影子目录 + workspaceRegistry），
 *      名称形如 `[Mac] default-workspace`
 *   4. 通过 127.0.0.1:<apiPort> 向插件面板提供状态与操作
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startHost } from "./host.js";

const SHADOW_ROOT = path.join(os.homedir(), ".dsh", "peer-link", "mount");
const HOST_KEY = Symbol.for("dsh-peer-link.host");

const NOTE = `# 远端工作区（本地锚点）

这个目录是给 DSH 用来标记「一台远端设备上的某个工作区」的，
**真正的文件不在这里**，在那台远端机器上。

在这里让 agent 干活不会影响远端文件。要操作远端项目，
请通过侧栏「远端设备」打开远端界面，在那边操作。
`;

/**
 * 用 ctx.workspaceRegistry 注册真实工作区。
 *
 * Cordis 要求先 inject 声明依赖，直接读 ctx.workspaceRegistry 会抛
 * "cannot get property ... without inject"。所以在 inject 回调里取服务。
 */
function makeWorkspaceBridge(ctx) {
  const created = [];
  let registry = null;

  ctx.inject(["workspaceRegistry"], (c) => {
    registry = c.workspaceRegistry;
    console.log("[peer-link] workspaceRegistry 已注入");
  });

  async function waitRegistry(ms = 8000) {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      if (registry && typeof registry.create === "function") return registry;
      await new Promise((r) => setTimeout(r, 200));
    }
    return null;
  }

  return {
    async ensure({ deviceId, deviceName, workspaceId, workspaceName }) {
      const reg = await waitRegistry();
      if (!reg) return { ok: false, error: "workspaceRegistry 未就绪" };

      const dir = path.join(SHADOW_ROOT, String(deviceId).slice(0, 8), String(workspaceId));
      fs.mkdirSync(dir, { recursive: true });
      const notePath = path.join(dir, "README-远端工作区.md");
      if (!fs.existsSync(notePath)) fs.writeFileSync(notePath, NOTE, "utf8");

      const title = `[${deviceName}] ${workspaceName}`;
      try {
        const project = await reg.create(dir, title);
        const id = project?.id ?? project?.workspaceId ?? null;
        if (!created.some((c) => c.path === dir)) created.push({ title, path: dir, id });
        console.log(`[peer-link] 工作区已就绪: ${title}`);
        return { ok: true, id };
      } catch (e) {
        console.error(`[peer-link] 工作区注册失败 ${title}:`, e?.message || e);
        return { ok: false, error: e?.message || String(e) };
      }
    },
    list() {
      return created;
    },
  };
}

export async function apply(ctx) {
  // 插件重载时先关掉上一个实例，否则被控端端口会一直被占
  const prev = globalThis[HOST_KEY];
  if (prev) {
    try {
      await prev.dispose();
      console.log("[peer-link] 已关闭上一个实例");
    } catch (e) {
      console.error("[peer-link] 关闭上一个实例失败:", e?.message || e);
    }
    globalThis[HOST_KEY] = null;
  }

  try {
    const workspaceBridge = makeWorkspaceBridge(ctx);
    const host = await startHost({
      stateName: "local",
      peerPort: Number(process.env.PEER_LINK_PORT || 41234),
      dshPort: Number(process.env.PEER_LINK_DSH_PORT || 12790),
      dshHost: process.env.PEER_LINK_DSH_HOST || "127.0.0.1",
      workspaceBridge,
    });
    globalThis[HOST_KEY] = host;

    // 启动后同步一次已有对端的工作区
    setTimeout(() => {
      host.syncWorkspaces().catch((e) => console.error("[peer-link] 初次同步失败:", e?.message || e));
    }, 3000);

    if (typeof ctx.effect === "function") {
      ctx.effect(() => () => {
        host.dispose?.();
        if (globalThis[HOST_KEY] === host) globalThis[HOST_KEY] = null;
      });
    }
  } catch (e) {
    console.error("[peer-link] host 启动失败:", e);
  }
}
