// main.js — 命令行界面。协议与状态在 core.js，网页界面在 web.js。

import path from "node:path";
import {
  activePairing,
  allWorkspaces,
  helloTo,
  lanAddresses,
  listSessions,
  loadState,
  pairTo,
  removePeer,
  requestTo,
  revokeGrant,
  saveState,
  setPairingCode,
  setPolicy,
  short,
  startPeerServer,
  stateSummary,
} from "./core.js";

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true;
      out[k] = v;
    } else out._.push(a);
  }
  return out;
}

const name = (args) => args.name || "default";

// ---------------- allow ----------------

async function cmdAllow(args) {
  const st0 = loadState(name(args));
  if (args.workspaces) {
    st0.workspaces = String(args.workspaces).split(",").map((s) => s.trim()).filter(Boolean);
  }
  if (args["dsh-home"]) st0.dshHome = args["dsh-home"];
  saveState(st0);

  const port = Number(args.port || 41234);
  const host = args.host || "0.0.0.0";
  const ttl = Number(args.ttl || 120);

  const log = (m) => {
    const t = new Date().toLocaleTimeString();
    console.log(`[${t}] ${m}`);
  };

  await startPeerServer({ name: name(args), port, host, log });
  const { code, expiresAt, ttlSec } = setPairingCode(name(args), ttl);
  const st = loadState(name(args));

  console.log("=== 允许连接本机 ===");
  console.log("device id  :", st.deviceId);
  console.log("cert fp    :", st.fingerprint);
  console.log("listen     :", `${host}:${port}`);
  console.log("可达地址   :");
  for (const a of lanAddresses()) console.log("   ", `${a.address} (${a.iface})`);
  console.log("工作区     :", st.workspaces.length ? st.workspaces.join(", ") : "(未配置，用 --workspaces 指定)");
  console.log("配对码     :", code, `（${ttlSec} 秒内有效，一次性）`);
  console.log("到期       :", new Date(expiresAt).toLocaleTimeString());
  console.log("");
}

// ---------------- pair / hello ----------------

async function cmdPair(args) {
  if (!args.addr || !args.code) {
    console.error("用法: node main.js pair --name cli --addr host:port --code 12345678");
    process.exit(1);
  }
  const r = await pairTo({ name: name(args), addr: args.addr, code: String(args.code) });
  if (!r.ok) {
    console.error("配对失败:", r.reason, r.detail || "");
    process.exit(2);
  }
  console.log("=== 配对成功 ===");
  console.log("对端设备 :", r.peer.displayName, `(${r.peer.deviceId.slice(0, 8)}…)`);
  console.log("对端指纹 :", short(r.peer.fingerprint), "（已固定）");
  console.log("连接票据 :", short(r.peer.ticket), `有效期至 ${new Date(r.peer.ticketExpiresAt).toLocaleString()}`);
}

async function cmdHello(args) {
  const r = await helloTo({ name: name(args), addr: args.addr });
  if (!r.ok) {
    console.error("认证失败:", r.reason);
    process.exit(2);
  }
  console.log("=== 认证成功 ===");
  console.log("对端:", r.welcome.displayName, "| 可见工作区:", r.welcome.workspaces);
}

async function cmdRequest(args, method, label) {
  const r = await requestTo({ name: name(args), addr: args.addr, method, payload: args.id ? { id: args.id } : null });
  console.log(`--- ${label} ---`);
  console.log(JSON.stringify(r, null, 2));
  if (!r.ok) process.exitCode = 2;
}

// ---------------- 管理 ----------------

function cmdWorkspaces(args) {
  const st = loadState(name(args));
  if (args.set) {
    st.workspaces = String(args.set).split(",").map((s) => s.trim()).filter(Boolean);
    saveState(st);
  }
  console.log("=== 本机工作区 ===");
  for (const w of allWorkspaces(st)) console.log(`  ${w.name}  ${w.id}  ${w.path}`);
  if (!st.workspaces.length) console.log("  (未配置)");
}

function cmdPolicy(args) {
  if (!args.device) {
    console.error("用法: node main.js policy --name srv --device <id> --mode all|selected [--workspaces id1,id2]");
    process.exit(1);
  }
  const ids = args.workspaces ? String(args.workspaces).split(",").map((s) => s.trim()).filter(Boolean) : [];
  const r = setPolicy(name(args), args.device, { mode: args.mode, ids });
  if (!r.ok) {
    console.error("找不到该设备:", r.error);
    process.exit(1);
  }
  console.log(`已更新 ${r.grant.displayName} 的访问策略:`);
  console.log("  mode      :", r.grant.policy.mode);
  console.log("  workspaces:", r.grant.policy.ids.length ? r.grant.policy.ids.join(", ") : "(全部)");
}

function cmdRevoke(args) {
  const r = revokeGrant(name(args), args.device);
  if (!r.ok) {
    console.error("找不到该设备:", r.error);
    process.exit(1);
  }
  console.log("已撤销:", r.grant.displayName);
}

function cmdUnpair(args) {
  const r = removePeer(name(args), args.device);
  if (!r.ok) {
    console.error("找不到该对端:", r.error);
    process.exit(1);
  }
  console.log("已移除对端:", r.peer.displayName);
}

function cmdStatus(args) {
  const s = stateSummary(name(args));
  console.log("=== 本机 ===");
  console.log("name      :", s.name);
  console.log("device id :", s.deviceId);
  console.log("cert fp   :", s.fingerprint);
  console.log("会话目录  :", s.dshHome);
  console.log("工作区    :", s.workspaces.length ? s.workspaces.map((w) => w.path).join(", ") : "(未配置)");
  if (s.pairing) console.log("配对码    :", s.pairing.code, `（剩 ${s.pairing.secondsLeft}s）`);

  console.log("\n=== 我配对的对端 (peers) ===");
  if (!s.peers.length) console.log("  (无)");
  for (const p of s.peers) {
    const left = p.ticketExpiresAt ? Math.round((p.ticketExpiresAt - Date.now()) / 60000) : 0;
    console.log(`  ${p.displayName} ${p.deviceId.slice(0, 8)}… ${p.address} fp=${short(p.fingerprint)} ticket=${left > 0 ? left + "min" : "过期"}`);
  }

  console.log("\n=== 允许控制我的设备 (grants) ===");
  if (!s.grants.length) console.log("  (无)");
  for (const g of s.grants) {
    const pol = g.policy;
    console.log(`  ${g.displayName} ${g.deviceId.slice(0, 8)}… fp=${short(g.fingerprint)} policy=${pol.mode}${pol.mode === "selected" ? "[" + (pol.ids || []).join(",") + "]" : ""}${g.revokedAt ? " REVOKED" : ""}`);
  }

  if (s.recentRequests.length) {
    console.log("\n=== 最近请求 ===");
    for (const q of s.recentRequests.slice(0, 5)) {
      console.log(`  ${new Date(q.receivedAt).toLocaleTimeString()} ${q.method} ${q.stage} by ${q.deviceId.slice(0, 8)}…`);
    }
  }
}

// ---------------- dispatch ----------------

const [, , cmd, ...rest] = process.argv;
const args = parseArgs(rest);
const a = name(args);

switch (cmd) {
  case "allow": await cmdAllow(args); break;
  case "pair": await cmdPair(args); break;
  case "hello": await cmdHello(args); break;
  case "workspaces": cmdWorkspaces(args); break;
  case "remote-workspaces": await cmdRequest(args, "workspaces.list", "远端工作区"); break;
  case "sessions": await cmdRequest(args, "session.list", "远端会话"); break;
  case "policy": cmdPolicy(args); break;
  case "revoke": cmdRevoke(args); break;
  case "unpair": cmdUnpair(args); break;
  case "status": cmdStatus(args); break;
  default:
    console.log(`用法:
  allow             --name srv --port 41234 [--ttl 120] [--dsh-home ~/.dsh] [--workspaces "D:\\a,D:\\b"]
  pair              --name cli --addr host:port --code 12345678
  hello             --name cli --addr host:port
  remote-workspaces --name cli --addr host:port
  sessions          --name cli --addr host:port
  workspaces        --name srv [--set "D:\\a,D:\\b"]
  policy            --name srv --device <id> --mode all|selected [--workspaces id1,id2]
  revoke            --name srv --device <id>
  unpair            --name cli --device <id>
  status            --name srv`);
}
