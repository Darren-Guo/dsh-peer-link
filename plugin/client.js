window.__ModuleLoader__.load({
  id: 'dsh-peer-link',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useState, useEffect, useCallback, useMemo } = React;

    const PANEL_ID = 'peer-link';
    const API_PORTS = [41730, 41731, 41732, 41733, 41734, 41735];

    const css = {
      wrap: { display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, font: 'inherit' },
      bar: {
        display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
        borderBottom: '1px solid var(--dsw-alias-border, #e5e7eb)', flex: '0 0 auto',
      },
      tab: (on) => ({
        border: 0,
        background: on ? 'var(--dsw-alias-bg-hover, #eef0f3)' : 'transparent',
        padding: '5px 12px', borderRadius: 6, font: 'inherit', cursor: 'pointer',
        color: on ? 'var(--dsw-alias-text, #111)' : 'var(--dsw-alias-text-2, #6b7280)',
        fontWeight: on ? 600 : 400,
      }),
      body: { flex: '1 1 auto', minHeight: 0, overflow: 'auto', padding: '14px 16px' },
      card: { border: '1px solid var(--dsw-alias-border, #e5e7eb)', borderRadius: 9, padding: 12, marginBottom: 10 },
      row: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
      input: {
        width: '100%', padding: '7px 9px', border: '1px solid var(--dsw-alias-border, #d1d5db)',
        borderRadius: 7, font: 'inherit', boxSizing: 'border-box', background: 'transparent', color: 'inherit',
      },
      label: { fontSize: 12, color: 'var(--dsw-alias-text-2, #6b7280)', marginBottom: 5, display: 'block' },
      btn: (primary) => ({
        padding: '6px 13px', borderRadius: 7, font: 'inherit', cursor: 'pointer',
        border: primary ? 0 : '1px solid var(--dsw-alias-border, #d1d5db)',
        background: primary ? '#111827' : 'transparent', color: primary ? '#fff' : 'inherit',
      }),
      muted: { fontSize: 12, color: 'var(--dsw-alias-text-2, #6b7280)' },
      code: { fontFamily: 'ui-monospace, Consolas, monospace', fontSize: 26, letterSpacing: 5 },
      err: { fontSize: 12, color: '#b91c1c' },
    };

    async function call(base, path, body) {
      const r = await fetch(base + path, body
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
        : {});
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    }

    async function findApi() {
      for (const p of API_PORTS) {
        const base = 'http://127.0.0.1:' + p;
        try {
          const r = await fetch(base + '/api/state', { signal: AbortSignal.timeout(1200) });
          if (r.ok) return base;
        } catch (e) { /* 下一个 */ }
      }
      return null;
    }

    function PeerLinkPanel() {
      const [base, setBase] = useState(null);
      const [state, setState] = useState(null);
      const [tab, setTab] = useState('devices');
      const [msg, setMsg] = useState('');
      const [addr, setAddr] = useState('');
      const [code, setCode] = useState('');
      const [needTokenFor, setNeedTokenFor] = useState(null);
      const [tokenDraft, setTokenDraft] = useState('');
      const [wsDraft, setWsDraft] = useState('');

      const refresh = useCallback(async () => {
        const b = base || (await findApi());
        if (!b) { setBase(null); return; }
        if (b !== base) setBase(b);
        try {
          const s = await call(b, '/api/state');
          setState(s);
        } catch (e) {
          setMsg('读取状态失败: ' + e.message);
        }
      }, [base]);

      useEffect(() => {
        refresh();
        const t = setInterval(refresh, 3000);
        return () => clearInterval(t);
      }, [refresh]);

      const live = state && state.connections && state.connections.length ? state.connections[0] : null;
      const peers = (state && state.peers) || [];
      const grants = (state && state.grants) || [];

      // 已连接：整块面板显示远端界面
      if (live) {
        const name = (peers.find((p) => p.deviceId === live.deviceId) || {}).displayName || '远端';
        const onDisc = async () => {
          await call(base, '/api/disconnect', { device: live.deviceId }).catch(() => {});
          refresh();
        };
        return h('div', { style: css.wrap },
          h('div', { style: css.bar },
            h('span', { style: Object.assign({}, css.muted, { flex: '1 1 auto', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }) }, name + ' · ' + live.url),
            h('button', { style: css.btn(false), onClick: onDisc }, '断开'),
            h('button', { style: css.btn(false), onClick: refresh }, '刷新')),
          h('iframe', { src: live.url, title: '远端 DSH', style: { flex: '1 1 auto', width: '100%', border: 0, background: '#fff', minHeight: 0 } })
        );
      }

      if (!base || !state) {
        return h('div', { style: { padding: 24 } },
          h('div', { style: { fontSize: 15, marginBottom: 8 } }, '远端设备'),
          h('div', { style: css.muted }, base ? '正在读取状态…' : 'Host 侧未就绪（控制端口 41730–41735 无响应）。确认插件已启用。'));
      }

      const post = (path, body) => call(base, path, body).catch((e) => { setMsg(e.message); });

      const doPair = async () => {
        setMsg('');
        const r = await post('/api/pair', { addr: addr.trim(), code: code.trim() });
        if (r && !r.ok) setMsg('配对失败: ' + r.reason);
        else if (r) { setAddr(''); setCode(''); setMsg('配对成功'); }
        refresh();
      };

      const doConnect = async (deviceId) => {
        setMsg('');
        const r = await post('/api/connect', { device: deviceId });
        if (r && !r.ok && r.needToken) { setNeedTokenFor(deviceId); return; }
        if (r && !r.ok) setMsg('连接失败: ' + (r.error || ''));
        refresh();
      };

      const doConnectWithToken = async () => {
        const r = await post('/api/connect', { device: needTokenFor, token: tokenDraft.trim() });
        if (r && r.ok) { setNeedTokenFor(null); setTokenDraft(''); }
        refresh();
      };

      // ---- 设备 pane ----
      const peerCards = peers.map((p) => {
        const tokenRow = needTokenFor === p.deviceId
          ? h('div', { style: { marginTop: 10 } },
              h('label', { style: css.label }, '这台设备需要 DSH 登录令牌（在对端启动输出里）'),
              h('input', { style: css.input, value: tokenDraft, placeholder: '粘贴令牌', onChange: (e) => setTokenDraft(e.target.value) }),
              h('div', { style: { marginTop: 8 } }, h('button', { style: css.btn(true), onClick: doConnectWithToken }, '用这个令牌连接')))
          : null;
        return h('div', { key: p.deviceId, style: css.card },
          h('div', { style: css.row },
            h('b', null, p.displayName),
            h('span', { style: css.muted }, p.address),
            h('span', { style: { flex: '1 1 auto' } }),
            h('button', { style: css.btn(true), onClick: () => doConnect(p.deviceId) }, '打开远端界面'),
            h('button', {
              style: css.btn(false),
              onClick: async () => { await post('/api/unpair', { device: p.deviceId }); refresh(); },
            }, '移除')),
          tokenRow);
      });

      const devicesPane = h('div', null,
        peers.length === 0
          ? h('div', { style: css.muted }, '还没有配对任何设备。切到「配对」添加。')
          : peerCards);

      // ---- 配对 pane ----
      const pairPane = h('div', null,
        h('div', { style: css.card },
          h('label', { style: css.label }, '设备地址'),
          h('input', { style: css.input, value: addr, placeholder: '100.64.0.4:41234', onChange: (e) => setAddr(e.target.value) }),
          h('div', { style: { height: 10 } }),
          h('label', { style: css.label }, '配对码（在对方「本机」页生成）'),
          h('input', { style: css.input, value: code, placeholder: '8 位数字', maxLength: 8, onChange: (e) => setCode(e.target.value) }),
          h('div', { style: { marginTop: 12 } }, h('button', { style: css.btn(true), onClick: doPair }, '添加设备'))));

      // ---- 本机 pane ----
      const wsText = wsDraft || (state.workspaces || []).map((w) => w.path).join('\n');
      const grantRows = grants.map((g) => h('div', { key: g.deviceId, style: Object.assign({}, css.row, { padding: '6px 0' }) },
        h('b', null, g.displayName),
        h('span', { style: css.muted }, (g.policy && g.policy.mode === 'all') ? '全部工作区' : '仅选中'),
        g.revokedAt ? h('span', { style: css.err }, '已撤销') : null,
        h('span', { style: { flex: '1 1 auto' } }),
        g.revokedAt ? null : h('button', {
          style: css.btn(false),
          onClick: async () => { await post('/api/revoke', { device: g.deviceId }); refresh(); },
        }, '撤销')));

      const localPane = h('div', null,
        h('div', { style: css.card },
          h('div', { style: css.row },
            h('span', { style: css.label }, '配对码'),
            h('span', { style: { flex: '1 1 auto' } }),
            h('button', {
              style: css.btn(false),
              onClick: async () => { await post('/api/code', { ttl: 600 }); refresh(); },
            }, '生成新码')),
          state.pairing
            ? h('div', null,
                h('div', { style: css.code }, state.pairing.code),
                h('div', { style: css.muted }, '剩余 ' + state.pairing.secondsLeft + ' 秒'))
            : h('div', { style: css.muted }, '点击「生成新码」'),
          h('div', { style: { marginTop: 14 } },
            h('div', { style: css.muted }, '本机地址：' + ((state.addresses || []).map((a) => a.address).join('  ') || '—')),
            h('div', { style: css.muted }, '被控端端口：' + state.peerPort)),
          h('div', { style: { marginTop: 12 } },
            h('label', { style: css.label }, '我提供访问的工作区（每行一个路径）'),
            h('textarea', {
              rows: 3,
              style: Object.assign({}, css.input, { fontFamily: 'ui-monospace, Consolas, monospace', fontSize: 12, resize: 'vertical' }),
              value: wsText,
              onChange: (e) => setWsDraft(e.target.value),
            }),
            h('div', { style: { marginTop: 8 } },
              h('button', {
                style: css.btn(false),
                onClick: async () => {
                  const list = wsText.split('\n').map((s) => s.trim()).filter(Boolean);
                  await post('/api/workspaces', { list });
                  setWsDraft('');
                  refresh();
                },
              }, '保存工作区')))),
        h('div', { style: css.card },
          h('div', { style: css.label }, '已授权可以控制本机的设备'),
          grantRows.length === 0 ? h('div', { style: css.muted }, '还没有设备连接过') : grantRows));

      const pane = tab === 'devices' ? devicesPane : tab === 'pair' ? pairPane : localPane;

      return h('div', { style: css.wrap },
        h('div', { style: css.bar },
          h('button', { style: css.tab(tab === 'devices'), onClick: () => setTab('devices') }, '设备'),
          h('button', { style: css.tab(tab === 'pair'), onClick: () => setTab('pair') }, '配对'),
          h('button', { style: css.tab(tab === 'local'), onClick: () => setTab('local') }, '本机'),
          h('span', { style: { flex: '1 1 auto' } }),
          h('span', { style: css.muted }, state.deviceId.slice(0, 8) + '…'),
          h('button', { style: css.btn(false), onClick: refresh }, '刷新')),
        h('div', { style: css.body },
          msg ? h('div', { style: Object.assign({}, css.muted, { marginBottom: 10 }) }, msg) : null,
          pane));
    }

    function PeerLinkIcon() {
      return h('svg', { viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': true, style: { display: 'block' } },
        h('rect', { x: 1, y: 3, width: 9, height: 7, rx: 1.5, fill: 'none', stroke: 'currentColor', strokeWidth: 1.3 }),
        h('rect', { x: 8, y: 7, width: 7, height: 6, rx: 1.5, fill: 'none', stroke: 'currentColor', strokeWidth: 1.3 }));
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('main', function* () {
          yield ctx.slots.register({ name: 'main', key: PANEL_ID }, PeerLinkPanel);
        });
        ctx.slots.inject('sidebar.panellist', () =>
          ctx.slots.register(
            { name: 'sidebar.panellist', id: PANEL_ID, order: 20, locale: 'peerLink', label: () => '远端设备' },
            PeerLinkIcon));
      },
    };
  },
});
