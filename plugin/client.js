window.__ModuleLoader__.load({
  id: 'dsh-peer-link',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    // 侧栏条目与主面板座位共用同一个 id
    const PANEL_ID = 'peer-link';
    const URL_KEY = 'peer-link:url';

    function readUrl() {
      try {
        return window.localStorage.getItem(URL_KEY) || '';
      } catch {
        return '';
      }
    }

    function PeerLinkPanel() {
      const [url, setUrl] = React.useState(readUrl);
      const [draft, setDraft] = React.useState('');

      const save = () => {
        const next = draft.trim();
        try {
          window.localStorage.setItem(URL_KEY, next);
        } catch {}
        setUrl(next);
        setDraft('');
      };

      if (!url) {
        return h(
          'div',
          { style: { padding: '32px', maxWidth: '560px', margin: '0 auto', fontFamily: 'inherit' } },
          h('h2', { style: { fontSize: '18px', margin: '0 0 8px' } }, '远端设备'),
          h(
            'p',
            { style: { color: '#6b7280', fontSize: '13px', margin: '0 0 20px' } },
            '还没有指定远端地址。隧道起来后，把本地地址填进来（例如 http://127.0.0.1:54330/?token=…）。'
          ),
          h('input', {
            value: draft,
            onChange: (e) => setDraft(e.target.value),
            placeholder: 'http://127.0.0.1:54330/?token=…',
            style: {
              width: '100%',
              padding: '8px 10px',
              border: '1px solid #d1d5db',
              borderRadius: '7px',
              font: 'inherit',
              boxSizing: 'border-box',
            },
          }),
          h(
            'button',
            {
              onClick: save,
              style: {
                marginTop: '12px',
                padding: '8px 16px',
                border: 0,
                borderRadius: '7px',
                background: '#111827',
                color: '#fff',
                font: 'inherit',
                cursor: 'pointer',
              },
            },
            '连接'
          )
        );
      }

      return h(
        'div',
        { style: { display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 } },
        h(
          'div',
          {
            style: {
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '6px 12px',
              fontSize: '12px',
              color: '#6b7280',
              borderBottom: '1px solid #e5e7eb',
            },
          },
          h('span', { style: { flex: '1 1 auto', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, url),
          h(
            'button',
            {
              onClick: () => {
                try {
                  window.localStorage.removeItem(URL_KEY);
                } catch {}
                setUrl('');
              },
              style: {
                border: '1px solid #d1d5db',
                background: '#fff',
                borderRadius: '6px',
                padding: '2px 10px',
                font: 'inherit',
                cursor: 'pointer',
              },
            },
            '断开'
          )
        ),
        h('iframe', {
          src: url,
          title: '远端 DSH',
          style: { flex: '1 1 auto', width: '100%', border: 0, background: '#fff', minHeight: 0 },
        })
      );
    }

    function PeerLinkIcon() {
      return h(
        'svg',
        { viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': true, style: { display: 'block' } },
        h('rect', { x: 1, y: 3, width: 9, height: 7, rx: 1.5, fill: 'none', stroke: 'currentColor', strokeWidth: 1.3 }),
        h('rect', { x: 8, y: 7, width: 7, height: 6, rx: 1.5, fill: 'none', stroke: 'currentColor', strokeWidth: 1.3 })
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('main', function* () {
          yield ctx.slots.register({ name: 'main', key: PANEL_ID }, PeerLinkPanel);
        });

        ctx.slots.inject('sidebar.panellist', () =>
          ctx.slots.register(
            {
              name: 'sidebar.panellist',
              id: PANEL_ID,
              order: 20,
              locale: 'peerLink',
              label: () => '远端设备',
            },
            PeerLinkIcon
          )
        );
      },
    };
  },
});
