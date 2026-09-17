/* ───────────────────────────────────────────────────────────────────────────
   Shared dashboard menu.

   Every page used to reach the others only by going back to the index, which
   carried a wall of 15 unlabelled chips in the header. This replaces both with
   one hamburger + grouped drawer, injected into whatever header the page has.

   Adding a dashboard means adding one entry to NAV_GROUPS and one
   `<script src="/app-nav.js" defer></script>` tag to the new page. Names here
   are the app's canonical labels — each page's own <h1> and <title> match them.

   It also carries the Facebook session pill. Every number on every tab is
   Shopify data and needs no Facebook at all; the Meta connection is only for
   creative previews, Ads Manager links and the ad-level Meta pulls. But when it
   IS missing the symptom is silent — ad names sit on "resolving…" — so the pill
   lives in the header of every page rather than in the drawer.
   ─────────────────────────────────────────────────────────────────────────── */
(function () {
  const NAV_GROUPS = [
    {
      label: 'Daily',
      items: [
        { href: '/daily-report.html',       name: 'Morning Brief',            desc: 'Auto-generated each weekday, grounded in Shopify session data' },
        { href: '/all-tabs-analysis.html',  name: 'Tab Summaries',            desc: 'Run an automated summary of any dashboard for a date range' },
      ],
    },
    {
      label: 'Conversion rate — why it moved',
      items: [
        { href: '/conversion-impact.html',  name: 'CVR by Traffic Source',    desc: 'Every utm_source: which channels moved blended CVR' },
        { href: '/meta-cvr-impact.html',    name: 'CVR · Meta Paid Social',   desc: 'Meta campaigns, landing pages and ads behind the change' },
        { href: '/google-cvr-impact.html',  name: 'CVR · Google',             desc: 'Google-family campaigns, source/medium and landing pages' },
        { href: '/owned-cvr-impact.html',   name: 'CVR · Email & SMS',      desc: 'Klaviyo and Attentive programs, flow steps and landing pages' },
        { href: '/cvr-decomposition.html',  name: 'Rate vs Mix Attribution',  desc: 'Splits a UTM slice into rate, mix, entry and exit effects' },
        { href: '/funnel-breakdown.html',   name: 'Funnel Drop-Off',          desc: 'Session → engaged → cart → checkout → purchase, by source' },
      ],
    },
    {
      label: 'Order value',
      items: [
        { href: '/aov-impact.html',         name: 'AOV by Traffic Source',    desc: 'Per-source decomposition of revenue and blended AOV' },
        { href: '/meta-aov-impact.html',    name: 'AOV · Meta Paid Social',   desc: 'Campaign, ad and landing-page decomposition of Meta AOV' },
        { href: '/product-mix.html',        name: 'Product Mix & Units',      desc: 'Units per product period over period, share of units, and each one\'s AOV impact' },
      ],
    },
    {
      label: 'Landing pages & traffic',
      items: [
        { href: '/lp-by-channel.html',      name: 'Landing Pages by Channel', desc: 'Top landing pages with a colour-coded funnel per channel' },
        { href: '/quality-of-traffic.html', name: 'Traffic Quality',          desc: 'Bounce, add-to-cart, duration and CVR by channel vs 7d/30d' },
      ],
    },
    {
      label: 'Meta ads & creative',
      items: [
        { href: '/',                        name: 'Top Ads by Spend',         desc: 'Highest-spend Meta ads with creatives and destination URLs', match: ['/', '/index.html'] },
        { href: '/ad-diagnostic.html',      name: 'Ad Diagnostic',            desc: 'Meta spend joined to Shopify sessions, ad by ad' },
        { href: '/campaign-analysis.html',  name: 'Campaign Performance',     desc: 'Campaign metrics day by day over a date range' },
        { href: '/creative-fatigue.html',   name: 'Creative Fatigue',         desc: 'Per-ad lifecycle scoring with runway projection' },
        { href: '/ad-set-fatigue.html',     name: 'Ad-Set Fatigue',           desc: 'Six-signal fatigue score per ad set, testing vs scaling' },
      ],
    },
    {
      label: 'Tools',
      items: [
        { href: '/debug.html',              name: 'Meta API Debug',           desc: 'Trace how ad destination URLs get resolved' },
      ],
    },
  ];

  const CSS = `
    .appnav-btn {
      display: inline-flex; align-items: center; gap: 8px;
      background: rgba(255,255,255,0.14); color: #fff;
      border: 1px solid rgba(255,255,255,0.35); border-radius: 8px;
      font: inherit; font-size: 0.82rem; font-weight: 600;
      padding: 7px 12px; cursor: pointer; white-space: nowrap;
      flex-shrink: 0;
    }
    .appnav-btn:hover { background: rgba(255,255,255,0.26); }
    .appnav-btn__bars { display: inline-flex; flex-direction: column; gap: 3px; }
    .appnav-btn__bars i { display: block; width: 15px; height: 2px; background: currentColor; border-radius: 2px; }
    /* Pages without a <header> get a floating light-themed button instead. */
    .appnav-btn--float {
      position: fixed; top: 12px; left: 12px; z-index: 9000;
      background: #1877f2; border-color: #1877f2;
      box-shadow: 0 2px 10px rgba(0,0,0,0.18);
    }
    .appnav-btn--float:hover { background: #0f61d4; }

    /* Headers are flex with space-between; adding the button as a third child
       would otherwise strand the page title in the middle of the bar. */
    header > h1 { margin-right: auto; }

    /* Facebook session pill. Mirrors .appnav-btn so it sits in a coloured header,
       with a float variant for the pages that have no <header> at all. */
    .appnav-fb {
      display: inline-flex; align-items: center; gap: 6px;
      border-radius: 8px; font: inherit; font-size: 0.78rem; font-weight: 600;
      padding: 6px 11px; white-space: nowrap; text-decoration: none;
      flex-shrink: 0; cursor: pointer;
      background: rgba(255,255,255,0.14); color: #fff;
      border: 1px solid rgba(255,255,255,0.35);
    }
    .appnav-fb__dot {
      width: 7px; height: 7px; border-radius: 50%; background: currentColor;
      flex-shrink: 0; opacity: 0.9;
    }
    /* Connected is ambient: legible, not loud. */
    .appnav-fb--on { opacity: 0.85; }
    .appnav-fb--on:hover { opacity: 1; background: rgba(255,255,255,0.26); }
    /* Disconnected is the only state worth interrupting for — previews are dead
       until it's fixed, and nothing else on the page says so. */
    .appnav-fb--off { background: #ffb020; color: #3d2b00; border-color: #ffb020; }
    .appnav-fb--off:hover { background: #ffc248; }
    .appnav-fb--pending { opacity: 0.6; }
    .appnav-fb__count { font-weight: 500; opacity: 0.8; }
    .appnav-fb--float {
      position: fixed; top: 12px; right: 12px; z-index: 9000;
      box-shadow: 0 2px 10px rgba(0,0,0,0.18);
      background: #1877f2; border-color: #1877f2; color: #fff;
    }
    .appnav-fb--float.appnav-fb--off { background: #ffb020; border-color: #ffb020; color: #3d2b00; }

    .appnav-scrim {
      position: fixed; inset: 0; background: rgba(15,22,36,0.45);
      opacity: 0; pointer-events: none; transition: opacity 0.16s;
      z-index: 9500;
    }
    .appnav-scrim.open { opacity: 1; pointer-events: auto; }

    .appnav-panel {
      position: fixed; top: 0; left: 0; bottom: 0; width: 340px; max-width: 86vw;
      background: #fff; z-index: 9600;
      box-shadow: 4px 0 24px rgba(0,0,0,0.18);
      transform: translateX(-102%); transition: transform 0.18s ease-out;
      display: flex; flex-direction: column;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .appnav-panel.open { transform: none; }
    .appnav-panel__head {
      display: flex; align-items: center; gap: 10px;
      padding: 14px 16px; background: #1877f2; color: #fff;
    }
    .appnav-panel__title { font-size: 0.95rem; font-weight: 700; flex: 1; }
    .appnav-panel__close {
      background: none; border: none; color: #fff; font-size: 1.3rem;
      line-height: 1; cursor: pointer; padding: 2px 6px; border-radius: 6px;
    }
    .appnav-panel__close:hover { background: rgba(255,255,255,0.2); }
    .appnav-panel__body { overflow-y: auto; padding: 6px 0 18px; }

    .appnav-group { padding: 10px 16px 2px; }
    .appnav-group__label {
      font-size: 0.66rem; font-weight: 800; text-transform: uppercase;
      letter-spacing: 0.11em; color: #8a94a6;
    }
    .appnav-item {
      display: block; text-decoration: none; color: #1c1e21;
      padding: 8px 16px 8px 14px; border-left: 3px solid transparent;
    }
    .appnav-item:hover { background: #f2f6ff; border-left-color: #c5d4f5; }
    .appnav-item__name { font-size: 0.85rem; font-weight: 600; }
    .appnav-item__desc { font-size: 0.72rem; color: #65676b; margin-top: 1px; line-height: 1.35; }
    .appnav-item--current {
      background: #eef3ff; border-left-color: #1877f2;
    }
    .appnav-item--current .appnav-item__name { color: #1877f2; }
    .appnav-item--current .appnav-item__name::after {
      content: ' · you are here'; font-weight: 500; font-size: 0.72rem; color: #65676b;
    }
  `;

  const norm = p => {
    const s = (p || '').replace(/\/+$/, '');
    return s === '' ? '/' : s;
  };

  // ── Facebook session pill ────────────────────────────────────────────────
  // Only the Meta-backed features need it: creative previews, Ads Manager deep
  // links, and the ad-level pulls on the Meta tabs. Shopify numbers are
  // unaffected, so the pill never blocks anything — it just says what state the
  // connection is in and offers the one-click fix.
  const authHref = (path) => path + '?next=' + encodeURIComponent(location.pathname + location.search);

  function buildFbPill(header) {
    const pill = document.createElement('a');
    pill.className = 'appnav-fb appnav-fb--pending';
    pill.innerHTML = '<span class="appnav-fb__dot"></span>Facebook…';
    pill.title = 'Checking the Facebook connection…';
    pill.href = authHref('/auth/facebook');

    if (header) header.insertBefore(pill, header.children[1] || null);
    else { pill.classList.add('appnav-fb--float'); document.body.appendChild(pill); }

    let connected = null;

    const paint = () => {
      pill.classList.remove('appnav-fb--pending', 'appnav-fb--on', 'appnav-fb--off');
      if (connected === null) {
        pill.classList.add('appnav-fb--pending');
        return;
      }
      if (connected) {
        pill.classList.add('appnav-fb--on');
        pill.innerHTML = '<span class="appnav-fb__dot"></span>Facebook connected' + progressHtml();
        pill.title = 'Connected to Facebook — creative previews and Ads Manager links work. Click to disconnect.';
        pill.href = authHref('/auth/logout');
      } else {
        pill.classList.add('appnav-fb--off');
        pill.innerHTML = '<span class="appnav-fb__dot"></span>Connect Facebook';
        pill.title = 'Not connected to Facebook. Ad-name previews and Ads Manager links stay blank until you sign in; '
          + 'every Shopify number on the page works without it.';
        pill.href = authHref('/auth/facebook');
      }
    };

    // Resolving an ad name is two Meta calls behind a 2-worker queue, so a big
    // table takes a while. Showing the count is the difference between "working"
    // and "stuck" — the question that sent us looking at the connection.
    function progressHtml() {
      const s = window.AdLink && window.AdLink.state;
      if (!s || !s.seen.size) return '';
      const done = s.resolved + s.failed;
      if (done >= s.seen.size) return ` <span class="appnav-fb__count">· ${s.resolved}/${s.seen.size} previews</span>`;
      return ` <span class="appnav-fb__count">· ${done}/${s.seen.size} previews…</span>`;
    }

    fetch('/api/auth-status')
      .then(r => r.json())
      .then(j => { connected = !!j.authenticated; paint(); })
      .catch(() => { connected = false; paint(); });

    // The resolver hit a 401 mid-flight: the status we fetched at load is stale.
    document.addEventListener('adlink-auth-failed', () => { connected = false; paint(); });

    if (window.AdLink) {
      let tick = null;
      window.AdLink.onProgress(() => {
        if (tick) return;                       // one repaint per second is plenty
        tick = setTimeout(() => { tick = null; if (connected) paint(); }, 1000);
      });
    }
  }

  function build() {
    const style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    const here = norm(location.pathname);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'appnav-btn';
    btn.setAttribute('aria-label', 'Open dashboard menu');
    btn.innerHTML = `<span class="appnav-btn__bars"><i></i><i></i><i></i></span>Dashboards`;

    // Sits at the start of whatever header the page has; pages built without a
    // header (Tab Summaries) get a floating button so the menu is never absent.
    const header = document.querySelector('header');
    if (header) header.insertBefore(btn, header.firstChild);
    else {
      btn.classList.add('appnav-btn--float');
      document.body.appendChild(btn);
    }

    buildFbPill(header);

    const scrim = document.createElement('div');
    scrim.className = 'appnav-scrim';

    const panel = document.createElement('nav');
    panel.className = 'appnav-panel';
    panel.setAttribute('aria-label', 'Dashboards');
    panel.innerHTML = `
      <div class="appnav-panel__head">
        <span class="appnav-panel__title">Dashboards</span>
        <button type="button" class="appnav-panel__close" aria-label="Close menu">×</button>
      </div>
      <div class="appnav-panel__body">
        ${NAV_GROUPS.map(g => `
          <div class="appnav-group"><span class="appnav-group__label">${g.label}</span></div>
          ${g.items.map(it => {
            const targets = (it.match || [it.href]).map(norm);
            const current = targets.includes(here);
            return `<a class="appnav-item${current ? ' appnav-item--current' : ''}" href="${it.href}"${current ? ' aria-current="page"' : ''}>
              <div class="appnav-item__name">${it.name}</div>
              <div class="appnav-item__desc">${it.desc}</div>
            </a>`;
          }).join('')}
        `).join('')}
        <div class="appnav-group"><span class="appnav-group__label">Session</span></div>
        <a class="appnav-item" href="${authHref('/auth/facebook')}">
          <div class="appnav-item__name">Connect Facebook</div>
          <div class="appnav-item__desc">Needed only for creative previews, Ads Manager links and the Meta tabs — returns you to this page</div>
        </a>
        <a class="appnav-item" href="/logout">
          <div class="appnav-item__name">Sign out</div>
          <div class="appnav-item__desc">Clears the shared-password session on this browser</div>
        </a>
      </div>`;

    document.body.appendChild(scrim);
    document.body.appendChild(panel);

    const setOpen = open => {
      panel.classList.toggle('open', open);
      scrim.classList.toggle('open', open);
      if (open) panel.querySelector('.appnav-item--current, .appnav-item').focus?.();
    };
    btn.addEventListener('click', () => setOpen(!panel.classList.contains('open')));
    scrim.addEventListener('click', () => setOpen(false));
    panel.querySelector('.appnav-panel__close').addEventListener('click', () => setOpen(false));
    document.addEventListener('keydown', e => { if (e.key === 'Escape') setOpen(false); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', build);
  else build();
})();
