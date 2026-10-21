/* ───────────────────────────────────────────────────────────────────────────
   Net AOV section, shared by the two AOV tabs.

   The tables already on those tabs work from order totals: shipping, tax and the
   SavedBy protection fee are inside "AOV", and protection lines and free gifts
   count as units. So when price/unit moves they can't say whether it was deeper
   discounts, cheaper products, protection, or gifts padding the unit count.
   This section reads /api/net-aov-data (line-item level) and answers that.

   Net AOV = paid product revenue after all discounts ÷ orders. Protection, free
   gifts ($0 list / type Gift) and units discounted to $0 are reported on their
   own and kept out of UPT and price/unit.

   A page mounts it with <div id="net-aov-root"></div> and calls
   NetAOV.load({ start, end, cs, ce, source, medium, groupDim }) from its own
   load(). It fetches one day per request (the endpoint has to read every order
   in the window before it can filter by channel, ~15-20s a store-day) and adds
   the days up; days are disjoint, so every sum and every histogram count is
   exact. A partial day would silently skew the comparison, so any failed or
   truncated day is surfaced, never quietly dropped.
   ─────────────────────────────────────────────────────────────────────────── */
(function () {
  // Two days in flight. The server already reads each day as six parallel
  // windows and Shopify's throughput is capped, so more doesn't help: on the full
  // store (renewals included, ~3,500 orders/day) two days side by side were
  // slower than back to back and three pushed every day past its time budget.
  // Scoped to the Online Store (~1,400 orders/day) two in flight is the faster
  // safe setting — a week against the week before took 108s vs 143s one at a
  // time, with no day truncated.
  const CONCURRENCY = 2;
  const FIELDS = ['orders', 'list', 'net', 'paid_units', 'protection', 'prot_orders',
    'gift_units', 'gift_orders', 'zero_units', 'zero_list', 'shipping', 'ship_waived', 'tax', 'tips', 'total'];
  const PARTS = ['C', 'C0', 'R', 'R0'];
  const DIMS = [
    ['order_type', 'Order type'],
    ['customer', 'New vs returning'],
    ['purchase', 'Subscription vs one-time'],
    ['discount', 'Discount type'],
    ['discount_code', 'Discount code'],
    ['protection', 'Protection attached'],
    ['gift', 'Free gift attached'],
    ['source', 'utm_source / medium'],
    ['campaign', 'utm_campaign'],
    ['landing_page', 'Landing page'],
  ];

  let root = null;
  let gen = 0;                       // bumps on every load so a stale fetch can't render
  let state = null;                  // { cur, prev, meta }
  const ui = { renewals: true, zeros: false, dim: 'order_type', minOrders: 20, lineDim: 'module', minUnits: 10 };

  // ── formatting ──
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fin = n => n != null && isFinite(n);
  const $2 = n => fin(n) ? (n < -0.004 ? '−' : '') + '$' + Math.abs(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : '—';
  const $0 = n => fin(n) ? '$' + Math.round(n).toLocaleString('en-US') : '—';
  const int = n => fin(n) ? Math.round(n).toLocaleString('en-US') : '—';
  const pct = n => fin(n) ? (n * 100).toFixed(1) + '%' : '—';
  const x2 = n => fin(n) ? n.toFixed(2) : '—';
  const sign = (n, f) => !fin(n) ? '—' : (n >= 0 ? '+' : '−') + f(Math.abs(n));
  const s$2 = n => sign(n, $2);
  const sInt = n => sign(n, int);
  const sPp = n => sign(n, v => (v * 100).toFixed(1) + 'pp');
  const sX2 = n => sign(n, v => v.toFixed(2));
  const cls = n => !fin(n) || Math.abs(n) < 1e-9 ? '' : (n > 0 ? 'num-pos' : 'num-neg');

  // ── aggregation ──
  const blank = () => Object.fromEntries(FIELDS.map(f => [f, 0]));
  const addTo = (a, b) => { for (const f of FIELDS) a[f] += b[f] || 0; return a; };
  const newPart = () => ({ totals: blank(), days: {}, seg: {}, hist_net: {}, hist_units: {}, lines: {} });
  const LINE_FIELDS = ['units', 'net', 'list', 'orders'];
  const LINE_DIMS = [
    ['module', 'Upsell module'],
    ['page', 'Page it was added from'],
    ['module_page', 'Upsell module × page'],
    ['product', 'Product'],
    ['module_product', 'Upsell module × product'],
    ['bundle', 'Bundle'],
  ];

  function mergePart(into, p) {
    addTo(into.totals, p.totals);
    for (const [d, v] of Object.entries(p.days)) addTo(into.days[d] ||= blank(), v);
    for (const [dim, m] of Object.entries(p.seg)) {
      const t = into.seg[dim] ||= {};
      for (const [k, v] of Object.entries(m)) addTo(t[k] ||= blank(), v);
    }
    for (const h of ['hist_net', 'hist_units']) {
      for (const [k, v] of Object.entries(p[h])) into[h][k] = (into[h][k] || 0) + v;
    }
    for (const [dim, m] of Object.entries(p.lines || {})) {
      const t = into.lines[dim] ||= {};
      for (const [k, v] of Object.entries(m)) {
        const g = t[k] ||= Object.fromEntries(LINE_FIELDS.map(f => [f, 0]));
        for (const f of LINE_FIELDS) g[f] += v[f] || 0;
      }
    }
  }

  // The parts the toggles currently include, merged into one aggregate.
  function view(period) {
    const keep = ['C'];
    if (ui.renewals) keep.push('R');
    if (ui.zeros) { keep.push('C0'); if (ui.renewals) keep.push('R0'); }
    const out = newPart();
    for (const k of keep) mergePart(out, period.parts[k]);
    return out;
  }

  // Ratios off one aggregate row. UPT and price/unit are paid lines only.
  function ratios(a) {
    const o = a.orders;
    return {
      orders: o,
      aov: o ? a.net / o : NaN,
      listPerOrder: o ? a.list / o : NaN,
      discPerOrder: o ? (a.list - a.net) / o : NaN,
      upt: o ? a.paid_units / o : NaN,
      listAsp: a.paid_units ? a.list / a.paid_units : NaN,
      netAsp: a.paid_units ? a.net / a.paid_units : NaN,
      discDepth: a.list ? 1 - a.net / a.list : NaN,
      protPerOrder: o ? a.protection / o : NaN,
      protAttach: o ? a.prot_orders / o : NaN,
      protFee: a.prot_orders ? a.protection / a.prot_orders : NaN,
      giftAttach: o ? a.gift_orders / o : NaN,
      giftUnitsPerOrder: o ? a.gift_units / o : NaN,
      zeroUnitsPerOrder: o ? a.zero_units / o : NaN,
      allUpt: o ? (a.paid_units + a.gift_units + a.zero_units + a.prot_orders) / o : NaN,
      shipPerOrder: o ? a.shipping / o : NaN,
      shipWaivedPerOrder: o ? a.ship_waived / o : NaN,
      taxPerOrder: o ? a.tax / o : NaN,
      tipsPerOrder: o ? a.tips / o : NaN,
      totalPerOrder: o ? a.total / o : NaN,
    };
  }

  // Net AOV = UPT × list price/unit × (1 − discount depth). Sequential split,
  // which sums exactly to the Δ: UPT first at old prices, then list price
  // (product mix / price changes) at new UPT, then discount depth.
  function driverSplit(p, c) {
    const keep0 = 1 - p.discDepth, keep1 = 1 - c.discDepth;
    const z = v => fin(v) ? v : 0;
    return {
      upt: z((c.upt - p.upt) * p.listAsp * keep0),
      price: z(c.upt * (c.listAsp - p.listAsp) * keep0),
      discount: z(c.upt * c.listAsp * (keep1 - keep0)),
    };
  }

  // Δ blended net AOV split per segment into a rate effect (the segment's own
  // AOV moved) and a mix effect (its share of orders moved, valued against the
  // old blended AOV). A segment missing from one period borrows its AOV from the
  // other, so its whole contribution is mix — the rows still sum to the total.
  function segmentSplit(segPrev, segCur, totPrev, totCur) {
    const B0 = totPrev.orders ? totPrev.net / totPrev.orders : 0;
    const keys = new Set([...Object.keys(segPrev || {}), ...Object.keys(segCur || {})]);
    return [...keys].map(k => {
      const a0 = segPrev?.[k] || blank(), a1 = segCur?.[k] || blank();
      const r0 = ratios(a0), r1 = ratios(a1);
      let c0 = a0.orders ? r0.aov : r1.aov;
      let c1 = a1.orders ? r1.aov : r0.aov;
      const s0 = totPrev.orders ? a0.orders / totPrev.orders : 0;
      const s1 = totCur.orders ? a1.orders / totCur.orders : 0;
      const rate = s0 * (c1 - c0);
      const mix = (s1 - s0) * (c1 - B0);
      return { key: k, a0, a1, r0, r1, s0, s1, rate, mix, total: rate + mix };
    });
  }

  function percentile(hist, p) {
    const bins = Object.keys(hist).map(Number).sort((a, b) => a - b);
    const n = bins.reduce((s, b) => s + hist[b], 0);
    if (!n) return NaN;
    let cum = 0;
    for (const b of bins) { cum += hist[b]; if (cum >= p * n) return b; }
    return bins[bins.length - 1];
  }

  // ── fetching ──
  function days(s, e) {
    const out = [];
    for (let d = new Date(s + 'T00:00:00Z'), last = new Date(e + 'T00:00:00Z'); d <= last; d = new Date(d.getTime() + 86400000)) {
      out.push(d.toISOString().slice(0, 10));
    }
    return out;
  }

  async function fetchDay(day, source, medium, channel) {
    const params = new URLSearchParams({ start: day, end: day });
    if (source) params.set('source', source);
    if (medium) params.set('medium', medium);
    if (channel) params.set('channel', channel);
    let lastErr;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const r = await fetch('/api/net-aov-data?' + params.toString());
        if (!r.ok) throw new Error('HTTP ' + r.status + ': ' + (await r.text()).slice(0, 200));
        return await r.json();
      } catch (e) { lastErr = e; }
    }
    throw lastErr;
  }

  function newPeriod(start, end) {
    return { start, end, parts: Object.fromEntries(PARTS.map(k => [k, newPart()])), scanned: 0, overflow: 0 };
  }

  async function load(opts) {
    root = root || document.getElementById('net-aov-root');
    if (!root) return;
    const my = ++gen;
    const { start, end, cs, ce, source = '', medium = '', channel = '', groupDim, shopifyAov = false } = opts;
    if (groupDim && my === 1) ui.dim = groupDim;
    // Shopify's own AOV, straight from ShopifyQL — only for the unscoped view,
    // since Shopify can't filter on the first-visit UTM the scoped tab uses.
    const shopifyP = shopifyAov
      ? fetch(`/api/shopify-aov-data?start=${start}&end=${end}&compare_start=${cs}&compare_end=${ce}`)
          .then(r => r.ok ? r.json() : Promise.reject(new Error('HTTP ' + r.status)))
          .catch(e => ({ error: e.message }))
      : Promise.resolve(null);
    const cur = newPeriod(start, end), prev = newPeriod(cs, ce);
    const jobs = [...days(start, end).map(d => [cur, d]), ...days(cs, ce).map(d => [prev, d])];
    let done = 0, failed = [];
    root.innerHTML = shell(`<div class="na-loading"><span class="spinner"></span><span class="na-loading__text">Loading net AOV — reading
        line items for ${jobs.length} days (about 10s a day)… 0 / ${jobs.length}</span>
        <div class="progress"><div style="width:0%"></div></div></div>`) + placeholders();
    collapse();

    let next = 0;
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, jobs.length) }, async () => {
      while (next < jobs.length) {
        const [period, day] = jobs[next++];
        try {
          // A day that ran out of time budget is missing its later orders, which
          // are the checkout orders (renewals land first) — retry it, and refuse
          // to render on a second miss rather than show a skewed comparison.
          let j = await fetchDay(day, source, medium, channel);
          if (j.truncated) j = await fetchDay(day, source, medium, channel);
          if (j.truncated) throw new Error('ran out of time budget twice, data would be partial');
          if (my !== gen) return;
          for (const k of PARTS) mergePart(period.parts[k], j.parts[k]);
          period.scanned += j.scanned;
          period.overflow += j.line_item_overflow || 0;
        } catch (e) {
          failed.push(`${day}: ${e.message}`);
        }
        done++;
        if (my !== gen) return;
        const el = root.querySelector('.na-loading__text');
        if (el) el.textContent = `Loading net AOV — reading line items for ${jobs.length} days (about 10s a day)… ${done} / ${jobs.length}`;
        const bar = root.querySelector('.na-loading .progress > div');
        if (bar) bar.style.width = (done / jobs.length * 100).toFixed(0) + '%';
      }
    }));
    if (my !== gen) return;
    if (failed.length) {
      root.innerHTML = shell(`<div class="warning">Net AOV couldn't load ${failed.length} of ${jobs.length} days, so it isn't shown (a missing day would skew the comparison): ${esc(failed.slice(0, 3).join(' · '))}</div>`);
      return;
    }
    state = { cur, prev, scoped: !!(source || medium), channel, shopify: await shopifyP };
    if (my !== gen) return;
    render();
  }

  // ── render ──
  const SUBCARDS = [
    ['na-bridge', 'Order-value bridge (per order)'],
    ['na-units', 'What moved paid units / order'],
    ['na-extras', 'Protection, free gifts &amp; $0 units'],
    ['na-segments', 'What moved net AOV, by segment'],
    ['na-dist', 'Order-value distribution (net AOV per order)'],
    ['na-trend', 'Daily net AOV'],
  ];
  // Stand-ins for the cards while days load, so the section's shape is visible
  // and nothing below looks finished when it isn't.
  function placeholders() {
    return SUBCARDS.map(([id, title]) => `<div class="card" id="${id}"><h3>${title}</h3>
      <p class="card__sub">Loading…</p><div class="na-loading"><span class="spinner"></span>Waiting for line items…</div></div>`).join('');
  }
  function collapse() {
    if (window.CardCollapse) CardCollapse.apply(root);
  }

  function shell(inner) {
    return `<div class="card na-head" data-no-collapse="1"><h3>Net AOV — what an order is worth in product revenue</h3>
      <p class="card__sub">Paid product revenue after every discount ÷ orders. Excludes shipping, tax and SavedBy protection,
      and counts only paid units, so free gifts and $0 lines can't pad units-per-order. Everything below this section
      is gross AOV (order totals incl. shipping, tax and protection), so the two won't match.</p>${inner}</div>`;
  }

  function render() {
    if (!state || !root) return;
    const P = view(state.prev), C = view(state.cur);
    const p = ratios(P.totals), c = ratios(C.totals);
    const warns = [];
    for (const [lbl, per] of [['Current', state.cur], ['Previous', state.prev]]) {
      if (per.overflow) warns.push(`${lbl} period: ${per.overflow} order(s) had more than 50 line items; lines past 50 aren't counted.`);
    }
    const r0 = state.cur.parts.R.totals.orders + state.cur.parts.R0.totals.orders;
    const z0 = state.cur.parts.C0.totals.orders + (ui.renewals ? state.cur.parts.R0.totals.orders : 0);

    root.innerHTML = `
      <div class="card na-head" data-no-collapse="1">
        <h3>Net AOV — what an order is worth in product revenue</h3>
        <p class="card__sub">${state.channel ? '<strong>Sales channel = Online Store only.</strong> ' : ''}Paid product revenue after every discount ÷ orders. Excludes shipping, tax and SavedBy protection,
          and counts only paid units, so free gifts and $0 lines can't pad units-per-order. The sections further down
          use <strong>gross AOV</strong> (order totals incl. shipping, tax and protection), so their numbers won't match this one.</p>
        <div class="na-toggles">
          ${state.scoped || !hasRenewals() ? '' : `<label><input type="checkbox" data-na="renewals" ${ui.renewals ? 'checked' : ''}> Include subscription renewals <span class="na-dim">(${int(r0)} orders this period, no first visit)</span></label>`}
          ${zeroCount() === 0 ? '' : `<label><input type="checkbox" data-na="zeros" ${ui.zeros ? 'checked' : ''}> Include $0 orders <span class="na-dim">(${int(z0)} this period: replacements, seeding, samples, $0 first payments)</span></label>`}
        </div>
        ${warns.map(w => `<div class="warning">${esc(w)}</div>`).join('')}
        ${kpis(p, c)}
        ${summary(P, C, p, c)}
      </div>
      ${bridgeCard(p, c)}
      ${unitsCard(P, C)}
      ${extrasCard(p, c)}
      ${segmentCard(P, C)}
      ${distributionCard(P, C)}
      ${trendCard(P, C)}
    `;
    collapse();
    wire();
  }

  // $0 orders in scope across both periods; the Online Store has none, so the toggle hides.
  function zeroCount() {
    return ['cur', 'prev'].reduce((a, k) => a + state[k].parts.C0.totals.orders + state[k].parts.R0.totals.orders, 0);
  }
  function hasRenewals() {
    return ['cur', 'prev'].some(k => state[k].parts.R.totals.orders + state[k].parts.R0.totals.orders > 0);
  }

  // Shopify AOV = (gross sales − discounts) ÷ orders. From ShopifyQL when the page
  // asked for it (exact to Shopify's reports); otherwise rebuilt from order data,
  // which runs ~1% high — Shopify values each order as placed and drops
  // post-checkout edits, and that can't be reproduced from line items. Either
  // way every order counts, $0 orders included, as in Shopify.
  function shopifyAov() {
    const sh = state.shopify;
    if (sh && !sh.error && sh.current) {
      const g = per => ({ with: per.with_protection.aov, without: per.without_protection.aov, orders: per.with_protection.orders });
      return { source: 'shopifyql', cur: g(sh.current), prev: g(sh.previous) };
    }
    const calc = period => {
      const keep = ['C', 'C0'].concat(ui.renewals ? ['R', 'R0'] : []);
      const t = keep.reduce((a, k) => addTo(a, period.parts[k].totals), blank());
      return { with: t.orders ? (t.net + t.protection) / t.orders : NaN, without: t.orders ? t.net / t.orders : NaN, orders: t.orders };
    };
    return { source: 'orders', cur: calc(state.cur), prev: calc(state.prev), error: sh && sh.error };
  }

  function kpis(p, c) {
    const k = (label, cv, pv, d, fmt, dfmt, invert) => `
      <div class="kpi"><div class="kpi__label">${label}</div>
        <div class="kpi__value">${fmt(cv)}</div>
        <div class="kpi__delta ${fin(d) && d !== 0 ? ((d > 0) !== !!invert ? 'up' : 'down') : ''}">prev ${fmt(pv)} · ${dfmt(d)}</div></div>`;
    const sa = shopifyAov();
    const note = sa.source === 'shopifyql'
      ? `<strong>Shopify AOV</strong> is Shopify's own number (ShopifyQL, Sales channel = Online Store): (gross sales − discounts) ÷ orders,
         each order valued as placed. It ties to Shopify's reports. Without protection drops product type "Protection".`
      : `<strong>Shopify AOV</strong> uses Shopify's definition, (gross sales − discounts) ÷ all orders, computed from this page's orders.
         Shopify's own report can't filter by first-visit UTM, and it drops post-checkout edits, so it runs ~1% lower.${sa.error ? ` (Shopify figure unavailable: ${esc(sa.error)})` : ''}`;
    return `<div class="kpi-row na-kpis">
      ${k('Shopify AOV (with protection)', sa.cur.with, sa.prev.with, sa.cur.with - sa.prev.with, $2, s$2)}
      ${k('Shopify AOV (without protection)', sa.cur.without, sa.prev.without, sa.cur.without - sa.prev.without, $2, s$2)}
      ${k('Net AOV', c.aov, p.aov, c.aov - p.aov, $2, s$2)}
      ${k('Orders', c.orders, p.orders, c.orders - p.orders, int, sInt)}
      ${k('Paid units / order', c.upt, p.upt, c.upt - p.upt, x2, sX2)}
      ${k('List price / unit', c.listAsp, p.listAsp, c.listAsp - p.listAsp, $2, s$2)}
      ${k('Discount depth', c.discDepth, p.discDepth, c.discDepth - p.discDepth, pct, sPp, true)}
      ${k('Net price / unit', c.netAsp, p.netAsp, c.netAsp - p.netAsp, $2, s$2)}
      ${k('Protection attach', c.protAttach, p.protAttach, c.protAttach - p.protAttach, pct, sPp)}
      ${k('Free-gift attach', c.giftAttach, p.giftAttach, c.giftAttach - p.giftAttach, pct, sPp)}
      ${k('Gross AOV', c.totalPerOrder, p.totalPerOrder, c.totalPerOrder - p.totalPerOrder, $2, s$2)}
    </div>
    <p class="na-dim na-kpi-note">${note} <strong>Net AOV</strong> is this section's own measure: protection out, and $0 orders only if toggled in.</p>`;
  }

  // Plain-language read of the biggest movers. Every number here is one shown in
  // a table below; nothing is inferred beyond the arithmetic.
  function summary(P, C, p, c) {
    if (!p.orders || !c.orders) return '';
    const d = c.aov - p.aov;
    const drv = driverSplit(p, c);
    const drivers = [
      ['paid units per order', drv.upt],
      ['list price per unit (product mix / price changes)', drv.price],
      ['discount depth', drv.discount],
    ].sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
    const line = dim => segmentSplit(P.seg[dim], C.seg[dim], P.totals, C.totals)
      .sort((a, b) => Math.abs(b.total) - Math.abs(a.total)).slice(0, 3)
      .map(s => `${esc(s.key)} ${s$2(s.total)} (${s$2(s.rate)} own net AOV, ${s$2(s.mix)} share of orders ${sPp(s.s1 - s.s0)})`).join('; ');
    // With one sales channel there is one order type, so the useful splits are
    // who bought (new / returning) and how (subscription / one-time).
    const lines = state.channel
      ? [['By customer', line('customer')], ['By purchase type', line('purchase')]]
      : [['By order type', line('order_type')]];
    return `<div class="na-summary">
      <div><strong>Net AOV ${d >= 0 ? 'rose' : 'fell'} ${$2(Math.abs(d))}</strong> (${$2(p.aov)} → ${$2(c.aov)}).
        By driver: ${drivers.map(([l, v]) => `${l} <span class="${cls(v)}">${s$2(v)}</span>`).join(', ')}.</div>
      ${lines.map(([l, t]) => `<div>${l}: ${t}.</div>`).join('')}
      ${unitsLine(P, C)}
      <div class="na-dim">Units/order as Shopify counts it (protection and gifts included): ${x2(p.allUpt)} → ${x2(c.allUpt)};
        paid units only: ${x2(p.upt)} → ${x2(c.upt)}.</div>
    </div>`;
  }

  // One line for the headline: did paid UPT move on main products or upsells,
  // and which module moved most. Same arithmetic as the units card.
  function unitsLine(P, C) {
    const o0 = P.totals.orders, o1 = C.totals.orders;
    const m0 = P.lines.module || {}, m1 = C.lines.module || {};
    const keys = [...new Set([...Object.keys(m0), ...Object.keys(m1)])];
    if (!keys.length || !o0 || !o1) return '';
    const parts = keys.map(k => [k, (m1[k]?.units || 0) / o1 - (m0[k]?.units || 0) / o0])
      .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
    return `<div>Paid units / order by upsell module: ${parts.map(([k, v]) => `${esc(k)} <span class="${cls(v)}">${sX2(v)}</span>`).join(', ')}.</div>`;
  }

  function bridgeCard(p, c) {
    const row = (label, pv, cv, opts = {}) => `<tr class="${opts.total ? 'na-total' : ''}">
      <td>${label}</td><td class="r">${$2(pv)}</td><td class="r">${$2(cv)}</td>
      <td class="r ${cls(opts.invert ? -(cv - pv) : cv - pv)}">${s$2(cv - pv)}</td></tr>`;
    const otherP = p.totalPerOrder - (p.aov + p.protPerOrder + p.shipPerOrder + p.taxPerOrder + p.tipsPerOrder);
    const otherC = c.totalPerOrder - (c.aov + c.protPerOrder + c.shipPerOrder + c.taxPerOrder + c.tipsPerOrder);
    const drv = driverSplit(p, c);
    return `<div class="card" id="na-bridge"><h3>Order-value bridge (per order)</h3>
      <p class="card__sub">From list price to what the customer paid. <strong>List merch</strong> is paid product lines at full price;
        <strong>discounts</strong> are every discount on those lines (codes, automatic, subscription pricing). Shipping is what was
        actually charged after free-shipping waivers, not the pre-discount rate.</p>
      <div class="na-grid">
        <div class="scroll-x"><table>
          <thead><tr><th>Per order</th><th class="r">Prev</th><th class="r">Curr</th><th class="r">Δ</th></tr></thead>
          <tbody>
            ${row('List merch value', p.listPerOrder, c.listPerOrder)}
            ${row('− Discounts', -p.discPerOrder, -c.discPerOrder)}
            ${row('= Net AOV', p.aov, c.aov, { total: true })}
            ${row('+ SavedBy protection', p.protPerOrder, c.protPerOrder)}
            ${row('+ Shipping charged', p.shipPerOrder, c.shipPerOrder)}
            ${row('+ Tax', p.taxPerOrder, c.taxPerOrder)}
            ${row('+ Tips / rounding', p.tipsPerOrder + otherP, c.tipsPerOrder + otherC)}
            ${row('= Gross AOV', p.totalPerOrder, c.totalPerOrder, { total: true })}
          </tbody></table></div>
        <div class="scroll-x"><table>
          <thead><tr><th>Net AOV driver</th><th class="r">Prev</th><th class="r">Curr</th><th class="r">Effect on net AOV</th></tr></thead>
          <tbody>
            <tr><td>Paid units / order</td><td class="r">${x2(p.upt)}</td><td class="r">${x2(c.upt)}</td><td class="r ${cls(drv.upt)}">${s$2(drv.upt)}</td></tr>
            <tr><td>List price / unit <span class="na-dim">(mix, price changes)</span></td><td class="r">${$2(p.listAsp)}</td><td class="r">${$2(c.listAsp)}</td><td class="r ${cls(drv.price)}">${s$2(drv.price)}</td></tr>
            <tr><td>Discount depth</td><td class="r">${pct(p.discDepth)}</td><td class="r">${pct(c.discDepth)}</td><td class="r ${cls(drv.discount)}">${s$2(drv.discount)}</td></tr>
            <tr class="na-total"><td>Δ Net AOV</td><td class="r">${$2(p.aov)}</td><td class="r">${$2(c.aov)}</td><td class="r ${cls(c.aov - p.aov)}">${s$2(c.aov - p.aov)}</td></tr>
          </tbody></table>
          <p class="footnote">Net AOV = paid units/order × list price/unit × (1 − discount depth). Effects are applied in that order and sum exactly to Δ Net AOV.
            Shipping waived on free-shipping orders: ${$2(p.shipWaivedPerOrder)} → ${$2(c.shipWaivedPerOrder)} per order.</p>
        </div>
      </div></div>`;
  }

  // Paid units per order by where the line came from. Each row's units ÷ ALL
  // orders, so the rows sum to paid UPT and their Δs sum to Δ UPT exactly; the
  // same holds for net $ per order and net AOV. Attach rate and units per
  // attaching order say whether a move is "fewer orders take it" or "those that
  // take it take fewer".
  function unitsCard(P, C) {
    const o0 = P.totals.orders, o1 = C.totals.orders;
    const m0 = P.lines[ui.lineDim] || {}, m1 = C.lines[ui.lineDim] || {};
    const z = { units: 0, net: 0, list: 0, orders: 0 };
    const rows = [...new Set([...Object.keys(m0), ...Object.keys(m1)])].map(k => {
      const a = m0[k] || z, b = m1[k] || z;
      const u0 = o0 ? a.units / o0 : 0, u1 = o1 ? b.units / o1 : 0;
      const n0 = o0 ? a.net / o0 : 0, n1 = o1 ? b.net / o1 : 0;
      return { key: k, a, b, u0, u1, du: u1 - u0, n0, n1, dn: n1 - n0,
        at0: o0 ? a.orders / o0 : NaN, at1: o1 ? b.orders / o1 : NaN,
        per0: a.orders ? a.units / a.orders : NaN, per1: b.orders ? b.units / b.orders : NaN,
        asp1: b.units ? b.net / b.units : NaN };
    });
    const big = ['page', 'module_page', 'product', 'module_product'].includes(ui.lineDim);
    const shown = rows.filter(r => !big || Math.max(r.a.units, r.b.units) >= ui.minUnits)
      .sort((x, y) => Math.abs(y.du) - Math.abs(x.du));
    const rest = rows.filter(r => !shown.includes(r));
    const restSum = rest.reduce((s, r) => ({ du: s.du + r.du, dn: s.dn + r.dn, u0: s.u0 + r.u0, u1: s.u1 + r.u1 }), { du: 0, dn: 0, u0: 0, u1: 0 });
    const tU0 = o0 ? P.totals.paid_units / o0 : NaN, tU1 = o1 ? C.totals.paid_units / o1 : NaN;
    const tN0 = o0 ? P.totals.net / o0 : NaN, tN1 = o1 ? C.totals.net / o1 : NaN;
    // Headline: main products vs every upsell module together.
    const mod0 = P.lines.module || {}, mod1 = C.lines.module || {};
    const MAIN = 'Main product (no upsell module)';
    const mainD = ((mod1[MAIN]?.units || 0) / (o1 || 1)) - ((mod0[MAIN]?.units || 0) / (o0 || 1));
    const upD = (tU1 - tU0) - mainD;
    const td = (v, f, d) => `<td class="r ${d ? cls(v) : ''}">${f(v)}</td>`;
    return `<div class="card" id="na-units"><h3>What moved paid units / order</h3>
      <p class="card__sub">Every paid line is tagged with the upsell module that added it (none = added as the main product) and the page it was
        added on. <strong>Units / order</strong> is that row's units ÷ all orders, so rows sum to paid UPT and the Δ column sums to Δ UPT.
        <strong>Attach</strong> = share of orders with at least one such line; <strong>per attaching order</strong> = units in those orders.
        Protection, free gifts and $0 lines are excluded.</p>
      <div class="na-summary" style="margin-bottom:12px">Paid units / order ${x2(tU0)} → ${x2(tU1)} (<span class="${cls(tU1 - tU0)}">${sX2(tU1 - tU0)}</span>):
        main products <span class="${cls(mainD)}">${sX2(mainD)}</span>, all upsell modules together <span class="${cls(upD)}">${sX2(upD)}</span>.</div>
      <div class="na-controls">
        <label>Split by <select data-na="linedim">${LINE_DIMS.map(([k, l]) => `<option value="${k}" ${k === ui.lineDim ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        ${big ? `<label>Min units <input type="number" min="1" value="${ui.minUnits}" data-na="minunits" style="width:70px"></label>` : ''}
      </div>
      <div class="scroll-x"><table>
        <thead><tr><th>${esc((LINE_DIMS.find(d => d[0] === ui.lineDim) || [])[1] || '')}</th>
          <th class="r">Prev units</th><th class="r">Curr units</th>
          <th class="r">Prev units / order</th><th class="r">Curr units / order</th><th class="r">Δ units / order</th>
          <th class="r">Attach prev</th><th class="r">Attach curr</th><th class="r">Per attaching order</th>
          <th class="r">Net $/unit</th><th class="r">Net $/order Δ</th></tr></thead>
        <tbody>${shown.map(r => `<tr><td>${esc(r.key)}</td>
          ${td(r.a.units, int)}${td(r.b.units, int)}${td(r.u0, x2)}${td(r.u1, x2)}
          <td class="r ${cls(r.du)}"><strong>${sX2(r.du)}</strong></td>
          ${td(r.at0, pct)}${td(r.at1, pct)}
          <td class="r">${x2(r.per0)} → ${x2(r.per1)}</td>
          ${td(r.asp1, $2)}${td(r.dn, s$2, true)}</tr>`).join('')}
          ${rest.length ? `<tr class="na-dim"><td>${rest.length} smaller rows (under ${ui.minUnits} units)</td><td colspan="2"></td>
            ${td(restSum.u0, x2)}${td(restSum.u1, x2)}${td(restSum.du, sX2, true)}<td colspan="4"></td>${td(restSum.dn, s$2, true)}</tr>` : ''}
        </tbody>
        <tfoot><tr><td>Total (paid UPT / net AOV)</td><td class="r">${int(P.totals.paid_units)}</td><td class="r">${int(C.totals.paid_units)}</td>
          <td class="r">${x2(tU0)}</td><td class="r">${x2(tU1)}</td><td class="r ${cls(tU1 - tU0)}"><strong>${sX2(tU1 - tU0)}</strong></td>
          <td colspan="4"></td><td class="r ${cls(tN1 - tN0)}">${s$2(tN1 - tN0)}</td></tr></tfoot>
      </table></div></div>`;
  }

  function extrasCard(p, c) {
    const row = (label, pv, cv, f, df) => `<tr><td>${label}</td><td class="r">${f(pv)}</td><td class="r">${f(cv)}</td><td class="r">${df(cv - pv)}</td></tr>`;
    return `<div class="card" id="na-extras"><h3>Protection, free gifts &amp; $0 units</h3>
      <p class="card__sub">These are on the order but aren't product sales. Shopify's unit count includes all of them, so a change here
        moves "units per transaction" without anyone buying more product. They're kept out of every UPT and price/unit figure on this section.</p>
      <div class="scroll-x"><table>
        <thead><tr><th>Per order</th><th class="r">Prev</th><th class="r">Curr</th><th class="r">Δ</th></tr></thead>
        <tbody>
          ${row('SavedBy protection: attach rate', p.protAttach, c.protAttach, pct, sPp)}
          ${row('SavedBy protection: avg fee when attached', p.protFee, c.protFee, $2, s$2)}
          ${row('SavedBy protection: $ per order', p.protPerOrder, c.protPerOrder, $2, s$2)}
          ${row('Free gifts ($0 list or type Gift): orders with one', p.giftAttach, c.giftAttach, pct, sPp)}
          ${row('Free gifts: units per order', p.giftUnitsPerOrder, c.giftUnitsPerOrder, x2, sX2)}
          ${row('Products discounted to $0: units per order', p.zeroUnitsPerOrder, c.zeroUnitsPerOrder, x2, sX2)}
          ${row('Units/order as Shopify counts it', p.allUpt, c.allUpt, x2, sX2)}
          ${row('Paid units/order (used for UPT here)', p.upt, c.upt, x2, sX2)}
        </tbody></table></div></div>`;
  }

  function segmentCard(P, C) {
    const rows = segmentSplit(P.seg[ui.dim], C.seg[ui.dim], P.totals, C.totals);
    const small = ['source', 'campaign', 'landing_page', 'discount_code'].includes(ui.dim);
    const shown = rows.filter(r => !small || Math.max(r.a0.orders, r.a1.orders) >= ui.minOrders)
      .sort((a, b) => Math.abs(b.total) - Math.abs(a.total));
    const hidden = rows.filter(r => !shown.includes(r));
    const hid = hidden.reduce((s, r) => ({ rate: s.rate + r.rate, mix: s.mix + r.mix, n: s.n + 1 }), { rate: 0, mix: 0, n: 0 });
    const sum = rows.reduce((s, r) => s + r.total, 0);
    const pT = ratios(P.totals), cT = ratios(C.totals);
    const td = (v, f, d) => `<td class="r ${d ? cls(v) : ''}">${f(v)}</td>`;
    return `<div class="card" id="na-segments"><h3>What moved net AOV, by segment</h3>
      <p class="card__sub"><strong>Own net-AOV effect</strong> = the segment's old share × its Δ net AOV (it got more or less valuable).
        <strong>Share of orders</strong> = Δ share × (its AOV − old blended AOV): it grew or shrank as a slice of the orders.
        Rows sum to Δ net AOV. Sorted by size of impact.</p>
      <div class="na-controls">
        <label>Split by <select data-na="dim">${DIMS.filter(([k]) => !(state.channel && k === 'order_type')).map(([k, l]) => `<option value="${k}" ${k === ui.dim ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        ${small ? `<label>Min orders <input type="number" min="1" value="${ui.minOrders}" data-na="min" style="width:70px"></label>` : ''}
      </div>
      <div class="scroll-x"><table>
        <thead><tr><th>Segment</th><th class="r">Prev orders</th><th class="r">Curr orders</th><th class="r">Share Δ</th>
          <th class="r">Prev net AOV</th><th class="r">Curr net AOV</th><th class="r">Δ</th>
          <th class="r">Paid UPT</th><th class="r">List $/unit</th><th class="r">Discount</th><th class="r">Protection</th>
          <th class="r">Own net-AOV effect</th><th class="r">Share effect</th><th class="r">Impact on net AOV</th></tr></thead>
        <tbody>${shown.map(r => `<tr><td>${esc(r.key)}</td>
          ${td(r.a0.orders, int)}${td(r.a1.orders, int)}${td(r.s1 - r.s0, sPp, true)}
          ${td(r.r0.aov, $2)}${td(r.r1.aov, $2)}${td(r.a0.orders && r.a1.orders ? r.r1.aov - r.r0.aov : NaN, s$2, true)}
          <td class="r">${x2(r.r1.upt)} <span class="na-dim">${sX2(r.r1.upt - r.r0.upt)}</span></td>
          <td class="r">${$2(r.r1.listAsp)} <span class="na-dim">${s$2(r.r1.listAsp - r.r0.listAsp)}</span></td>
          <td class="r">${pct(r.r1.discDepth)} <span class="na-dim">${sPp(r.r1.discDepth - r.r0.discDepth)}</span></td>
          <td class="r">${pct(r.r1.protAttach)}</td>
          ${td(r.rate, s$2, true)}${td(r.mix, s$2, true)}<td class="r ${cls(r.total)}"><strong>${s$2(r.total)}</strong></td></tr>`).join('')}
          ${hid.n ? `<tr class="na-dim"><td>${hid.n} smaller segments (under ${ui.minOrders} orders)</td><td colspan="10"></td>
            ${td(hid.rate, s$2, true)}${td(hid.mix, s$2, true)}${td(hid.rate + hid.mix, s$2, true)}</tr>` : ''}
        </tbody>
        <tfoot><tr><td>Total</td><td class="r">${int(P.totals.orders)}</td><td class="r">${int(C.totals.orders)}</td><td></td>
          <td class="r">${$2(pT.aov)}</td><td class="r">${$2(cT.aov)}</td><td class="r ${cls(cT.aov - pT.aov)}">${s$2(cT.aov - pT.aov)}</td>
          <td class="r">${x2(cT.upt)}</td><td class="r">${$2(cT.listAsp)}</td><td class="r">${pct(cT.discDepth)}</td><td class="r">${pct(cT.protAttach)}</td>
          <td></td><td></td><td class="r ${cls(sum)}"><strong>${s$2(sum)}</strong></td></tr></tfoot>
      </table></div></div>`;
  }

  // $10 net-AOV buckets with a $200+ tail, and paid-units-per-order 0..5+.
  function buckets(hist, edges, labelFn) {
    const n = Object.values(hist).reduce((a, b) => a + b, 0) || 1;
    const counts = edges.map(() => 0);
    for (const [k, v] of Object.entries(hist)) {
      const x = Number(k);
      let i = edges.findIndex((e, j) => x >= e && (j === edges.length - 1 || x < edges[j + 1]));
      if (i < 0) i = 0;
      counts[i] += v;
    }
    return edges.map((e, i) => ({ label: labelFn(e, i), share: counts[i] / n, count: counts[i] }));
  }

  function bars(prevB, curB) {
    const W = 760, H = 180, padL = 36, padB = 34, padT = 10, n = curB.length;
    const max = Math.max(0.01, ...prevB.map(b => b.share), ...curB.map(b => b.share));
    const bw = (W - padL) / n;
    const y = v => padT + (H - padB - padT) * (1 - v / max);
    let svg = `<svg viewBox="0 0 ${W} ${H}" class="na-svg" role="img" aria-label="Order distribution, previous vs current">`;
    for (let t = 0; t <= 4; t++) {
      const v = max * t / 4, yy = y(v);
      svg += `<line x1="${padL}" x2="${W}" y1="${yy}" y2="${yy}" class="na-grid-line"/><text x="${padL - 4}" y="${yy + 3}" class="na-axis" text-anchor="end">${(v * 100).toFixed(0)}%</text>`;
    }
    curB.forEach((b, i) => {
      const x = padL + i * bw;
      const pv = prevB[i].share;
      svg += `<rect x="${x + bw * 0.12}" y="${y(pv)}" width="${bw * 0.36}" height="${H - padB - y(pv)}" class="na-bar-prev"><title>${esc(b.label)} prev ${pct(pv)}</title></rect>`;
      svg += `<rect x="${x + bw * 0.5}" y="${y(b.share)}" width="${bw * 0.36}" height="${H - padB - y(b.share)}" class="na-bar-cur"><title>${esc(b.label)} curr ${pct(b.share)}</title></rect>`;
      if (n <= 12 || i % 2 === 0) svg += `<text x="${x + bw / 2}" y="${H - padB + 14}" class="na-axis" text-anchor="middle">${esc(b.label)}</text>`;
    });
    return svg + '</svg>';
  }

  function distributionCard(P, C) {
    const edges = Array.from({ length: 21 }, (_, i) => i * 10);
    const lab = (e, i) => i === 20 ? '$200+' : '$' + e;
    const pb = buckets(P.hist_net, edges, lab), cb = buckets(C.hist_net, edges, lab);
    const uEdges = [0, 1, 2, 3, 4, 5];
    const ulab = (e, i) => i === 5 ? '5+' : String(e);
    const pu = buckets(P.hist_units, uEdges, ulab), cu = buckets(C.hist_units, uEdges, ulab);
    const q = h => [0.25, 0.5, 0.75, 0.9].map(x => percentile(h, x));
    const qp = q(P.hist_net), qc = q(C.hist_net);
    const pr = ratios(P.totals), cr = ratios(C.totals);
    const qrow = (l, a, b) => `<tr><td>${l}</td><td class="r">${$0(a)}</td><td class="r">${$0(b)}</td><td class="r ${cls(b - a)}">${sign(b - a, $0)}</td></tr>`;
    // Bucket rows: only where the share moved or there are orders, so the table stays short.
    const brows = cb.map((b, i) => ({ ...b, prev: pb[i].share })).filter(b => b.share > 0.005 || b.prev > 0.005);
    return `<div class="card" id="na-dist"><h3>Order-value distribution (net AOV per order)</h3>
      <p class="card__sub">Did the whole basket shift down, or did the high-value tail thin out? Grey = previous, blue = current, as a share of orders.
        Percentiles are exact to the dollar.</p>
      <div class="na-grid">
        <div>${bars(pb, cb)}</div>
        <div class="scroll-x"><table>
          <thead><tr><th>Net AOV per order</th><th class="r">Prev</th><th class="r">Curr</th><th class="r">Δ</th></tr></thead>
          <tbody>${qrow('25th percentile', qp[0], qc[0])}${qrow('Median', qp[1], qc[1])}${qrow('75th percentile', qp[2], qc[2])}${qrow('90th percentile', qp[3], qc[3])}
            <tr class="na-total"><td>Mean (net AOV)</td><td class="r">${$2(pr.aov)}</td><td class="r">${$2(cr.aov)}</td><td class="r ${cls(cr.aov - pr.aov)}">${s$2(cr.aov - pr.aov)}</td></tr></tbody></table></div>
      </div>
      <div class="na-grid" style="margin-top:14px">
        <div class="scroll-x"><table>
          <thead><tr><th>Net AOV bucket</th><th class="r">Prev share</th><th class="r">Curr share</th><th class="r">Δ</th></tr></thead>
          <tbody>${brows.map(b => `<tr><td>${esc(b.label)}${b.label === '$200+' ? '' : '–' + (parseInt(b.label.slice(1), 10) + 9.99).toFixed(2)}</td><td class="r">${pct(b.prev)}</td><td class="r">${pct(b.share)}</td><td class="r ${cls(b.share - b.prev)}">${sPp(b.share - b.prev)}</td></tr>`).join('')}</tbody></table></div>
        <div>
          <div class="na-subhead">Paid units per order</div>
          ${bars(pu, cu)}
          <div class="scroll-x"><table>
            <thead><tr><th>Paid units</th><th class="r">Prev share</th><th class="r">Curr share</th><th class="r">Δ</th></tr></thead>
            <tbody>${cu.map((b, i) => `<tr><td>${esc(b.label)}</td><td class="r">${pct(pu[i].share)}</td><td class="r">${pct(b.share)}</td><td class="r ${cls(b.share - pu[i].share)}">${sPp(b.share - pu[i].share)}</td></tr>`).join('')}</tbody></table></div>
        </div>
      </div></div>`;
  }

  function trendCard(P, C) {
    const series = (agg, s, e) => days(s, e).map(d => ({ d, r: ratios(agg.days[d] || blank()) }));
    const cs = series(C, state.cur.start, state.cur.end), ps = series(P, state.prev.start, state.prev.end);
    const roll = (arr, i, k) => {
      const w = arr.slice(Math.max(0, i - k + 1), i + 1);
      const o = w.reduce((a, x) => a + x.r.orders, 0), n = w.reduce((a, x) => a + x.r.aov * x.r.orders, 0);
      return o ? n / o : NaN;
    };
    const W = 760, H = 200, padL = 44, padB = 26, padT = 10;
    const all = [...cs, ...ps].map(x => x.r.aov).filter(fin);
    let chart = '<p class="na-dim">Pick a range of a few days or more to see the daily trend.</p>';
    if (all.length >= 2) {
      const lo = Math.min(...all), hi = Math.max(...all), pad = (hi - lo) * 0.1 || 1;
      const yMin = lo - pad, yMax = hi + pad;
      const n = Math.max(cs.length, ps.length);
      const x = i => padL + (n === 1 ? 0 : i * (W - padL - 10) / (n - 1));
      const y = v => padT + (H - padB - padT) * (1 - (v - yMin) / (yMax - yMin));
      const path = (arr, f) => arr.map((p, i) => fin(f(p, i)) ? `${i && fin(f(arr[i - 1], i - 1)) ? 'L' : 'M'}${x(i).toFixed(1)},${y(f(p, i)).toFixed(1)}` : '').join(' ');
      chart = `<svg viewBox="0 0 ${W} ${H}" class="na-svg" role="img" aria-label="Daily net AOV, current vs previous">`;
      for (let t = 0; t <= 4; t++) {
        const v = yMin + (yMax - yMin) * t / 4;
        chart += `<line x1="${padL}" x2="${W}" y1="${y(v)}" y2="${y(v)}" class="na-grid-line"/><text x="${padL - 4}" y="${y(v) + 3}" class="na-axis" text-anchor="end">$${v.toFixed(0)}</text>`;
      }
      chart += `<path d="${path(ps, p => p.r.aov)}" class="na-line-prev"/>`;
      chart += `<path d="${path(cs, p => p.r.aov)}" class="na-line-cur"/>`;
      if (cs.length >= 7) chart += `<path d="${path(cs, (p, i) => roll(cs, i, 7))}" class="na-line-avg"/>`;
      cs.forEach((p, i) => { if (fin(p.r.aov)) chart += `<circle cx="${x(i)}" cy="${y(p.r.aov)}" r="3" class="na-dot"><title>${p.d}: ${$2(p.r.aov)} · ${int(p.r.orders)} orders</title></circle>`; });
      const step = Math.ceil(n / 10);
      cs.forEach((p, i) => { if (i % step === 0) chart += `<text x="${x(i)}" y="${H - 8}" class="na-axis" text-anchor="middle">${p.d.slice(5)}</text>`; });
      chart += '</svg>';
    }
    return `<div class="card" id="na-trend"><h3>Daily net AOV</h3>
      <p class="card__sub">Blue = current period, grey dashed = previous period lined up day-for-day${cs.length >= 7 ? ', orange = 7-day order-weighted average' : ''}.
        Use it to find the day the shift started (a promo, an LP or offer change, a gift threshold).</p>
      ${chart}
      <div class="scroll-x" style="margin-top:10px"><table>
        <thead><tr><th>Day</th><th class="r">Orders</th><th class="r">Net AOV</th><th class="r">vs prev-period day</th><th class="r">Paid UPT</th>
          <th class="r">List $/unit</th><th class="r">Discount</th><th class="r">Protection</th><th class="r">Free gift</th><th class="r">Gross AOV</th></tr></thead>
        <tbody>${cs.map((p, i) => { const q = ps[i]?.r; return `<tr><td>${p.d}</td><td class="r">${int(p.r.orders)}</td><td class="r">${$2(p.r.aov)}</td>
          <td class="r ${q ? cls(p.r.aov - q.aov) : ''}">${q ? s$2(p.r.aov - q.aov) : '—'}</td><td class="r">${x2(p.r.upt)}</td><td class="r">${$2(p.r.listAsp)}</td>
          <td class="r">${pct(p.r.discDepth)}</td><td class="r">${pct(p.r.protAttach)}</td><td class="r">${pct(p.r.giftAttach)}</td><td class="r">${$2(p.r.totalPerOrder)}</td></tr>`; }).join('')}</tbody>
      </table></div></div>`;
  }

  function wire() {
    root.querySelectorAll('[data-na]').forEach(el => {
      const k = el.dataset.na;
      el.addEventListener('change', () => {
        if (k === 'renewals') ui.renewals = el.checked;
        else if (k === 'zeros') ui.zeros = el.checked;
        else if (k === 'dim') ui.dim = el.value;
        else if (k === 'min') ui.minOrders = Math.max(1, parseInt(el.value, 10) || 1);
        else if (k === 'linedim') ui.lineDim = el.value;
        else if (k === 'minunits') ui.minUnits = Math.max(1, parseInt(el.value, 10) || 1);
        render();
      });
    });
  }

  const css = document.createElement('style');
  css.textContent = `
    #net-aov-root .na-toggles { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 0.82rem; margin-bottom: 12px; }
    #net-aov-root .na-toggles label, #net-aov-root .na-controls label { display: inline-flex; gap: 6px; align-items: center; }
    #net-aov-root .na-controls { display: flex; gap: 16px; flex-wrap: wrap; font-size: 0.82rem; margin-bottom: 10px; }
    #net-aov-root .na-controls select, #net-aov-root .na-controls input { font: inherit; padding: 3px 6px; border: 1px solid var(--border); border-radius: 6px; }
    #net-aov-root .na-dim { color: var(--text-secondary); font-size: 0.78rem; }
    #net-aov-root .na-kpis { margin-bottom: 6px; }
    #net-aov-root .na-kpi-note { margin: 0 0 12px; line-height: 1.5; }
    #net-aov-root .na-summary { font-size: 0.85rem; line-height: 1.6; background: #f7f8fa; border-radius: 6px; padding: 10px 14px; }
    #net-aov-root .na-summary > div + div { margin-top: 4px; }
    #net-aov-root .na-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; align-items: start; }
    #net-aov-root .na-total td { font-weight: 600; background: #f7f8fa; }
    #net-aov-root .na-loading { font-size: 0.85rem; color: var(--text-secondary); padding: 8px 0; }
    #net-aov-root .na-subhead { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-secondary); margin-bottom: 4px; }
    #net-aov-root .na-svg { width: 100%; height: auto; display: block; }
    #net-aov-root .na-grid-line { stroke: var(--border); stroke-width: 1; }
    #net-aov-root .na-axis { font-size: 10px; fill: var(--text-secondary); }
    #net-aov-root .na-bar-prev { fill: #b8bec7; }
    #net-aov-root .na-bar-cur { fill: var(--fb-blue); }
    #net-aov-root .na-line-prev { fill: none; stroke: #9ca3af; stroke-width: 1.5; stroke-dasharray: 4 3; }
    #net-aov-root .na-line-cur { fill: none; stroke: var(--fb-blue); stroke-width: 2; }
    #net-aov-root .na-line-avg { fill: none; stroke: #f97316; stroke-width: 2; }
    #net-aov-root .na-dot { fill: var(--fb-blue); }
    #net-aov-root td:first-child { min-width: 180px; }
  `;
  document.head.appendChild(css);

  window.NetAOV = { load };
})();
