/* ───────────────────────────────────────────────────────────────────────────
   Ad name → Meta creative preview link (+ copy-the-name button).

   Shopify only records the ad NAME in utm_content; Meta addresses ads by id.
   The unfiltered ad-level bulk pull times out chronically on this account, so
   DON'T try to pre-build a name→id index. Each name is resolved individually
   through two calls that are reliable (~90%):

     1. /api/meta-ad-lookup           name  → ad id
     2. /api/meta-ad-creative-preview ad id → preview_iframe.php URL

   Rows render immediately with a placeholder and upgrade in place as links
   land, driven by a 2-worker background queue with persistent caches.

   Lifted out of meta-cvr-impact.html so a second dashboard could use it
   without a second copy of the retry/cache/auth handling.

   Usage:
     AdLink.setLookupEnd('2026-08-13');            // window the lookup searches
     html += AdLink.cellHtml(adName, { copy: true });
     AdLink.enqueue(namesCurrentlyOnScreen);        // safe to call every paint
     AdLink.onProgress(repaintFn);                  // links landed
     AdLink.state.authFailed                        // → show a login prompt
   ─────────────────────────────────────────────────────────────────────────── */
(function () {
  const norm = (s) => String(s || '').trim().replace(/\s+/g, ' ').toLowerCase();

  // Bump when the matching logic changes — drops previously cached (possibly
  // wrong) ids instead of serving them forever.
  const CACHE_V = 'v1';
  const AD_ID_TTL = 24 * 60 * 60 * 1000;   // name → ad id
  const AD_PREV_TTL = 20 * 60 * 60 * 1000; // name → preview URL
  const ID_KEY = `adlink:${CACHE_V}:id`;
  const PREV_KEY = `adlink:${CACHE_V}:preview`;

  const lsGet = (k) => { try { return JSON.parse(localStorage.getItem(k) || '{}'); } catch { return {}; } };
  const lsSet = (k, o) => { try { localStorage.setItem(k, JSON.stringify(o)); } catch {} };

  const cachedAdId = (name) => {
    const e = lsGet(ID_KEY)[norm(name)];
    return e && (Date.now() - e.ts) < AD_ID_TTL ? e.ad_id : null;
  };
  const cacheAdId = (name, adId) => {
    const all = lsGet(ID_KEY); all[norm(name)] = { ad_id: adId, ts: Date.now() }; lsSet(ID_KEY, all);
  };
  const invalidateAdId = (name) => {
    const all = lsGet(ID_KEY); delete all[norm(name)]; lsSet(ID_KEY, all);
  };
  const cachedPreview = (name) => {
    const e = lsGet(PREV_KEY)[norm(name)];
    return e && (Date.now() - e.ts) < AD_PREV_TTL ? e : null;
  };
  const cachePreview = (name, url, adId) => {
    const all = lsGet(PREV_KEY); all[norm(name)] = { url, ad_id: adId, ts: Date.now() }; lsSet(PREV_KEY, all);
  };

  const adsManagerUrl = (accountId, adId) => {
    if (!adId) return null;
    const act = String(accountId || '').replace(/^act_/, '');
    return `https://adsmanager.facebook.com/adsmanager/manage/ads`
      + (act ? `?act=${encodeURIComponent(act)}&` : '?')
      + `selected_ad_ids=${encodeURIComponent(adId)}`;
  };

  // encodeURIComponent output is safe both as an attribute value and inside an
  // attribute selector.
  const domKey = (name) => encodeURIComponent(norm(name));

  // ── State ──────────────────────────────────────────────────────────────────
  const state = {
    queue: [],
    seen: new Set(),        // names ever enqueued this session
    attempts: new Map(),    // name → tries
    // Terminal outcomes, so a repaint (sort click, progress tick, "show all")
    // doesn't reset a resolved failure back to "resolving…" forever.
    terminal: new Map(),    // name → { kind: 'adsmanager'|'none', url, adId }
    running: 0,
    accountId: null,
    lastError: null,
    authFailed: false,
    resolved: 0,
    failed: 0,
    listeners: new Set(),   // several cards can want progress at once
  };

  let lookupEnd = null;     // end date of the window the name search covers

  const notify = () => { state.listeners.forEach(fn => { try { fn(); } catch {} }); };

  function enqueue(names) {
    if (state.authFailed) return;            // no point hammering a 401
    for (const n of (names || [])) {
      if (!n) continue;
      const k = norm(n);
      if (state.seen.has(k)) continue;
      state.seen.add(k);
      state.queue.push(n);
    }
    const workers = Math.min(2, state.queue.length);
    while (state.running < workers) {
      state.running++;
      worker().finally(() => { state.running--; });
    }
  }

  // Two workers, ~150ms apart. Failures go to the BACK of the queue (max 3
  // tries) rather than retrying inline, so one 10s timeout can't stall
  // everything behind it.
  async function worker() {
    while (state.queue.length) {
      const name = state.queue.shift();
      const tries = (state.attempts.get(norm(name)) || 0) + 1;
      state.attempts.set(norm(name), tries);
      try {
        const url = await resolvePreview(name);
        if (url) {
          state.resolved++;
          apply(name, url, cachedAdId(name), 'preview');
        }
      } catch (e) {
        if (e.status === 401) {
          // Auth is a whole-session problem, not a per-row one: stop the queue.
          state.authFailed = true;
          state.lastError = e.message;
          state.queue.length = 0;
          notify();
          return;
        }
        state.lastError = e.message;
        // Grab the id BEFORE invalidating — a failed *preview* call still leaves
        // a perfectly good id to deep-link Ads Manager with.
        const knownId = cachedAdId(name);
        invalidateAdId(name);
        if (tries < 3) {
          state.queue.push(name);
        } else {
          state.failed++;
          apply(name, knownId ? adsManagerUrl(state.accountId, knownId) : null, knownId, knownId ? 'adsmanager' : 'none');
        }
      }
      notify();
      await new Promise(r => setTimeout(r, 150));
    }
  }

  async function resolvePreview(name) {
    const hit = cachedPreview(name);
    if (hit) return hit.url;

    let adId = cachedAdId(name);
    if (!adId) {
      const params = new URLSearchParams({ name });
      if (lookupEnd) params.set('end', lookupEnd);
      const acctOverride = new URLSearchParams(location.search).get('ad_account');
      if (acctOverride) params.set('account_id', acctOverride);
      const r = await fetch(`/api/meta-ad-lookup?${params.toString()}`);
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw Object.assign(new Error(j.error || `lookup HTTP ${r.status}`), { status: r.status, needle: j.needle });
      adId = j.ad_id;
      if (j.account_id) state.accountId = j.account_id;
      cacheAdId(name, adId);
    }

    const pr = await fetch(`/api/meta-ad-creative-preview?ad_id=${encodeURIComponent(adId)}`);
    const pj = await pr.json().catch(() => ({}));
    if (!pr.ok) throw Object.assign(new Error(pj.error || `preview HTTP ${pr.status}`), { status: pr.status });
    cachePreview(name, pj.preview_url, adId);
    return pj.preview_url;
  }

  const previewHtml = (key, url, adId) =>
    `<a class="adrill-preview" href="${url}" target="_blank" rel="noopener"`
    + ` data-adkey="${key}" data-adid="${adId || ''}" title="Open Meta's creative preview">preview ↗</a>`;

  const adsManagerHtml = (key, url, adId) =>
    `<a class="adrill-preview adrill-preview--fallback" href="${url}" target="_blank" rel="noopener"`
    + ` data-adkey="${key}" data-adid="${adId || ''}"`
    + ` title="Creative preview unavailable right now — opens this ad in Ads Manager instead">Ads Manager ↗</a>`;

  const noneHtml = (key) =>
    `<span class="adrill-noad" data-adkey="${key}"`
    + ` title="Meta returned no ad matching this utm_content in the lookup window — it may have been renamed, or had no delivery">no link</span>`;

  // Swap every placeholder for this ad name (one name can be on several rows).
  function apply(name, url, adId, kind) {
    const key = domKey(name);
    // Remember non-preview outcomes so re-renders reproduce them (preview hits
    // are already persisted in localStorage and read by the render path).
    if (kind === 'preview') state.terminal.delete(norm(name));
    else state.terminal.set(norm(name), { kind, url, adId });
    document.querySelectorAll(`[data-adkey="${key}"]`).forEach(el => {
      if (el.classList.contains('adlink-copy')) return;     // not a link slot
      if (kind === 'preview') el.outerHTML = previewHtml(key, url, adId);
      else if (kind === 'adsmanager' && url) el.outerHTML = adsManagerHtml(key, url, adId);
      else el.outerHTML = noneHtml(key);
    });
  }

  // The markup for one ad name in whatever state it's currently in. Anything
  // cached from a previous visit renders as a live link on the first paint; the
  // rest get a placeholder the queue upgrades in place.
  function linkHtml(adName) {
    const key = domKey(adName);
    const hit = cachedPreview(adName);
    if (hit) return previewHtml(key, hit.url, hit.ad_id);
    if (state.authFailed) {
      return `<span class="adrill-noad" data-adkey="${key}" title="Not signed in to Facebook — sign in to load creative previews">no link</span>`;
    }
    const term = state.terminal.get(norm(adName));
    if (term && term.kind === 'adsmanager' && term.url) return adsManagerHtml(key, term.url, term.adId);
    if (term) return noneHtml(key);
    return `<span class="adrill-pending" data-adkey="${key}" title="Resolving this ad in Meta…">resolving…</span>`;
  }

  // Copy the FULL ad name — they run past 100 characters and selecting one out
  // of a table cell by hand is miserable.
  function copyHtml(adName) {
    if (!adName) return '';
    return `<button type="button" class="adlink-copy" data-adcopy="${encodeURIComponent(adName)}"`
      + ` title="Copy this ad name">copy</button>`;
  }

  function cellHtml(adName, opts = {}) {
    const parts = [linkHtml(adName)];
    if (opts.copy) parts.push(copyHtml(adName));
    return parts.join('');
  }

  // Synchronous, inside the click gesture, no permission prompt and no promise
  // to wait on. Deliberately tried FIRST: navigator.clipboard.writeText() can
  // hang indefinitely when the clipboard-write permission is undecided or the
  // window isn't focused, which leaves the button doing visibly nothing.
  // execCommand is deprecated but universally supported and instant.
  function copySync(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch { return false; }
  }

  const CSS = `
    .adrill-preview {
      display: inline-block; margin-left: 5px; padding: 1px 6px;
      background: #eef3ff; color: var(--fb-blue, #1877f2); border-radius: 3px;
      font-size: 0.66rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.03em; text-decoration: none; vertical-align: 1px;
      white-space: nowrap;
    }
    .adrill-preview:hover { background: var(--fb-blue, #1877f2); color: #fff; }
    .adrill-preview--fallback { background: #f3f0e8; color: #8a6d3b; }
    .adrill-preview--fallback:hover { background: #8a6d3b; color: #fff; }
    /* Kept byte-for-byte equivalent to the definitions that were inline in
       meta-cvr-impact.html: this stylesheet is appended at runtime and so wins
       ties against the page's own, and the tab shouldn't change appearance just
       because the resolver moved out of it. */
    .adrill-pending {
      display: inline-block; margin-left: 5px; font-size: 0.66rem;
      color: var(--text-secondary, #65676b); font-style: italic; white-space: nowrap;
      opacity: 0.75;
    }
    .adrill-noad {
      font-size: 0.66rem; color: var(--text-secondary, #65676b); font-weight: 400;
      margin-left: 4px; cursor: help;
      border-bottom: 1px dotted var(--text-secondary, #65676b);
    }
    .adlink-copy {
      display: inline-block; margin-left: 4px; padding: 1px 6px;
      background: #f0f2f5; color: var(--text-secondary, #65676b);
      border: 1px solid var(--border, #dddfe2); border-radius: 3px;
      font: inherit; font-size: 0.66rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.03em; cursor: pointer; vertical-align: 1px; white-space: nowrap;
    }
    .adlink-copy:hover { background: #e4e6eb; color: var(--fb-blue, #1877f2); }
    .adlink-copy--done { background: #dcfce7; color: #1a7f37; border-color: #a7e0b8; }
  `;

  function install() {
    const style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    // CAPTURE phase, deliberately. Host rows bind their own click listener
    // directly on the <td> ("expand me"), which runs BEFORE anything delegated
    // on document in the bubble phase — so stopping propagation there was too
    // late: copying also toggled the row and the re-render wiped the button's
    // feedback. Capture on document runs first and stops the row cold.
    document.addEventListener('click', (e) => {
      const btn = e.target.closest && e.target.closest('.adlink-copy');
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      const name = decodeURIComponent(btn.dataset.adcopy || '');

      const flash = (ok) => {
        btn.textContent = ok ? 'copied' : 'failed';
        btn.classList.toggle('adlink-copy--done', ok);
        setTimeout(() => {
          btn.textContent = 'copy';
          btn.classList.remove('adlink-copy--done');
        }, 1300);
      };

      if (copySync(name)) { flash(true); return; }
      // Only if the synchronous route was refused. writeText() can hang forever
      // on an undecided clipboard-write permission, so the timeout guarantees the
      // button always says something rather than looking dead.
      if (navigator.clipboard && navigator.clipboard.writeText) {
        let settled = false;
        const done = (ok) => { if (!settled) { settled = true; flash(ok); } };
        navigator.clipboard.writeText(name).then(() => done(true), () => done(false));
        setTimeout(() => done(false), 1200);
      } else {
        flash(false);
      }
    }, true);

    // Same reason, same phase: opening a creative preview shouldn't also expand
    // the row the link happens to sit in. Propagation only — the anchor's own
    // default (open in a new tab) is left alone.
    document.addEventListener('click', (e) => {
      if (e.target.closest && e.target.closest('.adrill-preview')) e.stopPropagation();
    }, true);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', install);
  else install();

  window.AdLink = {
    state,
    setLookupEnd(d) { lookupEnd = d || null; },
    enqueue,
    cellHtml,
    linkHtml,
    copyHtml,
    onProgress(fn) { state.listeners.add(fn); },
    offProgress(fn) { state.listeners.delete(fn); },
    norm,
  };
})();
