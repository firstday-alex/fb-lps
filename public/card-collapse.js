/* ───────────────────────────────────────────────────────────────────────────
   Collapsible cards for the AOV tabs.

   Same treatment as makeCardsCollapsible() on meta-cvr-impact.html: the card's
   h3 + p.card__sub become a clickable header, everything else moves into a body
   that hides when collapsed. Nodes are moved, not re-created, so ids and any
   listeners bound to controls inside the card keep working.

   Everything starts collapsed except cards marked data-no-collapse="1" (the
   page's answer card) or listed in `defaultOpen`. Open/closed choices are kept
   for the life of the page only — not in localStorage — so every visit opens
   on the same collapsed default, which is what the user asked for. They do
   survive re-renders: net-aov.js rebuilds its cards on every toggle, and calls
   apply() again afterwards.
   ─────────────────────────────────────────────────────────────────────────── */
(function () {
  const chosen = {};   // card id → open?, for this page view

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function apply(scope, opts = {}) {
    const defaultOpen = new Set(opts.defaultOpen || []);
    (scope || document).querySelectorAll('.card').forEach(card => {
      if (card.dataset.collapsibleDone === '1' || card.dataset.noCollapse === '1') return;
      const h3 = card.querySelector(':scope > h3');
      if (!h3) return;
      // State is keyed by id. The older AOV cards are static markup without ids;
      // their titles are unique on each page, so a slug of the title is stable.
      if (!card.id) card.id = 'cc-' + h3.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60);
      const sub = card.querySelector(':scope > p.card__sub');
      const title = h3.textContent.trim();
      const hint = sub ? sub.textContent.trim().replace(/\s+/g, ' ') : '';
      // A card whose header line IS its summary (the numbers) opts out of the
      // 90-char cut and wraps instead, and stays visible when the card is open.
      const full = card.dataset.hintFull === '1';
      if (full) card.classList.add('hint-full');

      const header = document.createElement('div');
      header.className = 'card-toggle';
      header.innerHTML = `
        <span class="card-toggle__chevron">&#9660;</span>
        <span class="card-toggle__title">${esc(title)}</span>
        ${hint ? `<span class="card-toggle__hint">${esc(full || hint.length <= 90 ? hint : hint.slice(0, 87) + '…')}</span>` : ''}`;
      const body = document.createElement('div');
      body.className = 'card-toggle__body';
      // The description is useful once the card is open, so it stays in the body;
      // only the h3 moves up into the header.
      h3.remove();
      while (card.firstChild) body.appendChild(card.firstChild);
      card.appendChild(header);
      card.appendChild(body);

      card.classList.add('collapsible');
      const open = card.id in chosen ? chosen[card.id] : defaultOpen.has(card.id);
      card.classList.toggle('collapsed', !open);
      card.dataset.collapsibleDone = '1';
      header.addEventListener('click', () => {
        chosen[card.id] = !card.classList.toggle('collapsed');
      });
    });
  }

  function setAll(scope, open) {
    (scope || document).querySelectorAll('.card.collapsible').forEach(card => {
      card.classList.toggle('collapsed', !open);
      chosen[card.id] = open;
    });
  }

  const css = document.createElement('style');
  css.textContent = `
    .card.collapsible { padding: 0; }
    .card-toggle { cursor: pointer; display: flex; align-items: center; gap: 10px; padding: 14px 20px;
      font-size: 0.95rem; font-weight: 600; color: var(--text-primary); user-select: none; }
    .card-toggle:hover { background: #f7f9fc; }
    .card-toggle__chevron { display: inline-block; transition: transform 0.2s; font-size: 0.7em; color: var(--text-secondary); width: 12px; }
    .card.collapsed .card-toggle__chevron { transform: rotate(-90deg); }
    .card-toggle__title { flex: 0 0 auto; }
    .card-toggle__hint { flex: 1; min-width: 0; font-size: 0.78rem; font-weight: 400; color: var(--text-secondary);
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .card.collapsed .card-toggle__hint { white-space: nowrap; }
    .card:not(.collapsed):not(.hint-full) .card-toggle__hint { display: none; }
    .card.hint-full .card-toggle { flex-wrap: wrap; }
    .card.hint-full .card-toggle__hint { white-space: normal; flex-basis: 100%; padding-left: 22px; color: var(--text-primary); }
    .card-toggle__body { padding: 16px 20px 20px; border-top: 1px solid var(--border); }
    .card.collapsed .card-toggle__body { display: none; }
    .cc-bar { display: flex; justify-content: flex-end; gap: 8px; margin: 0 0 10px; }
    .cc-bar button { font: inherit; font-size: 0.75rem; padding: 4px 10px; background: var(--surface);
      border: 1px solid var(--border); border-radius: 6px; cursor: pointer; color: var(--text-secondary); }
    .cc-bar button:hover { color: var(--fb-blue); }
    .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border);
      border-top-color: var(--fb-blue); border-radius: 50%; animation: cc-spin 0.8s linear infinite;
      vertical-align: -2px; margin-right: 8px; }
    @keyframes cc-spin { to { transform: rotate(360deg); } }
    .progress { height: 6px; background: var(--neutral-bg, #e4e6eb); border-radius: 3px; overflow: hidden; margin-top: 8px; }
    .progress > div { height: 100%; background: var(--fb-blue); transition: width 0.3s; }
    @media (max-width: 640px) { .card-toggle__hint { display: none; } }
  `;
  document.head.appendChild(css);

  window.CardCollapse = { apply, setAll };
})();
