/* ───────────────────────────────────────────────────────────────────────────
   Lets another tab open this one already pointed at a date:
     ?start=YYYY-MM-DD&end=YYYY-MM-DD[&autoload=1]

   Used by What Changed's per-row links. Every dashboard that loads it shares the
   same inputs (#date-start / #date-end, compare window synced on 'change') and
   a single load button, so one script covers them all.

   Load it with `defer` AFTER the page's inline script: deferred scripts run
   before DOMContentLoaded fires, so this listener is registered after the
   page's own and runs once the page has set its default dates — otherwise the
   page would overwrite ours with "yesterday".
   ─────────────────────────────────────────────────────────────────────────── */
(function () {
  const qs = new URLSearchParams(location.search);
  const isDay = (v) => /^\d{4}-\d{2}-\d{2}$/.test(v || '');
  const start = qs.get('start');
  if (!isDay(start)) return;
  const end = isDay(qs.get('end')) ? qs.get('end') : start;

  document.addEventListener('DOMContentLoaded', () => {
    const set = (id, v) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.value = v;
      // 'change' is what re-syncs each page's comparison window.
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };
    set('date-start', start);
    set('date-end', end);
    if (qs.get('autoload') === '1') {
      const btn = document.getElementById('btn-shopify-load') || document.getElementById('btn-load');
      if (btn) btn.click();
    }
  });
})();
