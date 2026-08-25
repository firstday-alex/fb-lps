# Facebook Ads LP Viewer

Express app (`server.js`) serving a set of static dashboard pages from `public/`.
It reads Shopify session/funnel data via the ShopifyQL + Admin GraphQL APIs and
Facebook ad creative data via the Meta Marketing API, and renders them as
filterable, heat-coloured tables.

## Deploying — push straight to production

**You are authorised to commit and push to `main` without asking each time.**
Vercel is connected to this GitHub repo (`firstday-alex/fb-lps`), so a push to
`main` publishes to production. Treat "make this change" as including "ship it":
commit with a clear message and push, then tell the user what went live.

This standing authorisation covers ordinary forward changes only. Still ask first
for anything that rewrites or discards history or is hard to undo:
`push --force`, `reset --hard` on pushed commits, rebasing published branches,
deleting branches or tags, or reverting someone else's work.

Verify before you push. The app has no test suite, so "verified" means you
actually ran it (see below) — not that the file parses.

### Boundary: code yes, platform data no

Pushing code here is fine. Writing data into the connected platforms is not.
Shopify, Meta, ClickUp, Gorgias and the rest stay **read-only**; Gmail and Slack
are **drafts only**. That is an organisation-level rule and it outranks anything
in this file. A dashboard change that only reads data is always fine; anything
that would mutate store, ad-account or helpdesk data needs the user to do it.

## Running it locally

```bash
node server.js          # http://localhost:3000
npm run dev             # same, with --watch
```

Credentials come from `.env` (see `.env.example`): `SHOPIFY_URL`,
`SHOPIFY_TOKEN`, `META_APP_ID`, `META_APP_SECRET`, `SESSION_SECRET`, `BASE_URL`.

`APP_PASSWORD` gates the whole app and is set in Vercel, not in `.env`. Locally
it is absent, so the server logs a warning and serves without the password gate —
that is expected, and it makes the JSON endpoints directly curl-able:

```bash
curl -s "http://localhost:3000/api/lp-by-channel-data?start=2026-08-18&end=2026-08-24&group=lp&limit=5"
```

That is the fastest way to check a dashboard change against real data: hit the
endpoint, confirm the numbers reconcile (a drill level's `totals` should match
the parent row it expanded from), then look at the page in a browser.

## Layout

- `server.js` — every route: page serving, the `/api/*-data` endpoints that build
  and run ShopifyQL, Meta OAuth + creative lookups, the password gate, and the
  daily-report cron target (`/api/generate-daily-report`, weekdays 14:00 UTC).
- `public/*.html` — one self-contained page per dashboard tab. Each carries its
  own CSS and script inline; they are not built or bundled.
- `public/app-nav.js` — the shared tab nav injected into every page.
- `public/ad-preview-link.js` — resolves ad names to Meta creative previews.
  Meta-only, so pages guard it behind a "is this Meta traffic?" check.
- `data/` — file-backed persistence used when the Vercel KV env vars are absent.

## Conventions

- Comments explain *why*, especially where a query or a guard looks arbitrary —
  the existing ones record real bugs (ShopifyQL's 1000-row cap, `TOP N` counting
  pairs when you add a dimension to `GROUP BY`, NUL separators in drill keys).
  Match that: when you work around something surprising, say what it was.
- ShopifyQL values are interpolated, so every user-supplied string goes through
  the local `esc()` helper. Exact-match filters (`*_exact`) beat `CONTAINS`
  filters for drill-downs — `CONTAINS` silently folds sibling rows together.
- Dashboards report Shopify-attributed CVR, which runs well below Ads Manager by
  design. Don't "fix" that gap.
