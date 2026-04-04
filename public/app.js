document.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
  checkForErrors();
  document.getElementById('load-ads-btn').addEventListener('click', loadTopAds);

  // Toggle custom date inputs
  const dateRange = document.getElementById('date-range');
  const dateStart = document.getElementById('date-start');
  const dateEnd = document.getElementById('date-end');

  // Default custom dates to last 7 days
  const today = new Date();
  const weekAgo = new Date(today);
  weekAgo.setDate(weekAgo.getDate() - 7);
  dateEnd.value = today.toISOString().split('T')[0];
  dateStart.value = weekAgo.toISOString().split('T')[0];

  dateRange.addEventListener('change', () => {
    const isCustom = dateRange.value === 'custom';
    dateStart.classList.toggle('hidden', !isCustom);
    dateEnd.classList.toggle('hidden', !isCustom);
  });
});

// --- Auth ---

async function checkAuthStatus() {
  try {
    const res = await fetch('/api/auth-status');
    const data = await res.json();

    const authSection = document.getElementById('auth-section');
    const accountSection = document.getElementById('account-section');

    if (data.authenticated) {
      authSection.innerHTML = '<button class="btn btn-logout" onclick="logout()">Logout</button>';
      accountSection.classList.remove('hidden');
      loadAdAccounts();
    } else {
      authSection.innerHTML = '<button class="btn btn-login" onclick="login()">Login with Facebook</button>';
      accountSection.classList.add('hidden');
    }
  } catch {
    showError('Failed to check authentication status.');
  }
}

function checkForErrors() {
  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');
  if (error) {
    showError('Authentication error: ' + error);
    window.history.replaceState({}, '', '/');
  }
}

function login() { window.location.href = '/auth/facebook'; }
function logout() { window.location.href = '/auth/logout'; }

// --- Ad Accounts ---

async function loadAdAccounts() {
  try {
    const res = await fetch('/api/ad-accounts');
    if (res.status === 401) { checkAuthStatus(); return; }

    const data = await res.json();
    if (data.error) { showError(data.error); return; }

    const select = document.getElementById('account-select');
    select.innerHTML = '<option value="">-- Choose an account --</option>';

    data.accounts.forEach(acc => {
      const option = document.createElement('option');
      option.value = acc.id;
      option.textContent = `${acc.name} (${acc.account_id})`;
      select.appendChild(option);
    });
  } catch {
    showError('Failed to load ad accounts.');
  }
}

// --- Top Ads ---

// Pagination & filter state
let _loadMoreState = null;
let _allAds = [];        // full list across all loaded pages
let _allMetrics = {};    // merged metrics across all pages
let _shopifyDays = 1;

async function loadTopAds() {
  const accountId = document.getElementById('account-select').value;
  if (!accountId) { showError('Please select an ad account.'); return; }

  showLoading(true);
  hideError();
  document.getElementById('ads-grid').classList.add('hidden');
  document.getElementById('ads-grid').innerHTML = '';
  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('campaign-filter-bar').classList.add('hidden');
  setLoadMoreVisible(false);
  _loadMoreState = null;
  _allAds = [];
  _allMetrics = {};

  try {
    const dateRange = document.getElementById('date-range').value;
    let adsDateParam = '';
    let shopifyDays = 1;

    if (dateRange === 'custom') {
      const since = document.getElementById('date-start').value;
      const until = document.getElementById('date-end').value;
      if (!since || !until) { showError('Please select start and end dates.'); return; }
      adsDateParam = `&since=${since}&until=${until}`;
      shopifyDays = Math.ceil((new Date(until) - new Date(since)) / (1000 * 60 * 60 * 24)) + 1;
    } else {
      adsDateParam = `&date_preset=${dateRange}`;
      const daysMap = { yesterday: 1, last_3d: 3, last_7d: 7, last_14d: 14, last_30d: 30 };
      shopifyDays = daysMap[dateRange] || 1;
    }

    const adsLimit = document.getElementById('ads-limit').value || '25';

    const adsData = await fetchAdsPage(accountId, adsLimit, adsDateParam, null);
    if (!adsData) return;

    if (!adsData.ads || adsData.ads.length === 0) {
      document.getElementById('empty-state').classList.remove('hidden');
      return;
    }

    _shopifyDays = shopifyDays;

    // Shopify metrics for initial batch
    let metricsData = null;
    try {
      const adList = adsData.ads.map(a => ({ ad_name: a.ad_name, destination_url: a.destination_url }));
      const metricsRes = await fetch(`/api/shopify-metrics?days=${shopifyDays}&ads=` + encodeURIComponent(JSON.stringify(adList)));
      if (metricsRes.ok) metricsData = await metricsRes.json();
    } catch {}

    _allAds = adsData.ads;
    _allMetrics = metricsData?.by_ad || {};

    populateCampaignFilter(_allAds);
    applyFilter();

    // Save state for load more
    if (adsData.has_more && adsData.next_cursor) {
      _loadMoreState = { accountId, adsDateParam, shopifyDays, adsLimit, nextCursor: adsData.next_cursor, totalLoaded: adsData.ads.length };
      setLoadMoreVisible(true);
    }
  } catch {
    showError('Failed to fetch ads. Please try again.');
  } finally {
    showLoading(false);
  }
}

async function loadMoreAds() {
  if (!_loadMoreState) return;
  const { accountId, adsDateParam, shopifyDays, adsLimit, nextCursor, totalLoaded } = _loadMoreState;

  setLoadMoreLoading(true);

  try {
    const adsData = await fetchAdsPage(accountId, adsLimit, adsDateParam, nextCursor);
    if (!adsData || !adsData.ads.length) { setLoadMoreVisible(false); return; }

    // Shopify metrics for this batch
    try {
      const adList = adsData.ads.map(a => ({ ad_name: a.ad_name, destination_url: a.destination_url }));
      const metricsRes = await fetch(`/api/shopify-metrics?days=${shopifyDays}&ads=` + encodeURIComponent(JSON.stringify(adList)));
      if (metricsRes.ok) {
        const md = await metricsRes.json();
        Object.assign(_allMetrics, md.by_ad || {});
      }
    } catch {}

    _allAds = [..._allAds, ...adsData.ads];
    populateCampaignFilter(_allAds);
    applyFilter();

    if (adsData.has_more && adsData.next_cursor) {
      _loadMoreState = { ..._loadMoreState, nextCursor: adsData.next_cursor, totalLoaded: totalLoaded + adsData.ads.length };
      setLoadMoreVisible(true);
    } else {
      _loadMoreState = null;
      setLoadMoreVisible(false);
    }
  } catch {
    showError('Failed to load more ads.');
  } finally {
    setLoadMoreLoading(false);
  }
}

async function fetchAdsPage(accountId, adsLimit, adsDateParam, after) {
  const url = `/api/top-ads?account_id=${encodeURIComponent(accountId)}&limit=${adsLimit}${adsDateParam}`
    + (after ? `&after=${encodeURIComponent(after)}` : '');
  const res = await fetch(url);
  if (res.status === 401) { checkAuthStatus(); return null; }
  const data = await res.json();
  if (data.error) { showError(data.error); return null; }
  return data;
}

// --- Campaign filter ---

function populateCampaignFilter(ads) {
  const select = document.getElementById('campaign-filter');
  const current = select.value;
  const campaigns = new Map(); // id → name
  ads.forEach(a => { if (a.campaign_id) campaigns.set(a.campaign_id, a.campaign_name || a.campaign_id); });

  select.innerHTML = '<option value="">All Campaigns</option>';
  [...campaigns.entries()]
    .sort((a, b) => a[1].localeCompare(b[1]))
    .forEach(([id, name]) => {
      const opt = document.createElement('option');
      opt.value = id;
      opt.textContent = name;
      if (id === current) opt.selected = true;
      select.appendChild(opt);
    });

  const bar = document.getElementById('campaign-filter-bar');
  if (campaigns.size > 1) {
    bar.classList.remove('hidden');
    select.onchange = applyFilter;
  } else {
    bar.classList.add('hidden');
  }
}

function applyFilter() {
  const campaignId = document.getElementById('campaign-filter').value;
  const filtered = campaignId ? _allAds.filter(a => a.campaign_id === campaignId) : _allAds;

  const grid = document.getElementById('ads-grid');
  grid.innerHTML = '';
  grid.classList.remove('hidden');

  const metricsObj = { by_ad: _allMetrics };
  filtered.forEach((ad, i) => appendAdCard(ad, i, metricsObj));

  const countEl = document.getElementById('campaign-filter-count');
  countEl.textContent = campaignId ? `${filtered.length} ad${filtered.length !== 1 ? 's' : ''}` : '';
}

function setLoadMoreVisible(visible) {
  let btn = document.getElementById('load-more-btn');
  if (!btn) return;
  btn.style.display = visible ? 'block' : 'none';
}

function setLoadMoreLoading(loading) {
  const btn = document.getElementById('load-more-btn');
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? 'Loading…' : 'Load More Ads';
}

// --- Rendering ---

function matchMetrics(ad, metricsData) {
  if (!metricsData?.by_ad || !ad.ad_name) return null;
  return metricsData.by_ad[ad.ad_name] || null;
}

function formatPct(val) {
  if (val === null || val === undefined) return '-';
  return (val * 100).toFixed(1) + '%';
}

function getDateRangeLabel() {
  const dateRange = document.getElementById('date-range').value;
  const labels = { yesterday: 'Yesterday', last_3d: 'Last 3 Days', last_7d: 'Last 7 Days', last_14d: 'Last 14 Days', last_30d: 'Last 30 Days' };
  if (dateRange === 'custom') {
    return `${document.getElementById('date-start').value} to ${document.getElementById('date-end').value}`;
  }
  return labels[dateRange] || dateRange;
}

function renderAds(ads, metricsData, startIndex = 0) {
  // kept for backward compat — applyFilter is the main render path now
  const grid = document.getElementById('ads-grid');
  grid.classList.remove('hidden');
  ads.forEach((ad, i) => appendAdCard(ad, startIndex + i, { by_ad: metricsData?.by_ad || {} }));
}

function appendAdCard(ad, index_, metricsData) {
  const grid = document.getElementById('ads-grid');
  const card = document.createElement('div');
  card.className = 'ad-card';
  card.dataset.campaignId = ad.campaign_id || '';

  const displayImage = ad.is_video
    ? (ad.thumbnail_url || ad.image_url)
    : (ad.image_url || ad.thumbnail_url);

  const imgTag = displayImage
    ? `<img src="${escapeHtml(displayImage)}" alt="" loading="lazy" onerror="this.parentElement.innerHTML='<div class=ad-card__no-image>No image available</div>'">`
    : '<div class="ad-card__no-image">No image available</div>';

  const imageHtml = ad.preview_url && displayImage
    ? `<a href="${escapeHtml(ad.preview_url)}" target="_blank" rel="noopener noreferrer" class="ad-card__image-link">${imgTag}</a>`
    : imgTag;

  const videoBadge = ad.is_video ? '<div class="ad-card__video-badge">VIDEO</div>' : '';
  const partnershipBadge = ad.is_partnership_ad ? '<div class="ad-card__partnership-badge">PARTNERSHIP</div>' : '';

  const sourceTag = ad.url_source
    ? `<span class="url-source" title="Resolved via: ${escapeHtml(ad.url_source)}">${escapeHtml(ad.url_source)}</span>`
    : '';
  const destinationHtml = ad.destination_url
    ? `<a href="${escapeHtml(ad.destination_url)}" target="_blank" rel="noopener noreferrer">${truncateUrl(ad.destination_url)}</a>${sourceTag}`
    : '<span class="no-url">No destination URL</span>';

  // --- Meta performance stats ---
  const impressions = parseFloat(ad.impressions) || 0;
  const outClicks   = ad.outbound_clicks ?? null;
  const lpViews     = ad.landing_page_views ?? null;
  const outCtr      = (outClicks !== null && impressions > 0) ? (outClicks / impressions * 100) : null;
  const lpLoadRate  = (outClicks && lpViews !== null) ? (lpViews / outClicks * 100) : null;

  const statFmt = (val, prefix = '', suffix = '', decimals = 2) =>
    val !== null && val !== undefined ? `${prefix}${parseFloat(val).toFixed(decimals)}${suffix}` : '—';

  const campaignCtx = ad.campaign_name
    ? `<div class="ad-card__campaign" title="${escapeHtml(ad.campaign_name)} › ${escapeHtml(ad.adset_name || '')}">${escapeHtml(ad.campaign_name)}<span class="ad-card__adset"> › ${escapeHtml(ad.adset_name || '—')}</span></div>`
    : '';

  const videoStatsHtml = ad.is_video && (ad.thruplays !== null || ad.avg_watch_time !== null) ? `
    <div class="ad-card__stat-row ad-card__stat-row--video">
      <span class="stat-item"><span class="stat-label">Thruplay</span><span class="stat-val">${statFmt(ad.thruplays, '', '', 0)}</span></span>
      <span class="stat-item"><span class="stat-label">Avg Watch</span><span class="stat-val">${ad.avg_watch_time !== null ? parseFloat(ad.avg_watch_time).toFixed(1) + 's' : '—'}</span></span>
    </div>` : '';

  // --- Shopify funnel ---
  const metrics = matchMetrics(ad, metricsData);
  const funnelMatchTag = metrics?.match_source === 'landing_page'
    ? `<span class="funnel-match-tag" title="Matched by landing page URL — includes all Facebook traffic to this page, not just this ad">LP match</span>`
    : '';
  const funnelHtml = metrics ? `
    <div class="ad-card__funnel">
      <div class="funnel-title">Shopify Funnel (${getDateRangeLabel()})${funnelMatchTag}</div>
      <div class="funnel-metrics">
        <div class="funnel-metric"><span class="funnel-value">${formatNumber(metrics.sessions)}</span><span class="funnel-label">Sessions</span></div>
        <div class="funnel-metric"><span class="funnel-value">${formatPct(metrics.bounce_rate)}</span><span class="funnel-label">Bounce</span></div>
        <div class="funnel-metric"><span class="funnel-value">${formatPct(metrics.added_to_cart_rate)}</span><span class="funnel-label">ATC</span></div>
        <div class="funnel-metric"><span class="funnel-value">${formatPct(metrics.reached_checkout_rate)}</span><span class="funnel-label">Checkout</span></div>
        <div class="funnel-metric"><span class="funnel-value">${formatPct(metrics.conversion_rate)}</span><span class="funnel-label">CVR</span></div>
        <div class="funnel-metric"><span class="funnel-value">${metrics.sessions_that_completed_checkout}</span><span class="funnel-label">Orders</span></div>
      </div>
    </div>` : '';

  card.innerHTML = `
    <div class="ad-card__image-container">
      ${imageHtml}
      ${videoBadge}
      ${partnershipBadge}
      <div class="ad-card__rank">${index_ + 1}</div>
    </div>
    <div class="ad-card__body">
      ${campaignCtx}
      <div class="ad-card__name">${escapeHtml(ad.ad_name)}</div>
      <div class="ad-card__stat-row">
        <span class="stat-item"><span class="stat-label">Spend</span><span class="stat-val">$${parseFloat(ad.spend || 0).toFixed(2)}</span></span>
        <span class="stat-item"><span class="stat-label">CPM</span><span class="stat-val">${statFmt(ad.cpm, '$')}</span></span>
        <span class="stat-item"><span class="stat-label">Freq</span><span class="stat-val">${statFmt(ad.frequency, '', '', 1)}</span></span>
        <span class="stat-item"><span class="stat-label">Impr</span><span class="stat-val">${formatNumber(ad.impressions)}</span></span>
      </div>
      <div class="ad-card__stat-row">
        <span class="stat-item"><span class="stat-label">Out. Clicks</span><span class="stat-val">${outClicks !== null ? formatNumber(outClicks) : '—'}</span></span>
        <span class="stat-item"><span class="stat-label">Out. CTR</span><span class="stat-val">${outCtr !== null ? outCtr.toFixed(2) + '%' : '—'}</span></span>
        <span class="stat-item"><span class="stat-label">LP Views</span><span class="stat-val">${lpViews !== null ? formatNumber(lpViews) : '—'}</span></span>
        <span class="stat-item"><span class="stat-label">LP Load</span><span class="stat-val">${lpLoadRate !== null ? lpLoadRate.toFixed(1) + '%' : '—'}</span></span>
      </div>
      ${videoStatsHtml}
      <div class="ad-card__url">${destinationHtml}</div>
      ${funnelHtml}
    </div>
  `;

  grid.appendChild(card);
}

// --- Utilities ---

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function truncateUrl(url, maxLen = 60) {
  if (!url) return '';
  try {
    const parsed = new URL(url);
    const display = parsed.hostname + parsed.pathname;
    return display.length > maxLen ? display.substring(0, maxLen) + '...' : display;
  } catch {
    return url.length > maxLen ? url.substring(0, maxLen) + '...' : url;
  }
}

function formatNumber(num) {
  if (!num) return '0';
  return parseInt(num).toLocaleString();
}

function showLoading(visible) {
  document.getElementById('loading').classList.toggle('hidden', !visible);
}

function showError(message) {
  const el = document.getElementById('error-message');
  el.textContent = message;
  el.classList.remove('hidden');
}

function hideError() {
  document.getElementById('error-message').classList.add('hidden');
}
