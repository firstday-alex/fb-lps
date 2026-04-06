document.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
  checkForErrors();
  document.getElementById('load-ads-btn').addEventListener('click', loadTopAds);

  const dateRange = document.getElementById('date-range');
  const dateStart = document.getElementById('date-start');
  const dateEnd = document.getElementById('date-end');

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

// --- State ---

let _loadMoreState = null;
let _allAds = [];
let _allMetrics = {};
let _shopifyDays = 1;

// --- Load Ads ---

async function loadTopAds() {
  const accountId = document.getElementById('account-select').value;
  if (!accountId) { showError('Please select an ad account.'); return; }

  showLoading(true);
  hideError();
  document.getElementById('table-container').classList.add('hidden');
  document.getElementById('ads-tbody').innerHTML = '';
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

    // Fetch Shopify metrics
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

    if (adsData.has_more && adsData.next_cursor) {
      _loadMoreState = { accountId, adsDateParam, shopifyDays, adsLimit, nextCursor: adsData.next_cursor };
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
  const { accountId, adsDateParam, shopifyDays, adsLimit, nextCursor } = _loadMoreState;
  setLoadMoreLoading(true);

  try {
    const adsData = await fetchAdsPage(accountId, adsLimit, adsDateParam, nextCursor);
    if (!adsData || !adsData.ads.length) { setLoadMoreVisible(false); return; }

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
      _loadMoreState = { ..._loadMoreState, nextCursor: adsData.next_cursor };
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
  const url = `/api/top-ads?lite=1&account_id=${encodeURIComponent(accountId)}&limit=${adsLimit}${adsDateParam}`
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
  const campaigns = new Map();
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

  const tbody = document.getElementById('ads-tbody');
  tbody.innerHTML = '';
  document.getElementById('table-container').classList.remove('hidden');

  filtered.forEach((ad, i) => {
    const row = buildTableRow(ad, i, _allMetrics);
    tbody.appendChild(row);
  });

  const countEl = document.getElementById('campaign-filter-count');
  countEl.textContent = campaignId ? `${filtered.length} ad${filtered.length !== 1 ? 's' : ''}` : '';
}

// --- Table rendering ---

function buildTableRow(ad, index, metricsMap) {
  const tr = document.createElement('tr');
  tr.className = 'ad-row';
  tr.onclick = () => openDetail(ad, metricsMap);

  const parsed = ad.ad_name_parsed || parseAdNameClient(ad.ad_name || '');
  const metrics = metricsMap[ad.ad_name] || null;

  const impressions = parseFloat(ad.impressions) || 0;
  const outClicks = ad.outbound_clicks ?? null;
  const lpViews = ad.landing_page_views ?? null;

  // Build the ad name display: show segments as tags
  const segmentsHtml = buildSegmentsHtml(parsed, ad);

  // Landing page display
  const lpDisplay = parsed.landing_page
    ? escapeHtml(parsed.landing_page === 'HOMEPAGE' ? '/' : '/' + parsed.landing_page)
    : '<span class="muted">--</span>';

  tr.innerHTML = `
    <td class="col-rank">${index + 1}</td>
    <td class="col-name">
      <div class="ad-name-segments">${segmentsHtml}</div>
      <div class="ad-name-campaign">${escapeHtml(ad.campaign_name || '')} <span class="muted">${escapeHtml(ad.adset_name || '')}</span></div>
    </td>
    <td class="col-lp">${lpDisplay}</td>
    <td class="col-num">$${parseFloat(ad.spend || 0).toFixed(2)}</td>
    <td class="col-num">${ad.cpm !== null ? '$' + ad.cpm.toFixed(2) : '--'}</td>
    <td class="col-num">${formatNumber(impressions)}</td>
    <td class="col-num">${outClicks !== null ? formatNumber(outClicks) : '--'}</td>
    <td class="col-num">${lpViews !== null ? formatNumber(lpViews) : '--'}</td>
    <td class="col-num col-shopify">${metrics ? formatNumber(metrics.sessions) : '--'}</td>
    <td class="col-num col-shopify">${metrics ? formatPct(metrics.bounce_rate) : '--'}</td>
    <td class="col-num col-shopify">${metrics ? formatPct(metrics.added_to_cart_rate) : '--'}</td>
    <td class="col-num col-shopify">${metrics ? formatPct(metrics.conversion_rate) : '--'}</td>
    <td class="col-num col-shopify">${metrics ? metrics.sessions_that_completed_checkout : '--'}</td>
  `;

  return tr;
}

function buildSegmentsHtml(parsed, ad) {
  const parts = [];

  // Show parsed segments as inline tags
  if (parsed.segments && parsed.segments.length > 0) {
    parsed.segments.forEach((seg, i) => {
      // First segment is typically the brand
      const cls = i === 0 ? 'seg seg-brand' : 'seg';
      parts.push(`<span class="${cls}">${escapeHtml(seg)}</span>`);
    });
  } else {
    // Fallback: show raw ad name truncated
    const name = ad.ad_name || '(unnamed)';
    parts.push(`<span class="seg">${escapeHtml(name.length > 40 ? name.slice(0, 40) + '...' : name)}</span>`);
  }

  // Partnership badge
  if (parsed.is_partnership) {
    const creator = parsed.creator ? escapeHtml(parsed.creator) : 'partner';
    parts.push(`<span class="seg seg-partner">${creator}</span>`);
  }

  return parts.join(' ');
}

// Client-side ad name parser (fallback if server didn't provide parsed data)
function parseAdNameClient(adName) {
  if (!adName) return { segments: [], landing_page: null, landing_page_url: null, is_partnership: false, creator: null };

  const nameLower = adName.toLowerCase();
  const isPartnership = nameLower.includes(':ext-') || nameLower.includes('creator_wl:ext') || /\bext[-_]creator\b/.test(nameLower);

  let creator = null;
  if (isPartnership) {
    const m = adName.match(/:ext-([^_:]+)/i);
    if (m) creator = m[1];
  }

  let landingPage = null;
  let landingPageUrl = null;
  const urlMatch = adName.match(/(?:^|[_:-])url[:_]([a-zA-Z0-9-]+)/i);
  if (urlMatch) {
    landingPage = urlMatch[1];
    const domain = nameLower.startsWith('trmv') ? 'therearemanyversions.com' : 'firstday.com';
    landingPageUrl = landingPage.toUpperCase() === 'HOMEPAGE'
      ? `https://${domain}/`
      : `https://${domain}/pages/${landingPage}`;
  }

  const segments = adName.split('_')
    .filter(s => !s.match(/^url[:_]/i))
    .map(s => s.replace(/:ext-.*$/i, '').replace(/^ext[-_].*$/i, ''))
    .filter(s => s.length > 0);

  return { segments, landing_page: landingPage, landing_page_url: landingPageUrl, is_partnership: isPartnership, creator };
}

// --- Detail panel ---

function openDetail(ad, metricsMap) {
  const parsed = ad.ad_name_parsed || parseAdNameClient(ad.ad_name || '');
  const metrics = metricsMap[ad.ad_name] || null;
  const impressions = parseFloat(ad.impressions) || 0;
  const outClicks = ad.outbound_clicks ?? null;
  const lpViews = ad.landing_page_views ?? null;
  const outCtr = (outClicks !== null && impressions > 0) ? (outClicks / impressions * 100) : null;
  const lpLoadRate = (outClicks && lpViews !== null) ? (lpViews / outClicks * 100) : null;

  const destLink = parsed.landing_page_url
    ? `<a href="${escapeHtml(parsed.landing_page_url)}" target="_blank" rel="noopener">${escapeHtml(parsed.landing_page_url)}</a>`
    : '<span class="muted">No destination URL</span>';

  let html = `
    <h2>Ad Detail</h2>
    <div class="detail-section">
      <div class="detail-label">Full Ad Name</div>
      <div class="detail-value detail-adname">${escapeHtml(ad.ad_name || '(unnamed)')}</div>
    </div>

    <div class="detail-section">
      <div class="detail-label">Campaign / Ad Set</div>
      <div class="detail-value">${escapeHtml(ad.campaign_name || '--')} / ${escapeHtml(ad.adset_name || '--')}</div>
    </div>

    <div class="detail-section">
      <div class="detail-label">Parsed Segments</div>
      <div class="detail-value">${buildSegmentsHtml(parsed, ad)}</div>
    </div>

    <div class="detail-section">
      <div class="detail-label">Destination URL</div>
      <div class="detail-value">${destLink}</div>
    </div>

    ${parsed.is_partnership ? `
    <div class="detail-section">
      <div class="detail-label">Partnership</div>
      <div class="detail-value"><span class="seg seg-partner">${escapeHtml(parsed.creator || 'Yes')}</span></div>
    </div>` : ''}

    <h3>Meta Performance</h3>
    <div class="detail-grid">
      <div class="detail-metric"><span class="detail-metric-val">$${parseFloat(ad.spend || 0).toFixed(2)}</span><span class="detail-metric-lbl">Spend</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${ad.cpm !== null ? '$' + ad.cpm.toFixed(2) : '--'}</span><span class="detail-metric-lbl">CPM</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${ad.frequency !== null ? ad.frequency.toFixed(1) : '--'}</span><span class="detail-metric-lbl">Frequency</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${formatNumber(impressions)}</span><span class="detail-metric-lbl">Impressions</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${outClicks !== null ? formatNumber(outClicks) : '--'}</span><span class="detail-metric-lbl">Out. Clicks</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${outCtr !== null ? outCtr.toFixed(2) + '%' : '--'}</span><span class="detail-metric-lbl">Out. CTR</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${lpViews !== null ? formatNumber(lpViews) : '--'}</span><span class="detail-metric-lbl">LP Views</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${lpLoadRate !== null ? lpLoadRate.toFixed(1) + '%' : '--'}</span><span class="detail-metric-lbl">LP Load Rate</span></div>
    </div>
  `;

  if (ad.thruplays !== null || ad.avg_watch_time !== null) {
    html += `
    <h3>Video</h3>
    <div class="detail-grid">
      <div class="detail-metric"><span class="detail-metric-val">${ad.thruplays !== null ? formatNumber(ad.thruplays) : '--'}</span><span class="detail-metric-lbl">Thruplays</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${ad.avg_watch_time !== null ? parseFloat(ad.avg_watch_time).toFixed(1) + 's' : '--'}</span><span class="detail-metric-lbl">Avg Watch</span></div>
    </div>`;
  }

  if (metrics) {
    const matchTag = metrics.match_source === 'landing_page'
      ? ' <span class="seg seg-warn">LP match</span>'
      : '';
    html += `
    <h3>Shopify Funnel (${getDateRangeLabel()})${matchTag}</h3>
    <div class="detail-grid">
      <div class="detail-metric"><span class="detail-metric-val">${formatNumber(metrics.sessions)}</span><span class="detail-metric-lbl">Sessions</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${formatPct(metrics.bounce_rate)}</span><span class="detail-metric-lbl">Bounce Rate</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${formatPct(metrics.added_to_cart_rate)}</span><span class="detail-metric-lbl">Add to Cart</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${formatPct(metrics.reached_checkout_rate)}</span><span class="detail-metric-lbl">Reached Checkout</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${formatPct(metrics.conversion_rate)}</span><span class="detail-metric-lbl">Conversion Rate</span></div>
      <div class="detail-metric"><span class="detail-metric-val">${metrics.sessions_that_completed_checkout}</span><span class="detail-metric-lbl">Orders</span></div>
    </div>`;
  } else {
    html += `<h3>Shopify Funnel</h3><p class="muted">No Shopify data matched for this ad.</p>`;
  }

  document.getElementById('detail-content').innerHTML = html;
  document.getElementById('detail-overlay').classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeDetail(e) {
  if (e && e.target !== e.currentTarget) return;
  document.getElementById('detail-overlay').classList.add('hidden');
  document.body.style.overflow = '';
}

// Close on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeDetail();
});

// --- Utilities ---

function setLoadMoreVisible(visible) {
  const btn = document.getElementById('load-more-btn');
  if (btn) btn.style.display = visible ? 'block' : 'none';
}

function setLoadMoreLoading(loading) {
  const btn = document.getElementById('load-more-btn');
  if (!btn) return;
  btn.disabled = loading;
  btn.textContent = loading ? 'Loading...' : 'Load More Ads';
}

function getDateRangeLabel() {
  const dateRange = document.getElementById('date-range').value;
  const labels = { yesterday: 'Yesterday', last_3d: 'Last 3 Days', last_7d: 'Last 7 Days', last_14d: 'Last 14 Days', last_30d: 'Last 30 Days' };
  if (dateRange === 'custom') {
    return `${document.getElementById('date-start').value} to ${document.getElementById('date-end').value}`;
  }
  return labels[dateRange] || dateRange;
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function formatNumber(num) {
  if (!num && num !== 0) return '0';
  return parseInt(num).toLocaleString();
}

function formatPct(val) {
  if (val === null || val === undefined) return '--';
  return (val * 100).toFixed(1) + '%';
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
