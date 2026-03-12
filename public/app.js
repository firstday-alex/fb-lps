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

async function loadTopAds() {
  const accountId = document.getElementById('account-select').value;
  if (!accountId) { showError('Please select an ad account.'); return; }

  showLoading(true);
  hideError();
  document.getElementById('ads-grid').classList.add('hidden');
  document.getElementById('empty-state').classList.add('hidden');

  try {
    // Build date range params
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

    // Fetch ads first
    const adsRes = await fetch(`/api/top-ads?account_id=${encodeURIComponent(accountId)}${adsDateParam}`);
    if (adsRes.status === 401) { checkAuthStatus(); return; }

    const adsData = await adsRes.json();
    if (adsData.error) { showError(adsData.error); return; }

    if (!adsData.ads || adsData.ads.length === 0) {
      document.getElementById('empty-state').classList.remove('hidden');
      return;
    }

    // Now fetch Shopify metrics with ad info for matching
    const adList = adsData.ads.map(a => ({ ad_name: a.ad_name, destination_url: a.destination_url }));
    let metricsData = null;
    try {
      const metricsRes = await fetch(`/api/shopify-metrics?days=${shopifyDays}&ads=` + encodeURIComponent(JSON.stringify(adList)));
      if (metricsRes.ok) metricsData = await metricsRes.json();
    } catch {}

    renderAds(adsData.ads, metricsData);
  } catch {
    showError('Failed to fetch ads. Please try again.');
  } finally {
    showLoading(false);
  }
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

function renderAds(ads, metricsData) {
  const grid = document.getElementById('ads-grid');
  grid.innerHTML = '';

  ads.forEach((ad, index) => {
    const card = document.createElement('div');
    card.className = 'ad-card';

    const displayImage = ad.is_video
      ? (ad.thumbnail_url || ad.image_url)
      : (ad.image_url || ad.thumbnail_url);

    const imageHtml = displayImage
      ? `<img src="${escapeHtml(displayImage)}" alt="${escapeHtml(ad.ad_name)}" loading="lazy">`
      : '<div class="ad-card__no-image">No image available</div>';

    const videoBadge = ad.is_video ? '<div class="ad-card__video-badge">VIDEO</div>' : '';
    const partnershipBadge = ad.is_partnership_ad ? '<div class="ad-card__partnership-badge">PARTNERSHIP</div>' : '';

    const destinationHtml = ad.destination_url
      ? `<a href="${escapeHtml(ad.destination_url)}" target="_blank" rel="noopener noreferrer">${truncateUrl(ad.destination_url)}</a>`
      : '<span class="no-url">No destination URL</span>';

    // Match Shopify funnel metrics to this ad
    const metrics = matchMetrics(ad, metricsData);
    const funnelHtml = metrics ? `
      <div class="ad-card__funnel">
        <div class="funnel-title">Shopify Funnel (${getDateRangeLabel()})</div>
        <div class="funnel-metrics">
          <div class="funnel-metric">
            <span class="funnel-value">${formatNumber(metrics.sessions)}</span>
            <span class="funnel-label">Sessions</span>
          </div>
          <div class="funnel-metric">
            <span class="funnel-value">${formatPct(metrics.bounce_rate)}</span>
            <span class="funnel-label">Bounce</span>
          </div>
          <div class="funnel-metric">
            <span class="funnel-value">${formatPct(metrics.added_to_cart_rate)}</span>
            <span class="funnel-label">ATC</span>
          </div>
          <div class="funnel-metric">
            <span class="funnel-value">${formatPct(metrics.reached_checkout_rate)}</span>
            <span class="funnel-label">Checkout</span>
          </div>
          <div class="funnel-metric">
            <span class="funnel-value">${formatPct(metrics.conversion_rate)}</span>
            <span class="funnel-label">CVR</span>
          </div>
          <div class="funnel-metric">
            <span class="funnel-value">${metrics.sessions_that_completed_checkout}</span>
            <span class="funnel-label">Orders</span>
          </div>
        </div>
      </div>
    ` : '';

    card.innerHTML = `
      <div class="ad-card__image-container">
        ${imageHtml}
        ${videoBadge}
        ${partnershipBadge}
        <div class="ad-card__rank">${index + 1}</div>
      </div>
      <div class="ad-card__body">
        <div class="ad-card__name">${escapeHtml(ad.ad_name)}</div>
        <div class="ad-card__stats">
          Spend: <span>$${parseFloat(ad.spend || 0).toFixed(2)}</span>
          Impressions: <span>${formatNumber(ad.impressions)}</span>
          Clicks: <span>${formatNumber(ad.clicks)}</span>
        </div>
        <div class="ad-card__url">${destinationHtml}</div>
        ${funnelHtml}
      </div>
    `;

    grid.appendChild(card);
  });

  grid.classList.remove('hidden');
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
