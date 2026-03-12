document.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
  checkForErrors();
  document.getElementById('load-ads-btn').addEventListener('click', loadTopAds);
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
    // Fetch ads and Shopify metrics in parallel
    const [adsRes, metricsRes] = await Promise.all([
      fetch(`/api/top-ads?account_id=${encodeURIComponent(accountId)}`),
      fetch('/api/shopify-metrics?days=1').catch(() => null),
    ]);

    if (adsRes.status === 401) { checkAuthStatus(); return; }

    const adsData = await adsRes.json();
    if (adsData.error) { showError(adsData.error); return; }

    if (!adsData.ads || adsData.ads.length === 0) {
      document.getElementById('empty-state').classList.remove('hidden');
      return;
    }

    // Build metrics lookup by landing page path
    let metricsMap = {};
    if (metricsRes && metricsRes.ok) {
      const metricsData = await metricsRes.json();
      if (metricsData.metrics) {
        metricsData.metrics.forEach(m => {
          metricsMap[m.landing_page_path] = m;
        });
      }
    }

    renderAds(adsData.ads, metricsMap);
  } catch {
    showError('Failed to fetch ads. Please try again.');
  } finally {
    showLoading(false);
  }
}

// --- Rendering ---

function matchMetrics(destinationUrl, metricsMap) {
  if (!destinationUrl || !Object.keys(metricsMap).length) return null;

  try {
    const parsed = new URL(destinationUrl);
    const path = parsed.pathname;

    // Exact match
    if (metricsMap[path]) return metricsMap[path];

    // Try with/without trailing slash
    const alt = path.endsWith('/') ? path.slice(0, -1) : path + '/';
    if (metricsMap[alt]) return metricsMap[alt];

    // Partial match: find paths that contain the destination slug
    for (const [key, val] of Object.entries(metricsMap)) {
      if (key.includes(path) || path.includes(key)) return val;
    }
  } catch {}

  return null;
}

function formatPct(val) {
  if (val === null || val === undefined) return '-';
  return (val * 100).toFixed(1) + '%';
}

function renderAds(ads, metricsMap) {
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

    // Match Shopify funnel metrics to this ad's destination URL
    const metrics = matchMetrics(ad.destination_url, metricsMap);
    const funnelHtml = metrics ? `
      <div class="ad-card__funnel">
        <div class="funnel-title">Shopify Funnel (Yesterday)</div>
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
