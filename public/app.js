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
    const res = await fetch(`/api/top-ads?account_id=${encodeURIComponent(accountId)}`);
    if (res.status === 401) { checkAuthStatus(); return; }

    const data = await res.json();
    if (data.error) { showError(data.error); return; }

    if (!data.ads || data.ads.length === 0) {
      document.getElementById('empty-state').classList.remove('hidden');
      return;
    }

    renderAds(data.ads);
  } catch {
    showError('Failed to fetch ads. Please try again.');
  } finally {
    showLoading(false);
  }
}

// --- Rendering ---

function renderAds(ads) {
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

    const destinationHtml = ad.destination_url
      ? `<a href="${escapeHtml(ad.destination_url)}" target="_blank" rel="noopener noreferrer">${truncateUrl(ad.destination_url)}</a>`
      : '<span class="no-url">No destination URL</span>';

    card.innerHTML = `
      <div class="ad-card__image-container">
        ${imageHtml}
        ${videoBadge}
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
