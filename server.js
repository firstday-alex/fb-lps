require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const META_API_VERSION = 'v21.0';
const META_BASE_URL = `https://graph.facebook.com/${META_API_VERSION}`;
const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const REDIRECT_URI = `${BASE_URL}/auth/facebook/callback`;
const COOKIE_SECRET = process.env.SESSION_SECRET || 'fallback-secret-change-me-32chars!';

// --- Token encryption (for storing in cookie) ---

const ALGORITHM = 'aes-256-gcm';

function getEncryptionKey() {
  return crypto.createHash('sha256').update(COOKIE_SECRET).digest();
}

function encryptToken(token) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${encrypted}`;
}

function decryptToken(data) {
  try {
    const [ivHex, tagHex, encrypted] = data.split(':');
    const key = getEncryptionKey();
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return null;
  }
}

// --- Cookie helpers ---

const COOKIE_NAME = 'fb_token';
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production' || BASE_URL.startsWith('https'),
  sameSite: 'lax',
  maxAge: 3600000,
  path: '/'
};

function setTokenCookie(res, token) {
  res.cookie(COOKIE_NAME, encryptToken(token), COOKIE_OPTIONS);
}

function getTokenFromCookie(req) {
  const cookie = req.cookies?.[COOKIE_NAME];
  if (!cookie) return null;
  return decryptToken(cookie);
}

function clearTokenCookie(res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
}

// --- Middleware ---

const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const token = getTokenFromCookie(req);
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated. Please log in.' });
  }
  req.accessToken = token;
  next();
}

// --- OAuth routes ---

app.get('/auth/facebook', (req, res) => {
  const authUrl = `https://www.facebook.com/${META_API_VERSION}/dialog/oauth`
    + `?client_id=${META_APP_ID}`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    + `&scope=ads_read`
    + `&response_type=code`;
  res.redirect(authUrl);
});

app.get('/auth/facebook/callback', async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    return res.redirect('/?error=' + encodeURIComponent(error_description || error));
  }
  if (!code) {
    return res.redirect('/?error=No+authorization+code+received');
  }

  try {
    const tokenUrl = `${META_BASE_URL}/oauth/access_token`
      + `?client_id=${META_APP_ID}`
      + `&client_secret=${META_APP_SECRET}`
      + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
      + `&code=${code}`;

    const tokenResponse = await fetch(tokenUrl);
    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      return res.redirect('/?error=' + encodeURIComponent(tokenData.error.message));
    }

    setTokenCookie(res, tokenData.access_token);
    res.redirect('/');
  } catch (err) {
    console.error('Token exchange failed:', err);
    res.redirect('/?error=Token+exchange+failed');
  }
});

app.get('/auth/logout', (req, res) => {
  clearTokenCookie(res);
  res.redirect('/');
});

app.get('/api/auth-status', (req, res) => {
  const token = getTokenFromCookie(req);
  res.json({ authenticated: !!token });
});

// --- Data routes ---

app.get('/api/ad-accounts', requireAuth, async (req, res) => {
  try {
    const url = `${META_BASE_URL}/me/adaccounts`
      + `?fields=id,name,account_id,account_status`
      + `&${metaParams(req.accessToken)}`
      + `&limit=100`;

    const response = await fetch(url);
    const data = await response.json();

    if (data.error) {
      if (data.error.code === 190) {
        clearTokenCookie(res);
        return res.status(401).json({ error: 'Session expired. Please log in again.' });
      }
      return res.status(400).json({ error: data.error.message });
    }

    const accounts = (data.data || []).map(acc => ({
      id: acc.id,
      name: acc.name,
      account_id: acc.account_id,
      account_status: acc.account_status
    }));

    res.json({ accounts });
  } catch (err) {
    console.error('Failed to fetch ad accounts:', err);
    res.status(500).json({ error: 'Failed to fetch ad accounts' });
  }
});

app.get('/api/top-ads', requireAuth, async (req, res) => {
  const { account_id } = req.query;

  if (!account_id) {
    return res.status(400).json({ error: 'account_id is required' });
  }

  try {
    // Step 1: Get top 10 ads by spend yesterday
    const insightsUrl = `${META_BASE_URL}/${account_id}/insights`
      + `?fields=ad_id,ad_name,spend,impressions,clicks`
      + `&date_preset=yesterday`
      + `&level=ad`
      + `&sort=spend_descending`
      + `&limit=10`
      + `&${metaParams(req.accessToken)}`;

    const insightsResponse = await fetch(insightsUrl);
    const insightsData = await insightsResponse.json();

    if (insightsData.error) {
      if (insightsData.error.code === 190) {
        clearTokenCookie(res);
        return res.status(401).json({ error: 'Session expired. Please log in again.' });
      }
      return res.status(400).json({ error: insightsData.error.message });
    }

    const ads = insightsData.data || [];
    if (ads.length === 0) {
      return res.json({ ads: [] });
    }

    // Step 2: Fetch creative details for each ad in parallel
    const adsWithCreatives = await Promise.all(
      ads.map(async (ad) => {
        try {
          const creativeUrl = `${META_BASE_URL}/${ad.ad_id}`
            + `?fields=creative{id,name,thumbnail_url,image_url,object_story_spec,effective_object_story_spec,asset_feed_spec}`
            + `&${metaParams(req.accessToken)}`;

          const creativeResponse = await fetch(creativeUrl);
          const creativeData = await creativeResponse.json();

          const creative = creativeData.creative || {};
          const storySpec = creative.object_story_spec || {};
          const effectiveStorySpec = creative.effective_object_story_spec || {};
          const assetFeedSpec = creative.asset_feed_spec || {};

          const destinationUrl = extractDestinationUrl(storySpec)
            || extractDestinationUrl(effectiveStorySpec)
            || extractAssetFeedUrl(assetFeedSpec);

          const imageUrl = creative.image_url
            || storySpec?.link_data?.picture
            || creative.thumbnail_url
            || null;

          const isVideo = !!storySpec.video_data;

          return {
            ad_id: ad.ad_id,
            ad_name: ad.ad_name,
            spend: ad.spend,
            impressions: ad.impressions,
            clicks: ad.clicks,
            destination_url: destinationUrl,
            image_url: imageUrl,
            thumbnail_url: creative.thumbnail_url || null,
            is_video: isVideo
          };
        } catch (creativeErr) {
          console.error(`Failed to fetch creative for ad ${ad.ad_id}:`, creativeErr);
          return {
            ad_id: ad.ad_id,
            ad_name: ad.ad_name,
            spend: ad.spend,
            impressions: ad.impressions,
            clicks: ad.clicks,
            destination_url: null,
            image_url: null,
            thumbnail_url: null,
            is_video: false
          };
        }
      })
    );

    res.json({ ads: adsWithCreatives });
  } catch (err) {
    console.error('Failed to fetch top ads:', err);
    res.status(500).json({ error: 'Failed to fetch top ads' });
  }
});

// --- Helpers ---

function generateAppSecretProof(accessToken) {
  return crypto.createHmac('sha256', META_APP_SECRET).update(accessToken).digest('hex');
}

function metaParams(accessToken) {
  return `access_token=${encodeURIComponent(accessToken)}&appsecret_proof=${generateAppSecretProof(accessToken)}`;
}

function extractDestinationUrl(storySpec) {
  if (storySpec.link_data?.link) {
    return storySpec.link_data.link;
  }
  if (storySpec.link_data?.call_to_action?.value?.link) {
    return storySpec.link_data.call_to_action.value.link;
  }
  if (storySpec.video_data?.call_to_action?.value?.link) {
    return storySpec.video_data.call_to_action.value.link;
  }
  if (storySpec.video_data?.link) {
    return storySpec.video_data.link;
  }
  if (storySpec.link_data?.child_attachments?.length > 0) {
    return storySpec.link_data.child_attachments[0].link;
  }
  if (storySpec.template_data?.link) {
    return storySpec.template_data.link;
  }
  if (storySpec.photo_data?.call_to_action?.value?.link) {
    return storySpec.photo_data.call_to_action.value.link;
  }
  return null;
}

function extractAssetFeedUrl(assetFeedSpec) {
  if (assetFeedSpec.link_urls?.length > 0) {
    return assetFeedSpec.link_urls[0].website_url || assetFeedSpec.link_urls[0].display_url || null;
  }
  if (assetFeedSpec.call_to_action_types?.length > 0 && assetFeedSpec.link_urls?.length > 0) {
    return assetFeedSpec.link_urls[0].website_url || null;
  }
  return null;
}

// --- Start server ---

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
