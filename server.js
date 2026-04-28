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

const SHOPIFY_URL = (process.env.SHOPIFY_URL || '').replace('https://', '').replace(/\/$/, '');
const SHOPIFY_TOKEN = process.env.SHOPIFY_TOKEN;
const SHOPIFY_API_VERSION = '2025-10';

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
app.use(express.json({ limit: '32kb' }));
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
    + `&scope=ads_read,pages_read_engagement,pages_show_list,business_management`
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
  const { account_id, date_preset, since, until, after } = req.query;
  const adsLimit = Math.min(Math.max(parseInt(req.query.limit) || 25, 1), 50);

  if (!account_id) {
    return res.status(400).json({ error: 'account_id is required' });
  }

  try {
    // Step 1: Get top N ads by spend for the given date range
    let dateParams;
    if (since && until) {
      dateParams = `&time_range={"since":"${since}","until":"${until}"}`;
    } else {
      dateParams = `&date_preset=${date_preset || 'yesterday'}`;
    }

    const insightsUrl = `${META_BASE_URL}/${account_id}/insights`
      + `?fields=ad_id,ad_name,spend,impressions,clicks,cpm,frequency,outbound_clicks,actions,campaign_name,campaign_id,adset_name,adset_id,video_thruplay_watched_actions,video_avg_time_watched_actions`
      + dateParams
      + `&level=ad`
      + `&sort=spend_descending`
      + `&limit=${adsLimit}`
      + (after ? `&after=${encodeURIComponent(after)}` : '')
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
    const nextCursor = insightsData.paging?.cursors?.after || null;
    const hasMore = !!insightsData.paging?.next;

    if (ads.length === 0) {
      return res.json({ ads: [], next_cursor: null, has_more: false });
    }

    // Helper: extract numeric value from Meta action-type arrays
    const actionVal = (arr, type) => {
      if (!Array.isArray(arr)) return null;
      const found = arr.find(a => a.action_type === type);
      return found ? (parseFloat(found.value) || 0) : null;
    };

    // Lite mode: skip creative/image fetching, just return insights + parsed ad name
    if (req.query.lite === '1') {
      const liteAds = ads.map(ad => {
        const parsed = parseAdName(ad.ad_name || '');
        return {
          ad_id: ad.ad_id,
          ad_name: ad.ad_name,
          ad_name_parsed: parsed,
          campaign_id: ad.campaign_id || null,
          campaign_name: ad.campaign_name || null,
          adset_id: ad.adset_id || null,
          adset_name: ad.adset_name || null,
          spend: ad.spend,
          impressions: ad.impressions,
          clicks: ad.clicks,
          cpm: ad.cpm ? parseFloat(ad.cpm) : null,
          frequency: ad.frequency ? parseFloat(ad.frequency) : null,
          outbound_clicks: actionVal(ad.outbound_clicks, 'outbound_click'),
          landing_page_views: actionVal(ad.actions, 'landing_page_view'),
          thruplays: actionVal(ad.video_thruplay_watched_actions, 'video_thruplay_watched'),
          avg_watch_time: actionVal(ad.video_avg_time_watched_actions, 'video_view'),
          destination_url: parsed.landing_page_url || null,
          is_partnership_ad: parsed.is_partnership,
        };
      });
      liteAds.sort((a, b) => parseFloat(b.spend || 0) - parseFloat(a.spend || 0));
      return res.json({ ads: liteAds, next_cursor: hasMore ? nextCursor : null, has_more: hasMore });
    }

    // Step 2: Build a page token map (for reading page posts)
    const pageTokenMap = {};
    try {
      const pagesUrl = `${META_BASE_URL}/me/accounts`
        + `?fields=id,access_token&limit=100`
        + `&${metaParams(req.accessToken)}`;
      const pagesResponse = await fetch(pagesUrl);
      const pagesData = await pagesResponse.json();
      if (pagesData.data) {
        pagesData.data.forEach(p => { pageTokenMap[p.id] = p.access_token; });
      }
    } catch (e) {
      console.error('Failed to fetch page tokens:', e);
    }

    // Helper: fetch with a timeout to prevent individual calls from hanging
    const fetchWithTimeout = (url, timeoutMs = 8000) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      return fetch(url, { signal: controller.signal }).finally(() => clearTimeout(timer));
    };

    // Step 3: Batch-fetch all ad creatives in one Meta Batch API call
    // This replaces N individual requests with 1 batch request
    const batchRequests = ads.map(ad => ({
      method: 'GET',
      relative_url: `${ad.ad_id}?fields=creative{id,name,thumbnail_url,image_url,object_story_spec,asset_feed_spec,link_url,effective_object_story_id,url_tags,call_to_action}`,
    }));

    let batchResults = [];
    try {
      const batchBody = new URLSearchParams({
        access_token: req.accessToken,
        appsecret_proof: generateAppSecretProof(req.accessToken),
        batch: JSON.stringify(batchRequests),
      });
      const batchFetchResp = await fetch(`${META_BASE_URL}/`, {
        method: 'POST',
        body: batchBody,
        signal: AbortSignal.timeout(20000),
      });
      batchResults = await batchFetchResp.json();
    } catch (e) {
      console.error('Batch creative fetch failed, falling back to individual:', e.message);
      batchResults = null;
    }

    // Parse batch results into a map of ad_id -> creative data
    const creativeMap = {};
    if (Array.isArray(batchResults)) {
      for (let i = 0; i < ads.length; i++) {
        const result = batchResults[i];
        if (result && result.code === 200) {
          try {
            creativeMap[ads[i].ad_id] = JSON.parse(result.body);
          } catch {}
        }
      }
    }

    // If batch failed entirely, fall back to individual parallel fetches
    if (!Array.isArray(batchResults)) {
      await Promise.all(ads.map(async (ad) => {
        try {
          const creativeUrl = `${META_BASE_URL}/${ad.ad_id}`
            + `?fields=creative{id,name,thumbnail_url,image_url,object_story_spec,asset_feed_spec,link_url,effective_object_story_id,url_tags,call_to_action}`
            + `&${metaParams(req.accessToken)}`;
          const resp = await fetchWithTimeout(creativeUrl, 8000);
          creativeMap[ad.ad_id] = await resp.json();
        } catch (e) {}
      }));
    }

    // Step 4: For ads missing URL from creative, batch-fetch direct creative fields
    // Collect creative IDs that need a direct fetch
    const needsDirectFetch = [];
    const firstPassResults = {};

    for (const ad of ads) {
      const creativeData = creativeMap[ad.ad_id] || {};
      const creative = creativeData.creative || {};
      const storySpec = creative.object_story_spec || {};
      const assetFeed = creative.asset_feed_spec || {};

      let url = extractDestinationUrl(storySpec)
        || extractAssetFeedUrl(assetFeed)
        || creative.link_url
        || creative.call_to_action?.value?.link
        || extractUrlTagsUrl(creative.url_tags)
        || null;

      // Check ad name slug
      let adNameUrl = null;
      if (ad.ad_name) {
        const urlSlugMatch = ad.ad_name.match(/(?:^|[_:-])url[:_]([a-zA-Z0-9-]+)/i);
        if (urlSlugMatch) {
          const slug = urlSlugMatch[1];
          adNameUrl = slug.toUpperCase() === 'HOMEPAGE'
            ? 'https://firstday.com/'
            : `https://firstday.com/pages/${slug}`;
        }
      }

      firstPassResults[ad.ad_id] = { creative, storySpec, assetFeed, url, adNameUrl };

      if (!url && !adNameUrl && creative.id) {
        needsDirectFetch.push({ ad_id: ad.ad_id, creative_id: creative.id });
      }
    }

    // Batch-fetch direct creative data for ads that need it
    const directCreativeMap = {};
    if (needsDirectFetch.length > 0) {
      const directBatchRequests = needsDirectFetch.map(item => ({
        method: 'GET',
        relative_url: `${item.creative_id}?fields=link_url,object_url,object_story_spec,call_to_action`,
      }));
      try {
        const directBatchBody = new URLSearchParams({
          access_token: req.accessToken,
          appsecret_proof: generateAppSecretProof(req.accessToken),
          batch: JSON.stringify(directBatchRequests),
        });
        const directBatchResp = await fetch(`${META_BASE_URL}/`, {
          method: 'POST',
          body: directBatchBody,
          signal: AbortSignal.timeout(15000),
        });
        const directBatchResults = await directBatchResp.json();
        if (Array.isArray(directBatchResults)) {
          for (let i = 0; i < needsDirectFetch.length; i++) {
            const result = directBatchResults[i];
            if (result && result.code === 200) {
              try {
                directCreativeMap[needsDirectFetch[i].ad_id] = JSON.parse(result.body);
              } catch {}
            }
          }
        }
      } catch (e) {
        console.error('Direct creative batch failed:', e.message);
      }
    }

    // Step 5: Build final results — only do expensive fallbacks (attachments) for ads still missing URLs
    const adsWithCreatives = await Promise.all(
      ads.map(async (ad) => {
        try {
          const { creative, storySpec, assetFeed, url: firstPassUrl, adNameUrl } = firstPassResults[ad.ad_id];

          let destinationUrl = null;
          let urlSource = null;
          const tryUrl = (src, url) => { if (!destinationUrl && url) { destinationUrl = url; urlSource = src; } };

          tryUrl('storySpec', extractDestinationUrl(storySpec));
          tryUrl('assetFeed', extractAssetFeedUrl(assetFeed));
          tryUrl('creative.link_url', creative.link_url || null);
          tryUrl('creative.call_to_action', creative.call_to_action?.value?.link || null);
          tryUrl('url_tags', extractUrlTagsUrl(creative.url_tags));

          // Apply direct creative data if we fetched it
          const directCreativeData = directCreativeMap[ad.ad_id];
          if (!destinationUrl && directCreativeData && !directCreativeData.error) {
            tryUrl('direct.link_url', directCreativeData.link_url || null);
            tryUrl('direct.object_url', directCreativeData.object_url || null);
            tryUrl('direct.storySpec', extractDestinationUrl(directCreativeData.object_story_spec || {}));
            tryUrl('direct.call_to_action', directCreativeData.call_to_action?.value?.link || null);
          }

          // Extract destination from ad name URL slug — always override for partnership ads
          if (ad.ad_name) {
            const urlSlugMatch = ad.ad_name.match(/(?:^|[_:-])url[:_]([a-zA-Z0-9-]+)/i);
            if (urlSlugMatch) {
              const slug = urlSlugMatch[1];
              const adNameUrlResolved = slug.toUpperCase() === 'HOMEPAGE'
                ? 'https://firstday.com/'
                : `https://firstday.com/pages/${slug}`;

              const nameLower = ad.ad_name.toLowerCase();
              const isPartnership = nameLower.includes('creator_wl:ext')
                || nameLower.includes('notes:ext-')
                || nameLower.includes('editor:ext-')
                || nameLower.includes(':ext-')
                || /\bext[-_]creator\b/.test(nameLower);

              if (isPartnership || !destinationUrl) {
                destinationUrl = adNameUrlResolved;
                urlSource = isPartnership ? 'adname-slug(partner)' : 'adname-slug';
              }
            }
          }

          // Fallback: Read the page post attachments (only for ads still missing URL)
          let attachmentFallbackUrl = null;
          if (!destinationUrl && creative.effective_object_story_id) {
            const pageId = creative.effective_object_story_id.split('_')[0];
            const pageToken = pageTokenMap[pageId];

            if (pageToken) {
              try {
                const attachUrl = `${META_BASE_URL}/${creative.effective_object_story_id}/attachments`
                  + `?fields=url,unshimmed_url,url_unshimmed,target,type,subattachments{url,unshimmed_url,url_unshimmed,target}`
                  + `&access_token=${encodeURIComponent(pageToken)}&appsecret_proof=${generateAppSecretProof(pageToken)}`;
                const attachResponse = await fetchWithTimeout(attachUrl, 6000);
                const attachData = await attachResponse.json();

                if (attachData.data?.[0]) {
                  const att = attachData.data[0];
                  let candidateUrl = att.unshimmed_url || att.url_unshimmed || att.url || att.target?.url || null;
                  if (!candidateUrl && att.subattachments?.data?.[0]) {
                    const sub = att.subattachments.data[0];
                    candidateUrl = sub.unshimmed_url || sub.url_unshimmed || sub.url || sub.target?.url || null;
                  }
                  if (candidateUrl) {
                    if (!candidateUrl.includes('facebook.com/') && !candidateUrl.includes('fb.com/')) {
                      destinationUrl = candidateUrl;
                      urlSource = 'attachment';
                    } else {
                      attachmentFallbackUrl = candidateUrl;
                    }
                  }
                }
              } catch (e) {}
            }
          }

          // Fallback: Extract CTA URL from ad preview (only one format, with timeout)
          if (!destinationUrl) {
            try {
              const previewUrl = `${META_BASE_URL}/${ad.ad_id}/previews`
                + `?ad_format=DESKTOP_FEED_STANDARD`
                + `&${metaParams(req.accessToken)}`;
              const previewResponse = await fetchWithTimeout(previewUrl, 5000);
              const previewData = await previewResponse.json();

              if (previewData.data?.[0]?.body) {
                const body = previewData.data[0].body.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

                const allHrefs = body.match(/href="(https?:\/\/[^"]+)"/g) || [];
                const externalHrefs = allHrefs
                  .map(m => m.match(/href="([^"]+)"/)[1])
                  .map(u => { try { return decodeURIComponent(u); } catch { return u; } })
                  .filter(u => !u.includes('facebook.com') && !u.includes('fbcdn.net') && !u.includes('fb.com') && !u.includes('fbsbx.com'));

                if (externalHrefs[0]) {
                  destinationUrl = externalHrefs[0];
                  urlSource = 'preview-href';
                }
              }
            } catch (e) {}
          }

          // Last resort: facebook.com attachment URL
          if (!destinationUrl && attachmentFallbackUrl) {
            destinationUrl = attachmentFallbackUrl;
            urlSource = 'attachment-fb';
          }

          // Get image from already-fetched creative data (no extra API call)
          let imageUrl = null;
          if (creative.image_url && !creative.image_url.includes('p64x64')) {
            imageUrl = creative.image_url;
          } else if (creative.thumbnail_url && !creative.thumbnail_url.includes('p64x64')) {
            imageUrl = creative.thumbnail_url;
          }
          if (!imageUrl) {
            imageUrl = storySpec?.link_data?.picture
              || storySpec?.video_data?.image_url
              || creative.thumbnail_url
              || null;
          }

          const isVideo = !!storySpec.video_data;

          // Build preview URL for viewing the creative
          const storyId = creative.effective_object_story_id;
          let previewUrl = null;
          if (storyId) {
            const [pageId, postId] = storyId.split('_');
            previewUrl = `https://www.facebook.com/${pageId}/posts/${postId}`;
          }

          // Detect partnership/branded content ads
          // Check object_story_spec fields
          let isPartnershipAd = !!(
            storySpec.link_data?.branded_content_sponsor_page_id
            || storySpec.video_data?.branded_content_sponsor_page_id
            || storySpec.photo_data?.branded_content_sponsor_page_id
          );

          // Also check ad name conventions for partnership indicators
          if (!isPartnershipAd && ad.ad_name) {
            const nameLower = ad.ad_name.toLowerCase();
            isPartnershipAd = nameLower.includes('creator_wl:ext')
              || nameLower.includes('notes:ext-')
              || nameLower.includes('editor:ext-')
              || nameLower.includes(':ext-')
              || /\bext[-_]creator\b/.test(nameLower);
          }

          // Log raw data for ads missing destination URL
          if (!destinationUrl) {
            console.log(`\n=== Missing destination URL for ad ${ad.ad_id} ===`);
            console.log('creative keys:', Object.keys(creative));
            console.log('object_story_spec:', JSON.stringify(storySpec, null, 2));
            if (creative.id) {
              console.log('creative id:', creative.id);
            }
          }

          return {
            ad_id: ad.ad_id,
            ad_name: ad.ad_name,
            campaign_id: ad.campaign_id || null,
            campaign_name: ad.campaign_name || null,
            adset_id: ad.adset_id || null,
            adset_name: ad.adset_name || null,
            spend: ad.spend,
            impressions: ad.impressions,
            clicks: ad.clicks,
            cpm: ad.cpm ? parseFloat(ad.cpm) : null,
            frequency: ad.frequency ? parseFloat(ad.frequency) : null,
            outbound_clicks: actionVal(ad.outbound_clicks, 'outbound_click'),
            landing_page_views: actionVal(ad.actions, 'landing_page_view'),
            thruplays: actionVal(ad.video_thruplay_watched_actions, 'video_thruplay_watched'),
            avg_watch_time: actionVal(ad.video_avg_time_watched_actions, 'video_view'),
            destination_url: destinationUrl,
            url_source: urlSource,
            image_url: imageUrl,
            thumbnail_url: creative.thumbnail_url || null,
            preview_url: previewUrl,
            is_video: isVideo,
            is_partnership_ad: isPartnershipAd
          };
        } catch (creativeErr) {
          console.error(`Failed to fetch creative for ad ${ad.ad_id}:`, creativeErr);
          return {
            ad_id: ad.ad_id,
            ad_name: ad.ad_name,
            campaign_id: ad.campaign_id || null,
            campaign_name: ad.campaign_name || null,
            adset_id: ad.adset_id || null,
            adset_name: ad.adset_name || null,
            spend: ad.spend,
            impressions: ad.impressions,
            clicks: ad.clicks,
            cpm: ad.cpm ? parseFloat(ad.cpm) : null,
            frequency: ad.frequency ? parseFloat(ad.frequency) : null,
            outbound_clicks: actionVal(ad.outbound_clicks, 'outbound_click'),
            landing_page_views: actionVal(ad.actions, 'landing_page_view'),
            thruplays: actionVal(ad.video_thruplay_watched_actions, 'video_thruplay_watched'),
            avg_watch_time: actionVal(ad.video_avg_time_watched_actions, 'video_view'),
            destination_url: null,
            url_source: null,
            image_url: null,
            thumbnail_url: null,
            preview_url: null,
            is_video: false,
            is_partnership_ad: false
          };
        }
      })
    );

    // Sort by spend descending
    adsWithCreatives.sort((a, b) => parseFloat(b.spend || 0) - parseFloat(a.spend || 0));

    res.json({ ads: adsWithCreatives, next_cursor: hasMore ? nextCursor : null, has_more: hasMore });
  } catch (err) {
    console.error('Failed to fetch top ads:', err);
    res.status(500).json({ error: 'Failed to fetch top ads' });
  }
});

// --- Test permissions endpoint ---

app.get('/api/test-permissions', requireAuth, async (req, res) => {
  try {
    // Test 1: Check what permissions the token actually has
    const permsUrl = `${META_BASE_URL}/me/permissions`
      + `?${metaParams(req.accessToken)}`;
    const permsResponse = await fetch(permsUrl);
    const permsData = await permsResponse.json();

    // Test 2: List pages via personal account
    const pagesUrl = `${META_BASE_URL}/me/accounts`
      + `?fields=id,name,access_token`
      + `&${metaParams(req.accessToken)}`;
    const pagesResponse = await fetch(pagesUrl);
    const pagesData = await pagesResponse.json();

    // Test 3: List businesses the user belongs to
    const bizUrl = `${META_BASE_URL}/me/businesses`
      + `?fields=id,name`
      + `&${metaParams(req.accessToken)}`;
    const bizResponse = await fetch(bizUrl);
    const bizData = await bizResponse.json();

    // Test 4: If we have a business, get its pages
    let bizPages = null;
    let pageToken = null;
    let postTest = null;

    if (bizData.data?.[0]) {
      const bizId = bizData.data[0].id;

      // Try owned_pages
      const bizPagesUrl = `${META_BASE_URL}/${bizId}/owned_pages`
        + `?fields=id,name,access_token`
        + `&${metaParams(req.accessToken)}`;
      const bizPagesResponse = await fetch(bizPagesUrl);
      bizPages = await bizPagesResponse.json();

      // Try to find page 375215066258824 (the ad's page) and read a post
      const targetPage = bizPages.data?.find(p => p.id === '375215066258824') || bizPages.data?.[0];
      if (targetPage?.access_token) {
        pageToken = targetPage.access_token;

        // Use the attachments EDGE (separate call, not a field on the post)
        const attachUrl = `${META_BASE_URL}/375215066258824_1403167991809848/attachments`
          + `?fields=url,unshimmed_url,target,title,type,subattachments`
          + `&access_token=${encodeURIComponent(pageToken)}&appsecret_proof=${generateAppSecretProof(pageToken)}`;
        const attachResponse = await fetch(attachUrl);
        postTest = await attachResponse.json();
      }
    }

    // Test 5: Also try direct page token request for the known page
    let directPageTest = null;
    try {
      const directUrl = `${META_BASE_URL}/375215066258824`
        + `?fields=id,name,access_token`
        + `&${metaParams(req.accessToken)}`;
      const directResponse = await fetch(directUrl);
      directPageTest = await directResponse.json();
    } catch (e) {}

    res.json({ permissions: permsData, personalPages: pagesData, businesses: bizData, bizPages, postTest, directPageTest });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Debug endpoint ---
// Usage: GET /api/debug-ad?ad_id=<id>
// Returns every raw API payload + a resolved chain showing which step found the URL.

app.get('/api/debug-ad', requireAuth, async (req, res) => {
  const { ad_id } = req.query;
  if (!ad_id) return res.status(400).json({ error: 'ad_id required' });

  const chain = []; // tracks which step resolved (or missed) the URL
  const log = (step, url) => chain.push({ step, resolved: url || null });

  try {
    // Step 1: Ad → creative (same fields as /api/top-ads)
    const adUrl = `${META_BASE_URL}/${ad_id}`
      + `?fields=name,creative{id,name,thumbnail_url,image_url,object_story_spec,asset_feed_spec,link_url,effective_object_story_id,url_tags,call_to_action}`
      + `&${metaParams(req.accessToken)}`;
    const adData = await (await fetch(adUrl)).json();

    const adName = adData.name || null;
    const creative = adData.creative || {};
    const storySpec = creative.object_story_spec || {};
    const assetFeed = creative.asset_feed_spec || {};

    log('1a. storySpec link_data / video_data / photo_data', extractDestinationUrl(storySpec));
    log('1b. asset_feed_spec link_urls', extractAssetFeedUrl(assetFeed));
    log('1c. creative.link_url', creative.link_url || null);
    log('1d. creative.call_to_action?.value?.link', creative.call_to_action?.value?.link || null);
    log('1e. url_tags parsed URL', extractUrlTagsUrl(creative.url_tags));

    // Step 2: Direct creative fetch (same fields as /api/top-ads)
    let creativeDirectData = null;
    if (creative.id) {
      const directUrl = `${META_BASE_URL}/${creative.id}`
        + `?fields=link_url,object_url,object_story_spec,call_to_action`
        + `&${metaParams(req.accessToken)}`;
      creativeDirectData = await (await fetch(directUrl)).json();
      log('2a. direct creative link_url', creativeDirectData.link_url || null);
      log('2b. direct creative object_url', creativeDirectData.object_url || null);
      log('2c. direct creative storySpec', extractDestinationUrl(creativeDirectData.object_story_spec || {}));
      log('2d. direct creative call_to_action', creativeDirectData.call_to_action?.value?.link || null);
    }

    // Step 3: Ad name url: slug
    let adNameUrl = null;
    if (adName) {
      const urlSlugMatch = adName.match(/(?:^|[_:-])url[:_]([a-zA-Z0-9-]+)/i);
      if (urlSlugMatch) {
        const slug = urlSlugMatch[1];
        adNameUrl = slug.toUpperCase() === 'HOMEPAGE'
          ? 'https://firstday.com/'
          : `https://firstday.com/pages/${slug}`;
      }
    }
    log('3. ad name url: slug', adNameUrl);

    // Step 4: Attachment fetch
    let attachmentData = null;
    let attachmentUrl = null;
    const storyId = creative.effective_object_story_id;
    if (storyId) {
      const pagesUrl = `${META_BASE_URL}/me/accounts?fields=id,access_token&limit=100&${metaParams(req.accessToken)}`;
      const pagesData = await (await fetch(pagesUrl)).json();
      const pageId = storyId.split('_')[0];
      const pageToken = pagesData.data?.find(p => p.id === pageId)?.access_token;

      if (pageToken) {
        const attachUrl = `${META_BASE_URL}/${storyId}/attachments`
          + `?fields=url,unshimmed_url,url_unshimmed,target,type,subattachments{url,unshimmed_url,url_unshimmed,target}`
          + `&access_token=${encodeURIComponent(pageToken)}&appsecret_proof=${generateAppSecretProof(pageToken)}`;
        attachmentData = await (await fetch(attachUrl)).json();

        const att = attachmentData.data?.[0];
        if (att) {
          attachmentUrl = att.unshimmed_url || att.url_unshimmed || att.url || att.target?.url || null;
          if (!attachmentUrl && att.subattachments?.data?.[0]) {
            const sub = att.subattachments.data[0];
            attachmentUrl = sub.unshimmed_url || sub.url_unshimmed || sub.url || sub.target?.url || null;
          }
        }
      }
    }
    log('4. attachment url (unshimmed_url / url_unshimmed / url)', attachmentUrl);

    // Step 5: Preview HTML scraping (same logic as /api/top-ads)
    let previewExtractedUrl = null;
    let previewRaw = null;
    if (!chain.find(s => s.resolved)) {
      const formats = ['DESKTOP_FEED_STANDARD', 'MOBILE_FEED_STANDARD'];
      for (const format of formats) {
        if (previewExtractedUrl) break;
        try {
          const previewApiUrl = `${META_BASE_URL}/${ad_id}/previews`
            + `?ad_format=${format}`
            + `&${metaParams(req.accessToken)}`;
          const previewResp = await fetch(previewApiUrl);
          previewRaw = await previewResp.json();

          if (previewRaw.data?.[0]?.body) {
            const body = previewRaw.data[0].body.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

            // Direct external hrefs in preview HTML
            const allHrefs = body.match(/href="(https?:\/\/[^"]+)"/g) || [];
            const externalHrefs = allHrefs
              .map(m => m.match(/href="([^"]+)"/)[1])
              .map(u => { try { return decodeURIComponent(u); } catch { return u; } })
              .filter(u => !u.includes('facebook.com') && !u.includes('fbcdn.net') && !u.includes('fb.com') && !u.includes('fbsbx.com'));

            if (externalHrefs[0]) {
              previewExtractedUrl = externalHrefs[0];
              break;
            }

            // Iframe scrape
            const iframeSrcMatch = body.match(/src="(https?:\/\/[^"]+)"/);
            if (iframeSrcMatch) {
              const iframeUrl = iframeSrcMatch[1];
              try {
                const iframeResp = await fetch(iframeUrl);
                const iframeHtml = await iframeResp.text();

                const redirectMatches = iframeHtml.match(/l\.facebook\.com\/l\.php\?u=([^&"]+)/g) || [];
                const redirectUrls = redirectMatches
                  .map(m => { try { return decodeURIComponent(m.split('u=')[1]); } catch { return null; } })
                  .filter(Boolean);

                if (redirectUrls[0]) {
                  previewExtractedUrl = redirectUrls[0];
                } else {
                  const iframeHrefs = (iframeHtml.match(/href="(https?:\/\/[^"]+)"/g) || [])
                    .map(m => m.match(/href="([^"]+)"/)[1])
                    .map(u => { try { return decodeURIComponent(u); } catch { return u; } })
                    .filter(u => !u.includes('facebook.com') && !u.includes('fbcdn.net') && !u.includes('fb.com'));
                  previewExtractedUrl = iframeHrefs[0] || null;
                }
              } catch (e) {}
            }
          }
        } catch (e) {}
      }
    }
    log('5. preview HTML scrape', previewExtractedUrl);

    // Summarise: first non-null step wins (partnership ads prefer step 3 over 1/2)
    const nameLower = (adName || '').toLowerCase();
    const isPartnership = nameLower.includes(':ext-') || nameLower.includes('creator_wl:ext') || /\bext[-_]creator\b/.test(nameLower);
    const firstResolved = chain.find(s => s.resolved)?.resolved || null;
    const finalUrl = isPartnership && adNameUrl ? adNameUrl : (adNameUrl || firstResolved);

    res.json({
      ad_id,
      ad_name: adName,
      is_partnership: isPartnership,
      effective_object_story_id: storyId || null,
      url_tags: creative.url_tags || null,
      call_to_action: creative.call_to_action || null,
      resolution_chain: chain,
      final_url: finalUrl,
      raw: { adData, creativeDirectData, attachmentData, previewRaw }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Shopify Metrics endpoint ---

app.get('/api/shopify-metrics', requireAuth, async (req, res) => {
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }

  const { days = '1', ads } = req.query;
  const numDays = Math.min(Math.max(parseInt(days) || 1, 1), 90);

  let adList = [];
  try {
    if (ads) adList = JSON.parse(ads);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid ads JSON' });
  }

  if (!adList.length) {
    return res.json({ by_ad: {}, days: numDays });
  }

  const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const gqlQuery = `query RunShopifyQL($q: String!) {
    shopifyqlQuery(query: $q) {
      tableData { columns { name } rows }
      parseErrors
    }
  }`;

  try {
    const results = {};

    // Helper: run a ShopifyQL query and aggregate rows into a metrics object
    async function runShopifyQL(shopifyql) {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
        body: JSON.stringify({ query: gqlQuery, variables: { q: shopifyql } }),
      });
      const json = await response.json();
      const payload = json.data?.shopifyqlQuery;
      if (!payload?.tableData) return null;

      const columns = payload.tableData.columns?.map(c => c.name) || [];
      const rows = payload.tableData.rows || [];
      if (!rows.length) return null;

      // Rows may be objects (keyed by column name) or arrays (ordered by columns)
      const getVal = (row, name) => {
        if (Array.isArray(row)) {
          const idx = columns.indexOf(name);
          return idx >= 0 ? row[idx] : undefined;
        }
        return row[name];
      };

      let totalSessions = 0, totalOrders = 0;
      let bounceSumW = 0, atcSumW = 0, checkoutSumW = 0, completedSumW = 0, cvrSumW = 0;
      let topPath = '';

      for (const row of rows) {
        const s = parseFloat(getVal(row, 'sessions')) || 0;
        totalSessions += s;
        totalOrders += parseFloat(getVal(row, 'sessions_that_completed_checkout')) || 0;
        bounceSumW += (parseFloat(getVal(row, 'bounce_rate')) || 0) * s;
        atcSumW += (parseFloat(getVal(row, 'added_to_cart_rate')) || 0) * s;
        checkoutSumW += (parseFloat(getVal(row, 'reached_checkout_rate')) || 0) * s;
        completedSumW += (parseFloat(getVal(row, 'completed_checkout_rate')) || 0) * s;
        cvrSumW += (parseFloat(getVal(row, 'conversion_rate')) || 0) * s;
        if (!topPath) topPath = getVal(row, 'landing_page_path') || '';
      }

      if (totalSessions === 0) return null;

      return {
        landing_page_path: topPath,
        sessions: totalSessions,
        sessions_that_completed_checkout: totalOrders,
        bounce_rate: +(bounceSumW / totalSessions).toFixed(4),
        added_to_cart_rate: +(atcSumW / totalSessions).toFixed(4),
        reached_checkout_rate: +(checkoutSumW / totalSessions).toFixed(4),
        completed_checkout_rate: +(completedSumW / totalSessions).toFixed(4),
        conversion_rate: +(cvrSumW / totalSessions).toFixed(4),
      };
    }

    const LP_EXCLUDES = `AND landing_page_path NOT CONTAINS 'checkout'
            AND landing_page_path NOT CONTAINS 'retextion'
            AND landing_page_path NOT CONTAINS 'account'
            AND landing_page_path NOT CONTAINS 'order'`;

    await Promise.all(adList.map(async (ad) => {
      const adName = ad.ad_name || '';
      if (!adName) return;

      try {
        // Primary: exact utm_content match (ad name)
        const escapedName = adName.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        let metrics = await runShopifyQL(`
          FROM sessions
            SHOW sessions, conversion_rate, bounce_rate, added_to_cart_rate,
              reached_checkout_rate, completed_checkout_rate, sessions_that_completed_checkout
            WHERE utm_source CONTAINS 'facebook'
              AND utm_content = '${escapedName}'
              ${LP_EXCLUDES}
            GROUP BY landing_page_path
            SINCE startOfDay(-${numDays}d) UNTIL endOfDay(-1d)
            ORDER BY sessions DESC
        `);

        let matchSource = 'utm_content';

        // Fallback: match by landing_page_path derived from destination_url
        if (!metrics && ad.destination_url) {
          try {
            const lpPath = new URL(ad.destination_url).pathname;
            if (lpPath && lpPath !== '/') {
              const escapedPath = lpPath.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
              metrics = await runShopifyQL(`
                FROM sessions
                  SHOW sessions, conversion_rate, bounce_rate, added_to_cart_rate,
                    reached_checkout_rate, completed_checkout_rate, sessions_that_completed_checkout
                  WHERE utm_source CONTAINS 'facebook'
                    AND landing_page_path = '${escapedPath}'
                    ${LP_EXCLUDES}
                  GROUP BY landing_page_path
                  SINCE startOfDay(-${numDays}d) UNTIL endOfDay(-1d)
                  ORDER BY sessions DESC
              `);
              if (metrics) matchSource = 'landing_page';
            }
          } catch {}
        }

        if (metrics) {
          results[adName] = { ad_name: adName, match_source: matchSource, ...metrics };
        }
      } catch (e) {
        console.error(`Shopify query failed for ad "${adName}":`, e.message);
      }
    }));

    res.json({ by_ad: results, days: numDays });
  } catch (err) {
    console.error('Shopify metrics error:', err);
    res.status(500).json({ error: 'Failed to fetch Shopify metrics' });
  }
});

// --- Conversion Impact (ShopifyQL period comparison) ---

app.get('/api/conversion-impact-data', async (req, res) => {
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }

  const { start, end } = req.query;
  if (!start || !end || !/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
    return res.status(400).json({ error: 'start and end query params required (YYYY-MM-DD)' });
  }

  const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const gqlQuery = `query RunShopifyQL($q: String!) {
    shopifyqlQuery(query: $q) {
      tableData { columns { name dataType } rows }
      parseErrors
    }
  }`;

  // Main summary: all utm_sources with full funnel metrics, selected range vs previous period
  const mainQuery = `FROM sessions
  SHOW sessions, conversion_rate, average_session_duration, sessions_with_cart_additions, sessions_that_reached_checkout, sessions_that_reached_and_completed_checkout
  GROUP BY utm_source WITH TOTALS, PERCENT_CHANGE
  SINCE ${start} UNTIL ${end}
  COMPARE TO previous_period
  ORDER BY sessions DESC
VISUALIZE conversion_rate TYPE table`;

  // Correlation dataset: session duration vs conversion rate, grouped by source + LP
  const correlationQuery = `FROM sessions
  SHOW sessions, conversion_rate, average_session_duration
  GROUP BY utm_source, landing_page_path
  SINCE ${start} UNTIL ${end}
  ORDER BY sessions DESC`;

  console.log('\n[conversion-impact-data] Main query:\n' + mainQuery);
  console.log('\n[conversion-impact-data] Correlation query:\n' + correlationQuery);

  const runQuery = async (q) => {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q } }),
    });
    const json = await resp.json();
    const payload = json.data?.shopifyqlQuery;
    if (payload?.parseErrors?.length) {
      const err = new Error('ShopifyQL parse error: ' + JSON.stringify(payload.parseErrors));
      err.details = payload.parseErrors;
      throw err;
    }
    if (!payload?.tableData) throw new Error('No data returned from Shopify');
    return payload.tableData;
  };

  try {
    const [main, correlation] = await Promise.all([
      runQuery(mainQuery),
      runQuery(correlationQuery),
    ]);

    res.json({
      query: mainQuery,
      columns: main.columns,
      rows: main.rows,
      correlation: {
        query: correlationQuery,
        columns: correlation.columns,
        rows: correlation.rows,
      },
    });
  } catch (err) {
    console.error('Conversion impact data error:', err);
    res.status(500).json({ error: err.message, details: err.details });
  }
});

// --- Meta Paid Social CVR Impact (by campaign + LP, filtered utm_source/medium) ---

app.get('/api/meta-cvr-impact-data', async (req, res) => {
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }

  const { start, end } = req.query;
  if (!start || !end || !/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
    return res.status(400).json({ error: 'start and end query params required (YYYY-MM-DD)' });
  }

  const escapeQL = (v) => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const source = escapeQL(req.query.source || 'facebook');
  const medium = escapeQL(req.query.medium || 'paid_social');

  // Optional custom comparison range. When both compare_start + compare_end
  // are valid YYYY-MM-DD, we run a second ShopifyQL query for that window
  // and merge it into the main response under synthetic
  // `comparison_<metric>__previous_period[_totals]` columns — same shape the
  // built-in `COMPARE TO previous_period` produces, so the frontend parser
  // works unchanged.
  const cs = req.query.compare_start;
  const ce = req.query.compare_end;
  const useCustomCompare = cs && ce
    && /^\d{4}-\d{2}-\d{2}$/.test(cs) && /^\d{4}-\d{2}-\d{2}$/.test(ce);

  const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const gqlQuery = `query RunShopifyQL($q: String!) {
    shopifyqlQuery(query: $q) {
      tableData { columns { name dataType } rows }
      parseErrors
    }
  }`;

  // When a custom compare window is supplied, drop COMPARE TO from the main
  // query (we'll merge the comparison data in code below). We keep WITH TOTALS
  // so the totals row still appears.
  const mainQuery = useCustomCompare
    ? `FROM sessions
  SHOW sessions, conversion_rate, average_session_duration, sessions_with_cart_additions, sessions_that_reached_checkout, sessions_that_reached_and_completed_checkout
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_campaign, landing_page_path WITH TOTALS
  SINCE ${start} UNTIL ${end}
  ORDER BY sessions DESC
VISUALIZE conversion_rate TYPE table`
    : `FROM sessions
  SHOW sessions, conversion_rate, average_session_duration, sessions_with_cart_additions, sessions_that_reached_checkout, sessions_that_reached_and_completed_checkout
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_campaign, landing_page_path WITH TOTALS, PERCENT_CHANGE
  SINCE ${start} UNTIL ${end}
  COMPARE TO previous_period
  ORDER BY sessions DESC
VISUALIZE conversion_rate TYPE table`;

  const compareQuery = useCustomCompare ? `FROM sessions
  SHOW sessions, conversion_rate, average_session_duration, sessions_with_cart_additions, sessions_that_reached_checkout, sessions_that_reached_and_completed_checkout
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_campaign, landing_page_path WITH TOTALS
  SINCE ${cs} UNTIL ${ce}
  ORDER BY sessions DESC` : null;

  console.log('\n[meta-cvr-impact-data] Main query:\n' + mainQuery);
  if (compareQuery) console.log('\n[meta-cvr-impact-data] Compare query:\n' + compareQuery);

  const runShopifyQL = async (q) => {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q } }),
    });
    const json = await resp.json();
    const payload = json.data?.shopifyqlQuery;
    if (payload?.parseErrors?.length) {
      const err = new Error('ShopifyQL parse error: ' + JSON.stringify(payload.parseErrors));
      err.parseErrors = payload.parseErrors;
      throw err;
    }
    if (!payload?.tableData) throw new Error('No data returned from Shopify');
    return payload.tableData;
  };

  try {
    const [main, compare] = await Promise.all([
      runShopifyQL(mainQuery),
      compareQuery ? runShopifyQL(compareQuery) : Promise.resolve(null),
    ]);

    // No custom compare → return main as-is (frontend already handles COMPARE
    // TO previous_period output).
    if (!compare) {
      return res.json({
        query: mainQuery,
        filter: { source, medium },
        columns: main.columns,
        rows: main.rows,
      });
    }

    // Merge the comparison query into the main response. We synthesize the
    // same column names ShopifyQL emits for COMPARE TO previous_period, so
    // the existing frontend parser picks them up without changes.
    const cols = main.columns.map(c => (c.name || '').toLowerCase());
    const cmpCols = compare.columns.map(c => (c.name || '').toLowerCase());

    const idx = (arr, n) => arr.findIndex(s => s === n);
    const iCampaign = idx(cols, 'utm_campaign');
    const iLp       = idx(cols, 'landing_page_path');
    const iSess     = idx(cols, 'sessions');
    const iCvr      = idx(cols, 'conversion_rate');
    const iSessTot  = idx(cols, 'sessions__totals');
    const iCvrTot   = idx(cols, 'conversion_rate__totals');

    const cmpICampaign = idx(cmpCols, 'utm_campaign');
    const cmpILp       = idx(cmpCols, 'landing_page_path');
    const cmpISess     = idx(cmpCols, 'sessions');
    const cmpICvr      = idx(cmpCols, 'conversion_rate');
    const cmpISessTot  = idx(cmpCols, 'sessions__totals');
    const cmpICvrTot   = idx(cmpCols, 'conversion_rate__totals');

    // Index comparison rows by (utm_campaign, landing_page_path)
    const cmpMap = new Map();
    let cmpTotals = null;
    for (const row of compare.rows) {
      const c = String(row[cmpICampaign] ?? '').trim();
      const l = String(row[cmpILp]       ?? '').trim();
      if (!c && !l) { cmpTotals = row; continue; }     // totals row
      cmpMap.set(c + '||' + l, row);
    }

    // Append two synthetic columns per metric we surface.
    const newColumns = [
      ...main.columns,
      { name: 'comparison_sessions__previous_period',        dataType: 'integer' },
      { name: 'comparison_conversion_rate__previous_period', dataType: 'percent' },
      { name: 'comparison_sessions__previous_period__totals',        dataType: 'integer' },
      { name: 'comparison_conversion_rate__previous_period__totals', dataType: 'percent' },
    ];

    const newRows = main.rows.map(row => {
      const c = String(row[iCampaign] ?? '').trim();
      const l = String(row[iLp]       ?? '').trim();
      const isTotalsRow = !c && !l;
      const cmpRow = isTotalsRow ? cmpTotals : cmpMap.get(c + '||' + l);
      const cmpSess = cmpRow != null ? cmpRow[cmpISess] : null;
      const cmpCvr  = cmpRow != null ? cmpRow[cmpICvr]  : null;
      const cmpSessTot = cmpTotals != null && cmpISessTot >= 0 ? cmpTotals[cmpISessTot] : (cmpRow != null && isTotalsRow ? cmpSess : null);
      const cmpCvrTot  = cmpTotals != null && cmpICvrTot  >= 0 ? cmpTotals[cmpICvrTot]  : (cmpRow != null && isTotalsRow ? cmpCvr  : null);
      return [...row, cmpSess, cmpCvr, cmpSessTot, cmpCvrTot];
    });

    res.json({
      query: mainQuery,
      compare_query: compareQuery,
      filter: { source, medium },
      compare_window: { start: cs, end: ce },
      columns: newColumns,
      rows: newRows,
    });
  } catch (err) {
    console.error('Meta CVR impact data error:', err);
    res.status(500).json({ error: err.message });
  }
});

// --- Top ad_name × landing_page_path combos (utm_content × landing_page_path) ---

app.get('/api/meta-ad-lp-data', async (req, res) => {
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }

  const { start, end } = req.query;
  if (!start || !end || !/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
    return res.status(400).json({ error: 'start and end query params required (YYYY-MM-DD)' });
  }

  const escapeQL = (v) => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const source = escapeQL(req.query.source || 'facebook');
  const medium = escapeQL(req.query.medium || 'paid_social');

  const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const gqlQuery = `query RunShopifyQL($q: String!) {
    shopifyqlQuery(query: $q) {
      tableData { columns { name dataType } rows }
      parseErrors
    }
  }`;

  const mainQuery = `FROM sessions
  SHOW sessions, conversion_rate
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_content, landing_page_path WITH PERCENT_CHANGE
  SINCE ${start} UNTIL ${end}
  COMPARE TO previous_period
  ORDER BY sessions DESC
VISUALIZE conversion_rate TYPE table`;

  console.log('\n[meta-ad-lp-data] Query:\n' + mainQuery);

  try {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q: mainQuery } }),
    });
    const json = await resp.json();
    const payload = json.data?.shopifyqlQuery;
    if (payload?.parseErrors?.length) {
      return res.status(500).json({ error: 'ShopifyQL parse error', details: payload.parseErrors });
    }
    if (!payload?.tableData) throw new Error('No data returned from Shopify');

    res.json({
      query: mainQuery,
      filter: { source, medium },
      columns: payload.tableData.columns,
      rows: payload.tableData.rows,
    });
  } catch (err) {
    console.error('Meta ad-lp data error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// DIAGNOSTIC DASHBOARD — bucketing-criteria persistence
// ─────────────────────────────────────────────
// Storage strategy:
//   1. If Vercel KV env vars are set (KV_REST_API_URL + KV_REST_API_TOKEN),
//      persist to KV — survives cold starts and is shared across all instances.
//   2. Otherwise persist to a JSON file (great for local dev). On Vercel
//      without KV, this falls through to /tmp which is ephemeral.
// Override the file path via DIAG_CRITERIA_FILE env var if needed.
const fsp = require('fs').promises;
const CRITERIA_FILE = process.env.DIAG_CRITERIA_FILE
  || (process.env.VERCEL ? '/tmp/diag-criteria.json' : path.join(__dirname, 'data', 'diag-criteria.json'));
const CRITERIA_KV_KEY = 'diag-criteria';

let kvClient = null;
if (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) {
  try {
    kvClient = require('@vercel/kv').kv;
    console.log('[diag-criteria] using Vercel KV for persistence');
  } catch (e) {
    console.warn('[diag-criteria] @vercel/kv import failed, falling back to file:', e.message);
  }
}
if (!kvClient) console.log('[diag-criteria] KV env vars not set, using file persistence:', CRITERIA_FILE);

const STORAGE_KIND = kvClient ? 'kv' : 'file';
const STORAGE_LABEL = kvClient ? 'Vercel KV' : CRITERIA_FILE;
const STORAGE_IS_EPHEMERAL = !kvClient && !!process.env.VERCEL && !process.env.DIAG_CRITERIA_FILE;

async function readStoredCriteria() {
  if (kvClient) {
    const v = await kvClient.get(CRITERIA_KV_KEY);
    return v && typeof v === 'object' ? v : null;
  }
  try {
    const raw = await fsp.readFile(CRITERIA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

async function writeStoredCriteria(data) {
  if (kvClient) {
    await kvClient.set(CRITERIA_KV_KEY, data);
    return { kind: 'kv', label: 'Vercel KV', size: JSON.stringify(data).length };
  }
  await fsp.mkdir(path.dirname(CRITERIA_FILE), { recursive: true });
  await fsp.writeFile(CRITERIA_FILE, JSON.stringify(data, null, 2), 'utf8');
  const stat = await fsp.stat(CRITERIA_FILE).catch(() => null);
  return { kind: 'file', label: CRITERIA_FILE, size: stat?.size || 0 };
}

const CRITERIA_DEFAULTS = {
  minimum_spend: 50,
  minimum_impressions: 1000,
  target_roas: 2.0,
  high_frequency: 3.0,
  ctr_decline_pct: -15,
  spend_increase: 50,
  cpa_increase: 25,
  discount_pct_new_mult: 0.5,
  qualifier_cvr_mult: 1.5,
  truth_check_lower: 0.5,
  truth_check_upper: 2.0,
  retargeting_patterns: 'rt,retarget,warm,visitors,view-content',
  strip_date_prefix: true,
};

// Coerce incoming values to the same types as the defaults so downstream code
// can rely on numbers being numbers and strings being strings.
function coerceCriteria(input) {
  const out = { ...CRITERIA_DEFAULTS };
  if (!input || typeof input !== 'object') return out;
  for (const k of Object.keys(CRITERIA_DEFAULTS)) {
    if (!(k in input)) continue;
    const def = CRITERIA_DEFAULTS[k];
    if (typeof def === 'boolean') {
      out[k] = (input[k] === true || input[k] === 'true');
    } else if (typeof def === 'string') {
      out[k] = String(input[k]).slice(0, 400);
    } else {
      const n = parseFloat(input[k]);
      if (Number.isFinite(n)) out[k] = n;
    }
  }
  return out;
}

app.get('/api/diag-criteria', async (req, res) => {
  try {
    const stored = await readStoredCriteria();
    if (stored) {
      console.log(`[diag-criteria GET] ${STORAGE_LABEL}`);
      return res.json({
        criteria: { ...CRITERIA_DEFAULTS, ...stored },
        updated_at: stored.updated_at || null,
        updated_by: stored.updated_by || null,
        source: STORAGE_KIND,
        file: STORAGE_LABEL,
        ephemeral: STORAGE_IS_EPHEMERAL,
      });
    }
    console.log(`[diag-criteria GET] no value at ${STORAGE_LABEL}, returning defaults`);
    res.json({
      criteria: { ...CRITERIA_DEFAULTS },
      updated_at: null, updated_by: null,
      source: 'defaults', file: STORAGE_LABEL,
      ephemeral: STORAGE_IS_EPHEMERAL,
    });
  } catch (err) {
    console.error('[diag-criteria GET] error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/diag-criteria', async (req, res) => {
  const cleaned = coerceCriteria(req.body);
  cleaned.updated_at = new Date().toISOString();
  if (req.body && typeof req.body.updated_by === 'string') {
    cleaned.updated_by = req.body.updated_by.slice(0, 120);
  }
  try {
    const result = await writeStoredCriteria(cleaned);
    console.log(`[diag-criteria POST] wrote to ${result.label} (${result.size} bytes)`);
    res.json({
      criteria: cleaned, saved: true,
      file: result.label, ephemeral: STORAGE_IS_EPHEMERAL,
    });
  } catch (err) {
    console.error('[diag-criteria POST] error:', err);
    res.status(500).json({ error: 'Failed to save: ' + err.message, file: STORAGE_LABEL });
  }
});

// ─────────────────────────────────────────────
// DIAGNOSTIC DASHBOARD — Meta ad-level insights with comparison window
// ─────────────────────────────────────────────
app.get('/api/diag-meta', requireAuth, async (req, res) => {
  const { account_id, since, until, compare_since, compare_until } = req.query;
  if (!account_id || !since || !until) {
    return res.status(400).json({ error: 'account_id, since, and until are required' });
  }

  const INSIGHT_FIELDS = [
    'ad_id', 'ad_name', 'adset_id', 'adset_name', 'campaign_id', 'campaign_name',
    'spend', 'impressions', 'reach', 'frequency', 'cpm', 'cpc', 'ctr',
    'inline_link_clicks', 'inline_link_click_ctr', 'cost_per_inline_link_click',
    'clicks',
    'actions', 'action_values',
    'video_p25_watched_actions', 'video_p50_watched_actions',
    'video_p75_watched_actions', 'video_p100_watched_actions',
    'video_thruplay_watched_actions',
    'quality_ranking', 'engagement_rate_ranking', 'conversion_rate_ranking',
  ].join(',');

  // Meta throttles by total payload (fields × rows). Keep page size small and
  // page through; up to 25 pages × 50 rows = 1250 ads max per window.
  // Meta's pagination `next` URL preserves access_token but NOT appsecret_proof,
  // so we re-append it to every paginated request.
  const proof = generateAppSecretProof(req.accessToken);
  const ensureProof = (u) => u.includes('appsecret_proof=') ? u : (u + `&appsecret_proof=${proof}`);

  const fetchInsights = async (s, u) => {
    const url = `${META_BASE_URL}/${account_id}/insights`
      + `?fields=${INSIGHT_FIELDS}`
      + `&time_range=${encodeURIComponent(JSON.stringify({ since: s, until: u }))}`
      + `&level=ad`
      + `&time_increment=all_days`
      + `&filtering=${encodeURIComponent(JSON.stringify([{ field: 'spend', operator: 'GREATER_THAN', value: 0 }]))}`
      + `&limit=50`
      + `&${metaParams(req.accessToken)}`;
    const all = [];
    let next = url;
    let pageCount = 0;
    while (next && pageCount < 25) {
      const resp = await fetch(ensureProof(next));
      const data = await resp.json();
      if (data.error) {
        if (data.error.code === 190) {
          clearTokenCookie(res);
          throw Object.assign(new Error('Session expired. Please log in again.'), { status: 401 });
        }
        throw new Error(data.error.message || 'Meta insights error');
      }
      if (Array.isArray(data.data)) all.push(...data.data);
      next = data.paging?.next || null;
      pageCount += 1;
    }
    return all;
  };

  try {
    const [current, prior] = await Promise.all([
      fetchInsights(since, until),
      compare_since && compare_until ? fetchInsights(compare_since, compare_until) : Promise.resolve([]),
    ]);

    // Helper to extract action value of a given type
    const actionVal = (arr, type) => {
      if (!Array.isArray(arr)) return 0;
      const f = arr.find(a => a.action_type === type);
      return f ? (parseFloat(f.value) || 0) : 0;
    };

    const shapeRow = (a) => {
      const impressions = parseFloat(a.impressions) || 0;
      const link_clicks = parseFloat(a.inline_link_clicks) || actionVal(a.actions, 'link_click');
      const lpv = actionVal(a.actions, 'landing_page_view');
      // 3-sec views come from the `actions` array under action_type 'video_view'
      // (Meta deprecated the top-level video_3_sec_watched_actions field).
      const v3 = actionVal(a.actions, 'video_view');
      const vthru = actionVal(a.video_thruplay_watched_actions, 'video_thruplay_watched')
        || actionVal(a.video_thruplay_watched_actions, 'video_view');
      return {
        ad_id: a.ad_id,
        ad_name: a.ad_name || '',
        adset_id: a.adset_id, adset_name: a.adset_name,
        campaign_id: a.campaign_id, campaign_name: a.campaign_name,
        spend: parseFloat(a.spend) || 0,
        impressions,
        reach: parseFloat(a.reach) || 0,
        frequency: parseFloat(a.frequency) || 0,
        cpm: parseFloat(a.cpm) || 0,
        cpc: parseFloat(a.cpc) || 0,
        ctr: parseFloat(a.ctr) || 0,                                // %
        link_clicks,
        link_ctr: parseFloat(a.inline_link_click_ctr) || 0,         // %
        cost_per_link_click: parseFloat(a.cost_per_inline_link_click) || 0,
        clicks_all: parseFloat(a.clicks) || 0,
        landing_page_views: lpv,
        video_3sec_views: v3 || null,
        video_thruplay: vthru || null,
        video_p25: actionVal(a.video_p25_watched_actions, 'video_view') || null,
        video_p50: actionVal(a.video_p50_watched_actions, 'video_view') || null,
        video_p75: actionVal(a.video_p75_watched_actions, 'video_view') || null,
        video_p100: actionVal(a.video_p100_watched_actions, 'video_view') || null,
        // Prefer the most-comprehensive purchase counter Meta returned; fall back
        // through Pixel-only and finally to the legacy 'purchase' action type.
        meta_purchases: actionVal(a.actions, 'omni_purchase')
          || actionVal(a.actions, 'offsite_conversion.fb_pixel_purchase')
          || actionVal(a.actions, 'purchase'),
        meta_purchase_value: actionVal(a.action_values, 'omni_purchase')
          || actionVal(a.action_values, 'offsite_conversion.fb_pixel_purchase')
          || actionVal(a.action_values, 'purchase'),
        meta_atc: actionVal(a.actions, 'omni_add_to_cart')
          || actionVal(a.actions, 'offsite_conversion.fb_pixel_add_to_cart')
          || actionVal(a.actions, 'add_to_cart'),
        meta_ic: actionVal(a.actions, 'omni_initiated_checkout')
          || actionVal(a.actions, 'offsite_conversion.fb_pixel_initiate_checkout')
          || actionVal(a.actions, 'initiate_checkout'),
        post_reactions: actionVal(a.actions, 'post_reaction'),
        post_comments: actionVal(a.actions, 'comment'),
        post_shares: actionVal(a.actions, 'post'),
        post_saves: actionVal(a.actions, 'onsite_conversion.post_save'),
        quality_ranking: a.quality_ranking || null,
        engagement_rate_ranking: a.engagement_rate_ranking || null,
        conversion_rate_ranking: a.conversion_rate_ranking || null,
      };
    };

    const currentRows = current.map(shapeRow);
    const priorRows   = prior.map(shapeRow);

    // Batch-fetch created_time for every distinct ad_id that appears in the
    // current period. Lets the FRESH_CREATIVE bucket flag ads first published
    // inside [since, until]. Batches of 50 run in parallel — for ~300 ads this
    // is ~6 concurrent calls, finishing in a few seconds.
    const adIdsForCreated = [...new Set(currentRows.map(r => r.ad_id))].filter(Boolean);
    const createdMap = {};
    const proof2 = generateAppSecretProof(req.accessToken);
    const batchSlices = [];
    for (let i = 0; i < adIdsForCreated.length; i += 50) {
      batchSlices.push(adIdsForCreated.slice(i, i + 50));
    }
    const batchResults = await Promise.all(batchSlices.map(async (slice) => {
      const batchRequests = slice.map(id => ({
        method: 'GET', relative_url: `${id}?fields=created_time`,
      }));
      try {
        const body = new URLSearchParams({
          access_token: req.accessToken,
          appsecret_proof: proof2,
          batch: JSON.stringify(batchRequests),
        });
        const resp = await fetch(`${META_BASE_URL}/`, {
          method: 'POST', body, signal: AbortSignal.timeout(20000),
        });
        return { slice, results: await resp.json() };
      } catch (e) {
        console.error('[diag-meta] created_time batch failed:', e.message);
        return { slice, results: null };
      }
    }));
    for (const { slice, results } of batchResults) {
      if (!Array.isArray(results)) continue;
      for (let j = 0; j < slice.length; j++) {
        const r = results[j];
        if (r && r.code === 200) {
          try {
            const parsed = JSON.parse(r.body);
            if (parsed.created_time) createdMap[slice[j]] = parsed.created_time;
          } catch {}
        }
      }
    }

    // landing_page_path is derived from the ad-name slug only (parseAdName).
    // Skipping the per-ad creative fetch keeps cold-load fast: for accounts
    // where ads don't follow the `url:slug` convention, we'll fall back to
    // '(unknown)' and the join won't match Shopify rows for those ads.
    // The detail panel separately fetches preview_shareable_link on demand.
    const pathFromUrl = (u) => {
      if (!u) return null;
      try { return new URL(u).pathname || '/'; } catch { return null; }
    };
    const enrich = (r) => {
      const parsed = parseAdName(r.ad_name);
      const pathFromName = parsed.landing_page_url ? pathFromUrl(parsed.landing_page_url) : null;
      return {
        ...r,
        landing_page_path: pathFromName || '(unknown)',
        creative_link_url: parsed.landing_page_url || null,
        preview_shareable_link: null,        // lazy-loaded
        ad_name_parsed: parsed,
        created_time: createdMap[r.ad_id] || null,
      };
    };

    res.json({
      current: currentRows.map(enrich),
      prior:   priorRows,
      since, until, compare_since: compare_since || null, compare_until: compare_until || null,
    });
  } catch (err) {
    console.error('[diag-meta] error:', err);
    if (err.status === 401) return res.status(401).json({ error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// DIAGNOSTIC DASHBOARD — preview link for one ad (lazy-loaded by detail panel)
// ─────────────────────────────────────────────
app.get('/api/diag-ad-preview', requireAuth, async (req, res) => {
  const { ad_id } = req.query;
  if (!ad_id) return res.status(400).json({ error: 'ad_id required' });
  try {
    const url = `${META_BASE_URL}/${ad_id}`
      + `?fields=preview_shareable_link,creative{link_url,object_story_spec,asset_feed_spec}`
      + `&${metaParams(req.accessToken)}`;
    const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
    const data = await r.json();
    if (data.error) {
      if (data.error.code === 190) { clearTokenCookie(res); return res.status(401).json({ error: 'Session expired' }); }
      return res.status(400).json({ error: data.error.message });
    }
    const creative = data.creative || {};
    const link = creative.link_url
      || extractDestinationUrl(creative.object_story_spec || {})
      || extractAssetFeedUrl(creative.asset_feed_spec || {})
      || null;
    res.json({
      ad_id,
      preview_shareable_link: data.preview_shareable_link || null,
      creative_link_url: link,
    });
  } catch (err) {
    console.error('[diag-ad-preview] error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// DIAGNOSTIC DASHBOARD — Shopify orders aggregated by utm_content × landing_page_path
// ─────────────────────────────────────────────
app.get('/api/diag-shopify', async (req, res) => {
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }
  const { since, until } = req.query;
  if (!since || !until || !/^\d{4}-\d{2}-\d{2}$/.test(since) || !/^\d{4}-\d{2}-\d{2}$/.test(until)) {
    return res.status(400).json({ error: 'since and until query params required (YYYY-MM-DD)' });
  }
  const escapeQL = (v) => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  // Match the syntax of /api/meta-cvr-impact-data: single utm_source + utm_medium
  // (ShopifyQL on this store rejects OR / IN clauses; AND-joined equality is the
  // pattern that works everywhere else in this app). To capture multiple
  // sources (e.g. facebook + instagram) we run one query per source and merge.
  const sources = (req.query.utm_sources || 'facebook')
    .split(',').map(s => s.trim()).filter(Boolean);
  const medium = escapeQL((req.query.utm_medium || 'paid_social').trim());

  const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const gqlQuery = `query RunShopifyQL($q: String!) {
    shopifyqlQuery(query: $q) { tableData { columns { name dataType } rows } parseErrors }
  }`;

  // Mirrors the proven /api/meta-cvr-impact-data and /api/shopify-metrics
  // patterns: FROM sessions, SHOW sessions + conversion_rate + completed-checkout
  // count, WHERE utm_source = X AND utm_medium = Y, GROUP BY utm_content,
  // landing_page_path. This Shopify store doesn't expose `orders` / `sales`
  // datasets — revenue / AOV / %new aren't reachable; the dashboard handles
  // null values and skips rules that need them.
  const buildQL = (source) => `FROM sessions
  SHOW sessions, conversion_rate, sessions_that_completed_checkout, average_session_duration, bounce_rate
  WHERE utm_source = '${escapeQL(source)}' AND utm_medium = '${medium}'
  GROUP BY utm_content, landing_page_path
  SINCE ${since} UNTIL ${until}
  ORDER BY sessions DESC`;

  const run = async (ql) => {
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q: ql } }),
    });
    const j = await r.json();
    if (j.data?.shopifyqlQuery?.parseErrors?.length) {
      const err = new Error('ShopifyQL parse error: ' + JSON.stringify(j.data.shopifyqlQuery.parseErrors));
      err.parseErrors = j.data.shopifyqlQuery.parseErrors;
      throw err;
    }
    return j.data?.shopifyqlQuery?.tableData || null;
  };

  try {
    // Run one query per utm_source in parallel and concat their rows.
    const queries = sources.map(buildQL);
    queries.forEach(q => console.log('\n[diag-shopify] query:\n' + q));
    const tables = await Promise.all(queries.map(run));

    // Merge: union the rows under a single columns array (all queries share schema).
    const cols = tables.find(t => t && t.columns)?.columns || null;
    const rows = tables.flatMap(t => t?.rows || []);
    res.json({
      sources, medium,
      queries,
      sessions: cols ? { columns: cols, rows } : null,
      since, until,
    });
  } catch (err) {
    console.error('[diag-shopify] error:', err);
    res.status(500).json({ error: err.message });
  }
});

// --- Campaign insights by day ---

app.get('/api/campaign-insights', requireAuth, async (req, res) => {
  const { account_id, since, until } = req.query;
  if (!account_id || !since || !until) {
    return res.status(400).json({ error: 'account_id, since, and until are required' });
  }

  try {
    const timeRange = `{"since":"${since}","until":"${until}"}`;

    // Step 1: Get all campaigns with total sessions (sorted by spend)
    const summaryUrl = `${META_BASE_URL}/${account_id}/insights`
      + `?fields=campaign_name,campaign_id,spend,impressions,clicks,actions,cpm,ctr,outbound_clicks`
      + `&time_range=${timeRange}`
      + `&level=campaign`
      + `&sort=spend_descending`
      + `&limit=100`
      + `&${metaParams(req.accessToken)}`;

    const summaryResp = await fetch(summaryUrl);
    const summaryData = await summaryResp.json();

    if (summaryData.error) {
      if (summaryData.error.code === 190) {
        clearTokenCookie(res);
        return res.status(401).json({ error: 'Session expired. Please log in again.' });
      }
      return res.status(400).json({ error: summaryData.error.message });
    }

    const campaigns = (summaryData.data || []).map(c => {
      const actionVal = (arr, type) => {
        if (!Array.isArray(arr)) return 0;
        const found = arr.find(a => a.action_type === type);
        return found ? (parseFloat(found.value) || 0) : 0;
      };
      const oc = Array.isArray(c.outbound_clicks)
        ? c.outbound_clicks.find(o => o.action_type === 'outbound_click')
        : null;
      return {
        campaign_id: c.campaign_id,
        campaign_name: c.campaign_name,
        spend: parseFloat(c.spend) || 0,
        impressions: parseInt(c.impressions) || 0,
        clicks: parseInt(c.clicks) || 0,
        outbound_clicks: oc ? parseInt(oc.value) : 0,
        cpm: parseFloat(c.cpm) || 0,
        ctr: parseFloat(c.ctr) || 0,
        purchases: actionVal(c.actions, 'purchase'),
        add_to_cart: actionVal(c.actions, 'add_to_cart'),
        initiate_checkout: actionVal(c.actions, 'initiate_checkout'),
        landing_page_views: actionVal(c.actions, 'landing_page_view'),
      };
    });

    res.json({ campaigns });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/campaign-daily', requireAuth, async (req, res) => {
  const { account_id, campaign_id, since, until } = req.query;
  if (!account_id || !campaign_id || !since || !until) {
    return res.status(400).json({ error: 'account_id, campaign_id, since, and until are required' });
  }

  try {
    const timeRange = `{"since":"${since}","until":"${until}"}`;

    const url = `${META_BASE_URL}/${campaign_id}/insights`
      + `?fields=campaign_name,spend,impressions,clicks,actions,cpm,ctr,outbound_clicks`
      + `&time_range=${timeRange}`
      + `&time_increment=1`
      + `&limit=90`
      + `&${metaParams(req.accessToken)}`;

    const resp = await fetch(url);
    const data = await resp.json();

    if (data.error) {
      if (data.error.code === 190) {
        clearTokenCookie(res);
        return res.status(401).json({ error: 'Session expired. Please log in again.' });
      }
      return res.status(400).json({ error: data.error.message });
    }

    const actionVal = (arr, type) => {
      if (!Array.isArray(arr)) return 0;
      const found = arr.find(a => a.action_type === type);
      return found ? (parseFloat(found.value) || 0) : 0;
    };

    const days = (data.data || []).map(d => {
      const oc = Array.isArray(d.outbound_clicks)
        ? d.outbound_clicks.find(o => o.action_type === 'outbound_click')
        : null;
      return {
        date: d.date_start,
        spend: parseFloat(d.spend) || 0,
        impressions: parseInt(d.impressions) || 0,
        clicks: parseInt(d.clicks) || 0,
        outbound_clicks: oc ? parseInt(oc.value) : 0,
        cpm: parseFloat(d.cpm) || 0,
        ctr: parseFloat(d.ctr) || 0,
        purchases: actionVal(d.actions, 'purchase'),
        add_to_cart: actionVal(d.actions, 'add_to_cart'),
        initiate_checkout: actionVal(d.actions, 'initiate_checkout'),
        landing_page_views: actionVal(d.actions, 'landing_page_view'),
      };
    });

    res.json({ days });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Ad name parser ---

// Deconstructs ad names like: "brand_campaign-type_audience_creative-desc_url:landing-page"
// Partnership ads contain ":ext-" patterns
function parseAdName(adName) {
  if (!adName) return { segments: [], landing_page: null, landing_page_url: null, is_partnership: false, creator: null };

  const nameLower = adName.toLowerCase();

  // Detect partnership
  const isPartnership = nameLower.includes('creator_wl:ext')
    || nameLower.includes('notes:ext-')
    || nameLower.includes('editor:ext-')
    || nameLower.includes(':ext-')
    || /\bext[-_]creator\b/.test(nameLower);

  // Extract creator handle from partnership patterns
  let creator = null;
  if (isPartnership) {
    const creatorMatch = adName.match(/:ext-([^_:]+)/i);
    if (creatorMatch) creator = creatorMatch[1];
  }

  // Extract URL slug
  let landingPage = null;
  let landingPageUrl = null;
  const urlSlugMatch = adName.match(/(?:^|[_:-])url[:_]([a-zA-Z0-9-]+)/i);
  if (urlSlugMatch) {
    const slug = urlSlugMatch[1];
    landingPage = slug;
    // Determine brand domain from ad name
    const brandDomain = nameLower.startsWith('trmv') ? 'therearemanyversions.com' : 'firstday.com';
    landingPageUrl = slug.toUpperCase() === 'HOMEPAGE'
      ? `https://${brandDomain}/`
      : `https://${brandDomain}/pages/${slug}`;
  }

  // Split into segments (by underscore), excluding url: and ext- parts
  const rawSegments = adName.split('_');
  const segments = rawSegments
    .filter(s => !s.match(/^url[:_]/i))
    .map(s => s.replace(/:ext-.*$/i, '').replace(/^ext[-_].*$/i, ''))
    .filter(s => s.length > 0);

  return {
    segments,
    landing_page: landingPage,
    landing_page_url: landingPageUrl,
    is_partnership: isPartnership,
    creator,
  };
}

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

// Parse url_tags (UTM param string) for any parameter value that is a full URL.
// e.g. url_tags = "utm_source=facebook&utm_content=https%3A%2F%2Ffirstday.com%2Fpages%2Ffoo"
function extractUrlTagsUrl(urlTags) {
  if (!urlTags) return null;
  try {
    const params = new URLSearchParams(urlTags);
    for (const [, value] of params) {
      if (value.startsWith('http://') || value.startsWith('https://')) {
        try { new URL(value); return value; } catch {}
      }
    }
  } catch (e) {}
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
