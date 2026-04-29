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

  // ALWAYS run the main query with COMPARE TO previous_period — proven to
  // work, returns the full column shape the frontend parser expects. When a
  // custom compare window is supplied, we run a second query for that range
  // and OVERWRITE the previous_period values in each main row.
  const mainQuery = `FROM sessions
  SHOW sessions, conversion_rate, average_session_duration, sessions_with_cart_additions, sessions_that_reached_checkout, sessions_that_reached_and_completed_checkout
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_campaign, landing_page_path WITH TOTALS, PERCENT_CHANGE
  SINCE ${start} UNTIL ${end}
  COMPARE TO previous_period
  ORDER BY sessions DESC
VISUALIZE conversion_rate TYPE table`;

  const compareQuery = useCustomCompare ? `FROM sessions
  SHOW sessions, conversion_rate
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

    // Overwrite the previous_period values in the main response with values
    // from the custom compare window. The main query's column shape stays
    // identical (same columns, same row order), we just swap the numbers in
    // the existing `comparison_*__previous_period` cells.
    if (!main || !Array.isArray(main.rows) || !Array.isArray(main.columns)) {
      throw new Error('Main Shopify response missing rows/columns array (got ' + typeof main + ')');
    }
    if (!compare || !Array.isArray(compare.rows) || !Array.isArray(compare.columns)) {
      throw new Error('Compare Shopify response missing rows/columns array (got ' + typeof compare + ')');
    }

    const mainColNames = main.columns.map(c => c.name);
    const cmpColNames  = compare.columns.map(c => c.name);
    const toArray = (row, names) => {
      if (Array.isArray(row)) return row;
      if (row && typeof row === 'object') return names.map(n => row[n]);
      return [];
    };

    const cols = mainColNames.map(n => (n || '').toLowerCase());
    const cmpCols = cmpColNames.map(n => (n || '').toLowerCase());
    const idx = (arr, n) => arr.findIndex(s => s === n);

    // Where to write in the main row
    const iCampaign      = idx(cols, 'utm_campaign');
    const iLp            = idx(cols, 'landing_page_path');
    const iMainPrevS     = idx(cols, 'comparison_sessions__previous_period');
    const iMainPrevCvr   = idx(cols, 'comparison_conversion_rate__previous_period');
    const iMainPrevSTot  = idx(cols, 'comparison_sessions__previous_period__totals');
    const iMainPrevCvrTot= idx(cols, 'comparison_conversion_rate__previous_period__totals');

    // Where to read from the compare row
    const cmpICampaign   = idx(cmpCols, 'utm_campaign');
    const cmpILp         = idx(cmpCols, 'landing_page_path');
    const cmpISess       = idx(cmpCols, 'sessions');
    const cmpICvr        = idx(cmpCols, 'conversion_rate');
    const cmpISessTot    = idx(cmpCols, 'sessions__totals');
    const cmpICvrTot     = idx(cmpCols, 'conversion_rate__totals');

    // Index compare rows. ShopifyQL's `WITH TOTALS` doesn't emit a separate
    // empty-dimension row — it adds `__totals` columns to every data row.
    // Read the grand totals from the first row's `__totals` columns and skip
    // the search for a totals row.
    const cmpMap = new Map();
    const cmpTotals = compare.rows.length > 0
      ? toArray(compare.rows[0], cmpColNames)
      : null;
    for (const row of compare.rows) {
      const arr = toArray(row, cmpColNames);
      const c = String(arr[cmpICampaign] ?? '').trim();
      const l = String(arr[cmpILp]       ?? '').trim();
      if (!c && !l) continue;
      cmpMap.set(c + '||' + l, arr);
    }

    let matched = 0;
    let unmatched = 0;
    const newRows = main.rows.map(row => {
      const arr = toArray(row, mainColNames).slice();         // shallow copy (mutate locally)
      const c = String(arr[iCampaign] ?? '').trim();
      const l = String(arr[iLp]       ?? '').trim();
      const isTotalsRow = !c && !l;
      const cmpRow = isTotalsRow ? cmpTotals : cmpMap.get(c + '||' + l);
      if (cmpRow) matched++; else if (!isTotalsRow) unmatched++;

      // Per-row previous_period values
      if (iMainPrevS >= 0)   arr[iMainPrevS]   = cmpRow != null && cmpISess >= 0 ? cmpRow[cmpISess] : null;
      if (iMainPrevCvr >= 0) arr[iMainPrevCvr] = cmpRow != null && cmpICvr  >= 0 ? cmpRow[cmpICvr]  : null;

      // Totals (same value on every row — the parser only reads from rows[0])
      if (iMainPrevSTot >= 0)   arr[iMainPrevSTot]   = cmpTotals != null && cmpISessTot >= 0 ? cmpTotals[cmpISessTot] : null;
      if (iMainPrevCvrTot >= 0) arr[iMainPrevCvrTot] = cmpTotals != null && cmpICvrTot  >= 0 ? cmpTotals[cmpICvrTot]  : null;

      return arr;
    });

    const mergeStats = {
      main_rows: main.rows.length,
      compare_rows: compare.rows.length,
      compare_keys_indexed: cmpMap.size,
      had_compare_totals: !!cmpTotals,
      matched_keys: matched,
      unmatched_keys: unmatched,
      main_has_prev_columns: { iMainPrevS, iMainPrevCvr, iMainPrevSTot, iMainPrevCvrTot },
    };
    console.log('[meta-cvr-impact-data] custom-compare merge:', mergeStats);

    res.json({
      query: mainQuery,
      compare_query: compareQuery,
      filter: { source, medium },
      compare_window: { start: cs, end: ce },
      merge_stats: mergeStats,
      columns: main.columns,                                  // unchanged shape
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

// ─────────────────────────────────────────────
// AD-SET FATIGUE ENGINE
// ─────────────────────────────────────────────
// Six-signal weighted fatigue score (0–100) per ad set. Each signal is a
// deviation from the ad set's own trailing window so high-frequency-by-design
// creatives don't get falsely flagged.
//
// Weights (sum = 100): freq velocity 25, CTR decay 20, ROAS slope 20,
// CPC inflation 15, audience saturation 10, CPP slope 10.
//
// Lifecycle states (from PRD):
//   <30  🟢 healthy        ·   30-50 👀 watching   ·   50-70 🟡 fatiguing
//   70-85 🟠 fatigued      ·   85+   🔴 replace_now
// Each signal is normalised to a 0-100 contribution, where 100 means the
// signal is "fully bad." We clip extreme deviations to keep the score from
// being dominated by tiny-denominator noise.

function fatigueState(score) {
  if (score >= 85) return 'replace_now';
  if (score >= 70) return 'fatigued';
  if (score >= 50) return 'fatiguing';
  if (score >= 30) return 'watching';
  return 'healthy';
}

// Linear least-squares slope over [y0, y1, ..., y_{n-1}] vs index.
// Returns {slope, mean} where slope is per-day-step. Returns null if <3 pts.
function olsSlope(y) {
  if (!y || y.length < 3) return null;
  const n = y.length;
  let sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (let i = 0; i < n; i++) {
    sx += i; sy += y[i]; sxx += i * i; sxy += i * y[i];
  }
  const denom = n * sxx - sx * sx;
  if (denom === 0) return null;
  const slope = (n * sxy - sx * sy) / denom;
  const mean = sy / n;
  return { slope, mean };
}

// Convert a signed deviation to a 0-100 "badness" contribution.
// `value` should already be sign-normalised so positive = bad.
// `cap` is the value at which the signal is fully maxed out (= 100).
function normSignal(value, cap) {
  if (value == null || isNaN(value) || !isFinite(value)) return null;
  const v = Math.max(0, value);             // bad signals only push score up
  return Math.min(100, (v / cap) * 100);
}

// Computes per-signal contributions and a final 0-100 score.
//   daily: array of { date, spend, impressions, clicks, link_clicks, reach,
//                     purchases, purchase_value } sorted ascending by date.
//   audienceSize: optional estimated audience size (number) for saturation.
function computeFatigueScore(daily, audienceSize) {
  if (!daily || daily.length === 0) {
    return { score: null, state: 'unknown', signals: {}, reason: 'no_daily_data' };
  }
  // Take the last 14 days (or fewer if less data available).
  const d = daily.slice(-14);
  const last7  = d.slice(-7);
  const prev7  = d.slice(-14, -7);
  const last5  = d.slice(-5);

  const sum = (arr, k) => arr.reduce((s, x) => s + (x[k] || 0), 0);
  const safeDiv = (n, d) => (d > 0 ? n / d : null);

  // Window aggregates
  const last7Spend = sum(last7, 'spend');
  const prev7Spend = sum(prev7, 'spend');
  const last7Impr  = sum(last7, 'impressions');
  const prev7Impr  = sum(prev7, 'impressions');
  const last7Reach = sum(last7, 'reach');
  const prev7Reach = sum(prev7, 'reach');
  const last7Clicks= sum(last7, 'clicks');
  const prev7Clicks= sum(prev7, 'clicks');
  const last7Purch = sum(last7, 'purchases');
  const prev7Purch = sum(prev7, 'purchases');

  // Frequency = impressions / reach (per window)
  const last7Freq = safeDiv(last7Impr, last7Reach);
  const prev7Freq = safeDiv(prev7Impr, prev7Reach);
  // CTR (all clicks) = clicks / impressions
  const last7Ctr = safeDiv(last7Clicks, last7Impr);
  const prev7Ctr = safeDiv(prev7Clicks, prev7Impr);
  // CPC = spend / clicks
  const last7Cpc = safeDiv(last7Spend, last7Clicks);
  const prev7Cpc = safeDiv(prev7Spend, prev7Clicks);

  // Daily ROAS series (last 5 days)
  const dailyRoas = last5.map(x => {
    if ((x.spend || 0) <= 0) return null;
    return (x.purchase_value || 0) / x.spend;
  }).filter(v => v != null);
  // Daily CPP series (last 5 days)
  const dailyCpp = last5.map(x => {
    if ((x.purchases || 0) <= 0) return null;
    return x.spend / x.purchases;
  }).filter(v => v != null);

  // Signal 1: Frequency velocity — bad when freq is rising fast
  // (last7 - prev7) / prev7. Cap at +1.0 (100% week-over-week jump).
  const freqVelocityRaw = (last7Freq != null && prev7Freq != null && prev7Freq > 0)
    ? (last7Freq - prev7Freq) / prev7Freq : null;
  const sFreqVelocity = normSignal(freqVelocityRaw, 1.0);

  // Signal 2: CTR decay — bad when CTR is FALLING
  // (prev7 - last7) / prev7. Cap at +0.5 (50% drop).
  const ctrDecayRaw = (last7Ctr != null && prev7Ctr != null && prev7Ctr > 0)
    ? (prev7Ctr - last7Ctr) / prev7Ctr : null;
  const sCtrDecay = normSignal(ctrDecayRaw, 0.5);

  // Signal 3: ROAS slope — bad when slope is NEGATIVE (declining ROAS)
  // We sign-flip so positive = bad. Cap at -0.5 ROAS units per day.
  let sRoasSlope = null;
  let roasSlopeRaw = null;
  if (dailyRoas.length >= 3) {
    const r = olsSlope(dailyRoas);
    if (r) {
      roasSlopeRaw = r.slope;
      // Negative slope = bad. Normalise abs(negative slope) relative to mean.
      const decline = -r.slope;
      // express as fraction-of-mean per day, so a 10%/day decline → 0.10
      const declineFrac = r.mean > 0 ? decline / r.mean : 0;
      sRoasSlope = normSignal(declineFrac, 0.20);   // 20%/day = fully bad
    }
  }

  // Signal 4: CPC inflation — bad when CPC is RISING
  const cpcInflationRaw = (last7Cpc != null && prev7Cpc != null && prev7Cpc > 0)
    ? (last7Cpc - prev7Cpc) / prev7Cpc : null;
  const sCpcInflation = normSignal(cpcInflationRaw, 0.5);

  // Signal 5: Audience saturation — reach / estimated audience size.
  // If no audience size provided, use a structural proxy: cumulative reach
  // growth slowdown. fraction = last7_reach / cumulative_reach. As the ad set
  // matures and saturates, last7 reach as a % of cumulative shrinks. We
  // INVERT: high "saturation_proxy" = low new-reach addition vs cumulative.
  let sSaturation = null;
  let saturationRaw = null;
  if (audienceSize && audienceSize > 0 && last7Reach > 0) {
    // True saturation: fraction of total audience already reached this week
    saturationRaw = last7Reach / audienceSize;
    sSaturation = normSignal(saturationRaw, 0.6);   // 60%+ = fully saturated
  } else {
    // Proxy: compare last 7d reach to total 14d reach. A healthy young ad set
    // adds substantial NEW reach in last 7d (high ratio). A saturated ad set
    // has flat reach growth (last7Reach close to cumulative). We invert the
    // ratio so that low new-reach contribution → high saturation signal.
    const cumulativeReach = sum(d, 'reach');
    if (cumulativeReach > 0 && last7Reach > 0) {
      const newReachRatio = last7Reach / cumulativeReach;
      // ratio of 0.5 = balanced (half of 14d reach came in last 7d) = healthy
      // ratio approaching 0 = no fresh reach = saturated
      saturationRaw = Math.max(0, 0.5 - newReachRatio) * 2;     // 0..1
      sSaturation = normSignal(saturationRaw, 1.0);
    }
  }

  // Signal 6: CPP slope — bad when CPP is rising (cost going up)
  let sCppSlope = null;
  let cppSlopeRaw = null;
  if (dailyCpp.length >= 3) {
    const r = olsSlope(dailyCpp);
    if (r) {
      cppSlopeRaw = r.slope;
      const inflFrac = r.mean > 0 ? r.slope / r.mean : 0;   // pos = rising = bad
      sCppSlope = normSignal(inflFrac, 0.20);
    }
  }

  // Weighted score. If a signal is null (insufficient data), redistribute its
  // weight pro-rata across the available signals so the score stays on a 0-100
  // scale regardless of which signals are missing.
  const weights = {
    freq_velocity:    25,
    ctr_decay:        20,
    roas_slope:       20,
    cpc_inflation:    15,
    audience_saturation: 10,
    cpp_slope:        10,
  };
  const signals = {
    freq_velocity:    sFreqVelocity,
    ctr_decay:        sCtrDecay,
    roas_slope:       sRoasSlope,
    cpc_inflation:    sCpcInflation,
    audience_saturation: sSaturation,
    cpp_slope:        sCppSlope,
  };
  let weightSum = 0;
  let weighted = 0;
  for (const k of Object.keys(signals)) {
    if (signals[k] != null) {
      weightSum += weights[k];
      weighted  += signals[k] * weights[k];
    }
  }
  const score = weightSum > 0 ? weighted / weightSum : null;

  return {
    score: score == null ? null : Math.round(score * 10) / 10,
    state: score == null ? 'unknown' : fatigueState(score),
    signals,
    raw: {
      last7Freq, prev7Freq,
      last7Ctr,  prev7Ctr,
      last7Cpc,  prev7Cpc,
      last7Reach, prev7Reach,
      last7Spend, prev7Spend,
      last7Purch, prev7Purch,
      freqVelocityRaw, ctrDecayRaw, roasSlopeRaw, cpcInflationRaw, saturationRaw, cppSlopeRaw,
      dailyRoasN: dailyRoas.length,
      dailyCppN:  dailyCpp.length,
    },
    weight_sum: weightSum,
    days_analyzed: d.length,
  };
}

// ─────────────────────────────────────────────
// CVR DECOMPOSITION (Rate / Mix / Entry / Exit)
// ─────────────────────────────────────────────
// Returns ad-level (utm_content × landing_page_path) sessions + conversion_rate
// for two arbitrary periods (period_a = "before", period_b = "after"). The
// frontend joins the two row sets on (utm_content, landing_page_path), filters
// by an optional landing_page_path substring, and runs the four-component
// counterfactual decomposition documented in the PRD.
//
// We intentionally run two single-period queries (no COMPARE TO previous_period)
// because the decomposition tool needs custom, possibly unequal-length periods.
// ShopifyQL doesn't expose substring matching on landing_page_path reliably, so
// the LP filter is applied client-side after both row sets land.
app.get('/api/cvr-decomp-data', async (req, res) => {
  const t0 = Date.now();
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    console.error('[cvr-decomp] missing Shopify credentials');
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }

  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  const {
    period_a_start, period_a_end,
    period_b_start, period_b_end,
  } = req.query;

  if (![period_a_start, period_a_end, period_b_start, period_b_end].every(s => s && dateRe.test(s))) {
    console.warn('[cvr-decomp] invalid date params:', req.query);
    return res.status(400).json({
      error: 'period_a_start, period_a_end, period_b_start, period_b_end required (YYYY-MM-DD)',
    });
  }

  const escapeQL = v => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const source = escapeQL(req.query.source || 'facebook');
  const medium = escapeQL(req.query.medium || 'paid_social');
  const lpFilterRaw = (req.query.lp_filter || '').trim();

  // ShopifyQL doesn't support LIKE — confirmed via parser error. So:
  //   • If the user gave us something that looks like a literal path (starts
  //     with `/` and contains no spaces), push it down as an exact-match
  //     `landing_page_path = '...'`. This is the common case (e.g. PRD's
  //     `/pages/tdk-behind-the-science-lp`) and avoids the 5000-row cap
  //     biting on high-traffic slices.
  //   • Otherwise (substring like "tdk" or "behind-the-science") we leave it
  //     to the frontend to filter client-side.
  const lpExactMatch = lpFilterRaw && lpFilterRaw.startsWith('/') && !/\s/.test(lpFilterRaw)
    ? lpFilterRaw
    : null;

  // ShopifyQL caps results at 5000 rows on this store; default is 1000.
  // We hit 1000 in testing on broad slices — bumping LIMIT covers the long
  // tail of low-traffic ads that matter for the decomposition.
  const ROW_LIMIT = 5000;

  console.log('\n[cvr-decomp] ───────────────────────────────────────────────');
  console.log('[cvr-decomp] request:', {
    source, medium,
    period_a: `${period_a_start} → ${period_a_end}`,
    period_b: `${period_b_start} → ${period_b_end}`,
    lp_filter_raw: lpFilterRaw || '(none)',
    lp_exact_match_pushdown: lpExactMatch || '(none — client-side substring)',
    row_limit: ROW_LIMIT,
  });

  const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const gqlQuery = `query RunShopifyQL($q: String!) {
    shopifyqlQuery(query: $q) {
      tableData { columns { name dataType } rows }
      parseErrors
    }
  }`;

  const lpClause = lpExactMatch ? ` AND landing_page_path = '${escapeQL(lpExactMatch)}'` : '';
  const buildQuery = (start, end) => `FROM sessions
  SHOW sessions, conversion_rate
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'${lpClause}
  GROUP BY utm_content, landing_page_path WITH TOTALS
  SINCE ${start} UNTIL ${end}
  ORDER BY sessions DESC
  LIMIT ${ROW_LIMIT}`;

  const queryA = buildQuery(period_a_start, period_a_end);
  const queryB = buildQuery(period_b_start, period_b_end);

  console.log('[cvr-decomp] period A query:\n' + queryA);
  console.log('[cvr-decomp] period B query:\n' + queryB);

  const runShopifyQL = async (q, label) => {
    const tStart = Date.now();
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q } }),
    });
    const json = await resp.json();
    const payload = json.data?.shopifyqlQuery;
    const ms = Date.now() - tStart;
    if (payload?.parseErrors?.length) {
      console.error(`[cvr-decomp] ${label} parse errors after ${ms}ms:`, payload.parseErrors);
      const err = new Error('ShopifyQL parse error: ' + JSON.stringify(payload.parseErrors));
      err.parseErrors = payload.parseErrors;
      throw err;
    }
    if (!payload?.tableData) {
      console.error(`[cvr-decomp] ${label} no tableData after ${ms}ms; raw:`, JSON.stringify(json).slice(0, 400));
      throw new Error(`No data returned from Shopify for ${label}`);
    }
    console.log(`[cvr-decomp] ${label} ✓ ${payload.tableData.rows.length} rows in ${ms}ms`);
    return payload.tableData;
  };

  try {
    const [a, b] = await Promise.all([
      runShopifyQL(queryA, 'period_a'),
      runShopifyQL(queryB, 'period_b'),
    ]);

    const totalMs = Date.now() - t0;
    const cappedA = a.rows.length >= ROW_LIMIT;
    const cappedB = b.rows.length >= ROW_LIMIT;
    if (cappedA || cappedB) {
      console.warn(`[cvr-decomp] ⚠ row cap hit (LIMIT ${ROW_LIMIT})`,
        { period_a_capped: cappedA, period_b_capped: cappedB });
    }
    console.log(`[cvr-decomp] ✓ done in ${totalMs}ms — A: ${a.rows.length} rows, B: ${b.rows.length} rows`);

    res.json({
      filter: { source, medium, lp_filter_raw: lpFilterRaw, lp_exact_match_pushdown: lpExactMatch },
      row_limit: ROW_LIMIT,
      capped: { period_a: cappedA, period_b: cappedB },
      period_a: { start: period_a_start, end: period_a_end, columns: a.columns, rows: a.rows, query: queryA },
      period_b: { start: period_b_start, end: period_b_end, columns: b.columns, rows: b.rows, query: queryB },
    });
  } catch (err) {
    console.error('[cvr-decomp] ✗ error:', err.message, err.parseErrors || '');
    res.status(500).json({ error: err.message, parseErrors: err.parseErrors });
  }
});

// ─────────────────────────────────────────────
// AD-SET FATIGUE DASHBOARD — main data endpoint
// ─────────────────────────────────────────────
// One round-trip that pulls and joins:
//   • Meta ad-level daily insights for [since, until] (current period)
//   • Meta ad-level totals for [compare_since, compare_until] (prior period)
//   • Meta ad-set metadata: campaign{name}, effective_status, learning_stage_info
//   • Shopify sessions/CVR for current and prior period, grouped by
//     (utm_content, landing_page_path)
//   • Shopify utm_content → Meta adset_name mapping (via ad_name)
// Returns rows shaped as { adset, campaign, lp, sessions, cvr, fatigue, ... }
// suitable for the grouped-by-LP tables.

app.get('/api/ad-set-fatigue-data', requireAuth, async (req, res) => {
  const t0 = Date.now();
  const { account_id, since, until } = req.query;
  if (!account_id || !since || !until) {
    return res.status(400).json({ error: 'account_id, since, until required (YYYY-MM-DD)' });
  }
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRe.test(since) || !dateRe.test(until)) {
    return res.status(400).json({ error: 'since/until must be YYYY-MM-DD' });
  }
  if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
    return res.status(500).json({ error: 'Shopify credentials not configured' });
  }

  // Comparison window. By default, same-length window immediately preceding
  // [since, until]. Override with explicit compare_since / compare_until
  // params from the picker when the user wants a custom comparison range
  // (e.g. month-vs-month rather than rolling-14d-vs-prior-14d).
  const autoCompare = (() => {
    const sd = new Date(since + 'T00:00:00Z');
    const ed = new Date(until + 'T00:00:00Z');
    const days = Math.round((ed - sd) / 86400000) + 1;
    const cEnd   = new Date(sd); cEnd.setUTCDate(cEnd.getUTCDate() - 1);
    const cStart = new Date(cEnd); cStart.setUTCDate(cStart.getUTCDate() - (days - 1));
    return {
      since: cStart.toISOString().slice(0, 10),
      until: cEnd.toISOString().slice(0, 10),
      days,
    };
  })();
  const cs = req.query.compare_since;
  const cu = req.query.compare_until;
  const useCustomCompare = cs && cu && dateRe.test(cs) && dateRe.test(cu);
  const auto = useCustomCompare
    ? { since: cs, until: cu, days: Math.round((new Date(cu) - new Date(cs)) / 86400000) + 1, mode: 'custom' }
    : { ...autoCompare, mode: 'auto-prev-period' };

  const source = (req.query.source || 'facebook').replace(/'/g, "\\'");
  const medium = (req.query.medium || 'paid_social').replace(/'/g, "\\'");

  console.log('\n[ad-set-fatigue] ───────────────────────────────────────────');
  console.log('[ad-set-fatigue] request', {
    account_id, since, until,
    compare_since: auto.since, compare_until: auto.until,
    compare_mode: auto.mode,
    period_days: auto.days,
    source, medium,
  });

  const proof = generateAppSecretProof(req.accessToken);
  const ensureProof = (u) => u.includes('appsecret_proof=') ? u : (u + `&appsecret_proof=${proof}`);

  const META_FIELDS = [
    'ad_id', 'ad_name', 'adset_id', 'adset_name', 'campaign_id', 'campaign_name',
    'date_start', 'date_stop',
    'spend', 'impressions', 'reach', 'frequency', 'clicks',
    'inline_link_clicks', 'cpc', 'ctr', 'outbound_clicks',
    'actions', 'action_values',
  ].join(',');

  // ────── Meta insights fetcher (paginated) ──────
  // `time_increment` controls daily vs total roll-up.
  const fetchInsights = async (s, u, increment, label) => {
    const tStart = Date.now();
    const url = `${META_BASE_URL}/${account_id}/insights`
      + `?fields=${META_FIELDS}`
      + `&time_range=${encodeURIComponent(JSON.stringify({ since: s, until: u }))}`
      + `&level=ad`
      + `&time_increment=${increment}`
      + `&filtering=${encodeURIComponent(JSON.stringify([{ field: 'spend', operator: 'GREATER_THAN', value: 0 }]))}`
      + `&limit=100`
      + `&${metaParams(req.accessToken)}`;
    const all = [];
    let next = url;
    let pages = 0;
    while (next && pages < 30) {
      const resp = await fetch(ensureProof(next));
      const data = await resp.json();
      if (data.error) {
        if (data.error.code === 190) {
          clearTokenCookie(res);
          throw Object.assign(new Error('Session expired. Please log in again.'), { status: 401 });
        }
        throw new Error(`Meta insights error (${label}): ${data.error.message || JSON.stringify(data.error)}`);
      }
      if (Array.isArray(data.data)) all.push(...data.data);
      next = data.paging?.next || null;
      pages += 1;
    }
    console.log(`[ad-set-fatigue] meta-insights ${label}: ${all.length} rows in ${Date.now() - tStart}ms (${pages} pages)`);
    return all;
  };

  // ────── Meta ad-set metadata fetcher (for learning_stage etc) ──────
  const fetchAdsetsMeta = async (adsetIds) => {
    if (!adsetIds.length) return {};
    const tStart = Date.now();
    const out = {};
    // Use batch API: 50 ad sets per batch request, multiple batches in parallel.
    const slices = [];
    for (let i = 0; i < adsetIds.length; i += 50) slices.push(adsetIds.slice(i, i + 50));
    const proof2 = generateAppSecretProof(req.accessToken);
    const ADSET_FIELDS = 'id,name,effective_status,configured_status,learning_stage_info,daily_budget,lifetime_budget';
    // NB: the outer binding here was previously named `results` and the inner
    // for-of destructured `{ slice, results }` from it — which triggered a
    // "cannot access 'results' before initialization" TDZ error in newer V8.
    // Renamed the outer to `batchResults` to remove the shadow.
    const batchResults = await Promise.all(slices.map(async (slice) => {
      const batch = slice.map(id => ({
        method: 'GET', relative_url: `${id}?fields=${ADSET_FIELDS}`,
      }));
      try {
        const body = new URLSearchParams({
          access_token: req.accessToken,
          appsecret_proof: proof2,
          batch: JSON.stringify(batch),
        });
        const resp = await fetch(`${META_BASE_URL}/`, {
          method: 'POST', body, signal: AbortSignal.timeout(20000),
        });
        return { slice, results: await resp.json() };
      } catch (e) {
        console.warn(`[ad-set-fatigue] adset batch failed:`, e.message);
        return { slice, results: null };
      }
    }));
    let ok = 0, fail = 0;
    for (const { slice, results } of batchResults) {
      if (!Array.isArray(results)) { fail += slice.length; continue; }
      for (let j = 0; j < slice.length; j++) {
        const r = results[j];
        if (r && r.code === 200) {
          try { out[slice[j]] = JSON.parse(r.body); ok++; }
          catch { fail++; }
        } else {
          fail++;
        }
      }
    }
    console.log(`[ad-set-fatigue] adset-meta: ${ok} ok / ${fail} fail in ${Date.now() - tStart}ms`);
    return out;
  };

  // ────── Shopify ShopifyQL fetcher ──────
  const fetchShopify = async (s, u, label) => {
    const tStart = Date.now();
    const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
    const gqlQuery = `query R($q:String!){shopifyqlQuery(query:$q){tableData{columns{name dataType} rows} parseErrors}}`;
    const q = `FROM sessions
  SHOW sessions, conversion_rate
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_content, landing_page_path WITH TOTALS
  SINCE ${s} UNTIL ${u}
  ORDER BY sessions DESC
  LIMIT 5000`;
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q } }),
    });
    const json = await resp.json();
    const payload = json.data?.shopifyqlQuery;
    if (payload?.parseErrors?.length) {
      console.error(`[ad-set-fatigue] shopify ${label} parseErrors:`, payload.parseErrors);
      throw new Error(`ShopifyQL ${label}: ${JSON.stringify(payload.parseErrors)}`);
    }
    const rows = payload?.tableData?.rows || [];
    console.log(`[ad-set-fatigue] shopify ${label}: ${rows.length} rows in ${Date.now() - tStart}ms`);
    return { columns: payload?.tableData?.columns || [], rows };
  };

  try {
    // Run all four queries in parallel.
    const [metaDaily, metaPriorTotals, shopifyCurr, shopifyPrev] = await Promise.all([
      fetchInsights(since, until, '1', 'current-daily'),
      fetchInsights(auto.since, auto.until, 'all_days', 'prior-total'),
      fetchShopify(since, until, 'current'),
      fetchShopify(auto.since, auto.until, 'prior'),
    ]);

    // ────── Build ad → adset mapping and per-ad daily rollup ──────
    const actionVal = (arr, type) => Array.isArray(arr)
      ? (arr.find(a => a.action_type === type)?.value ? parseFloat(arr.find(a => a.action_type === type).value) : 0)
      : 0;

    // Each row in metaDaily is one (ad, day). Roll up into adset → daily series.
    // adsetId → { adset_name, campaign_id, campaign_name, ad_ids:Set, ad_names:Set, daily: Map(date → agg) }
    const adsetCurr = new Map();
    const adNameToAdsetName = new Map();   // utm_content lookup key
    let droppedNoAdset = 0;
    for (const r of metaDaily) {
      if (!r.adset_id) { droppedNoAdset++; continue; }
      const id = r.adset_id;
      let entry = adsetCurr.get(id);
      if (!entry) {
        entry = {
          adset_id: id,
          adset_name: r.adset_name || '(unnamed)',
          campaign_id: r.campaign_id,
          campaign_name: r.campaign_name || '',
          ad_ids: new Set(),
          ad_names: new Set(),
          daily: new Map(),
          // Pick a representative ad_id for previews (first encountered).
          rep_ad_id: r.ad_id,
          rep_ad_name: r.ad_name || '',
        };
        adsetCurr.set(id, entry);
      }
      if (r.ad_id) entry.ad_ids.add(r.ad_id);
      if (r.ad_name) {
        entry.ad_names.add(r.ad_name);
        adNameToAdsetName.set(r.ad_name, entry.adset_name);
      }
      const date = r.date_start || r.date_stop || 'unknown';
      const dayAgg = entry.daily.get(date) || {
        date, spend: 0, impressions: 0, reach: 0, clicks: 0, link_clicks: 0,
        outbound_clicks: 0, purchases: 0, purchase_value: 0,
      };
      dayAgg.spend       += parseFloat(r.spend) || 0;
      dayAgg.impressions += parseFloat(r.impressions) || 0;
      dayAgg.reach       += parseFloat(r.reach) || 0;
      dayAgg.clicks      += parseFloat(r.clicks) || 0;
      dayAgg.link_clicks += parseFloat(r.inline_link_clicks) || 0;
      dayAgg.outbound_clicks += actionVal(r.outbound_clicks, 'outbound_click');
      dayAgg.purchases       += actionVal(r.actions, 'omni_purchase')
        || actionVal(r.actions, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.actions, 'purchase');
      dayAgg.purchase_value  += actionVal(r.action_values, 'omni_purchase')
        || actionVal(r.action_values, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.action_values, 'purchase');
      entry.daily.set(date, dayAgg);
    }
    console.log(`[ad-set-fatigue] meta rollup: ${adsetCurr.size} ad sets, ${adNameToAdsetName.size} ad-name map entries (dropped ${droppedNoAdset} rows w/o adset_id)`);

    // ────── Prior-period totals per adset ──────
    const adsetPrior = new Map();   // adset_id → totals
    for (const r of metaPriorTotals) {
      if (!r.adset_id) continue;
      const id = r.adset_id;
      const cur = adsetPrior.get(id) || {
        spend: 0, impressions: 0, clicks: 0, link_clicks: 0,
        outbound_clicks: 0, purchases: 0, purchase_value: 0,
      };
      cur.spend       += parseFloat(r.spend) || 0;
      cur.impressions += parseFloat(r.impressions) || 0;
      cur.clicks      += parseFloat(r.clicks) || 0;
      cur.link_clicks += parseFloat(r.inline_link_clicks) || 0;
      cur.outbound_clicks += actionVal(r.outbound_clicks, 'outbound_click');
      cur.purchases       += actionVal(r.actions, 'omni_purchase')
        || actionVal(r.actions, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.actions, 'purchase');
      cur.purchase_value  += actionVal(r.action_values, 'omni_purchase')
        || actionVal(r.action_values, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.action_values, 'purchase');
      adsetPrior.set(id, cur);
    }

    // ────── Adset metadata (learning stage etc) ──────
    const adsetIds = [...adsetCurr.keys()];
    const adsetMeta = await fetchAdsetsMeta(adsetIds);

    // ────── Parse Shopify rows → keyed by (utm_content, lp) ──────
    const parseShopifyRows = (block) => {
      const cols = (block.columns || []).map(c => (c.name || '').toLowerCase());
      const iAd  = cols.indexOf('utm_content');
      const iLp  = cols.indexOf('landing_page_path');
      const iSess= cols.indexOf('sessions');
      const iCvr = cols.indexOf('conversion_rate');
      const get  = (row, idx) => Array.isArray(row) ? row[idx] : row[block.columns[idx].name];
      const out = [];
      for (const row of (block.rows || [])) {
        const ad = String(get(row, iAd) ?? '').trim();
        const lp = String(get(row, iLp) ?? '').trim();
        if (!ad || !lp) continue;
        const sess = parseFloat(get(row, iSess)) || 0;
        const cvrRaw = parseFloat(get(row, iCvr)) || 0;
        const cvr = cvrRaw > 1 ? cvrRaw / 100 : cvrRaw;
        out.push({ utm_content: ad, lp, sessions: Math.round(sess), cvr, orders: Math.round(sess * cvr) });
      }
      return out;
    };
    const shopCurr = parseShopifyRows(shopifyCurr);
    const shopPrev = parseShopifyRows(shopifyPrev);
    console.log(`[ad-set-fatigue] shopify parsed: curr=${shopCurr.length} prev=${shopPrev.length}`);

    // ────── Map Shopify utm_content → adset_name ──────
    // The convention here: utm_content IS the full Meta ad name. So we look it
    // up directly in our ad_name map. Anything we can't map gets bucketed
    // into an "(unmapped)" pseudo-adset so it's visible, not silently dropped.
    const aggregateByAdsetLp = (rows, label) => {
      const map = new Map();   // key = adset_name + '||' + lp
      let mapped = 0, unmapped = 0;
      for (const r of rows) {
        const adsetName = adNameToAdsetName.get(r.utm_content) || '(unmapped)';
        if (adsetName === '(unmapped)') unmapped++;
        else mapped++;
        const k = adsetName + '||' + r.lp;
        const cur = map.get(k) || { adset_name: adsetName, lp: r.lp, sessions: 0, orders: 0 };
        cur.sessions += r.sessions;
        cur.orders   += r.orders;
        map.set(k, cur);
      }
      for (const v of map.values()) {
        v.cvr = v.sessions > 0 ? v.orders / v.sessions : 0;
      }
      console.log(`[ad-set-fatigue] shopify-aggregate ${label}: mapped=${mapped} unmapped=${unmapped} (utm_content not in current Meta data)`);
      return map;
    };
    const shopCurrAgg = aggregateByAdsetLp(shopCurr, 'current');
    const shopPrevAgg = aggregateByAdsetLp(shopPrev, 'prior');

    // ────── Compute fatigue per adset + build output rows ──────
    const out = [];
    let scoredCount = 0, healthyCount = 0, watchingCount = 0, fatiguingCount = 0,
        fatiguedCount = 0, replaceNowCount = 0, unscoredCount = 0;

    // Build a quick adset_name → adset object lookup so we can also emit rows
    // for adsets that have Shopify sessions but were excluded by the spend>0
    // Meta filter (rare).
    const adsetByName = new Map();
    for (const a of adsetCurr.values()) adsetByName.set(a.adset_name, a);

    // Iterate Shopify-aggregated keys (every (adset, lp) with sessions in EITHER
    // period). This is the natural unit for the grouped-by-LP table.
    //
    // Drop long-tail rows: any (adset × LP) combo with fewer than
    // MIN_SESSIONS sessions in the CURRENT period is ignored. Tiny session
    // counts produce noisy CVR comparisons and clutter the LP-grouped tables;
    // 100 is the same threshold used by the CVR Decomposition tool.
    const MIN_SESSIONS = 100;
    const allKeys = new Set([...shopCurrAgg.keys(), ...shopPrevAgg.keys()]);
    let droppedLowSess = 0;
    for (const key of allKeys) {
      const curr = shopCurrAgg.get(key) || { sessions: 0, orders: 0, cvr: 0 };
      const prev = shopPrevAgg.get(key) || { sessions: 0, orders: 0, cvr: 0 };
      if ((curr.sessions || 0) < MIN_SESSIONS) {
        droppedLowSess++;
        continue;
      }
      const adsetName = (curr.adset_name || prev.adset_name);
      const lp = (curr.lp || prev.lp);

      // Resolve the Meta side
      const adsetEntry = adsetByName.get(adsetName);
      let fatigue = { score: null, state: 'unknown', signals: {}, reason: 'no_meta_data' };
      let metaCurr = { spend: 0, impressions: 0, clicks: 0, link_clicks: 0, outbound_clicks: 0,
                       reach: 0, purchases: 0, purchase_value: 0 };
      let metaPrev = adsetPrior.get(adsetEntry?.adset_id) || { spend: 0, impressions: 0, clicks: 0,
                       link_clicks: 0, outbound_clicks: 0, purchases: 0, purchase_value: 0 };
      let learning = null;
      let effective_status = null;
      let configured_status = null;
      let rep_ad_id = null;
      let campaign_name = '';
      let campaign_id = null;

      if (adsetEntry) {
        rep_ad_id = adsetEntry.rep_ad_id;
        campaign_id = adsetEntry.campaign_id;
        campaign_name = adsetEntry.campaign_name;
        // Aggregate adset's daily series from Map values
        const dailySorted = [...adsetEntry.daily.values()].sort((a, b) => (a.date < b.date ? -1 : 1));
        for (const d of dailySorted) {
          metaCurr.spend       += d.spend;
          metaCurr.impressions += d.impressions;
          metaCurr.clicks      += d.clicks;
          metaCurr.link_clicks += d.link_clicks;
          metaCurr.outbound_clicks += d.outbound_clicks;
          metaCurr.reach       += d.reach;        // NB: sum is approximate vs unique-reach
          metaCurr.purchases   += d.purchases;
          metaCurr.purchase_value += d.purchase_value;
        }
        fatigue = computeFatigueScore(dailySorted, null);
        const meta = adsetMeta[adsetEntry.adset_id];
        if (meta) {
          learning = meta.learning_stage_info?.status || null;
          effective_status = meta.effective_status || null;
          configured_status = meta.configured_status || null;
        }
      }

      const isTesting = /testing/i.test(campaign_name);
      const row = {
        adset_id: adsetEntry?.adset_id || null,
        adset_name: adsetName,
        campaign_id, campaign_name,
        is_testing: isTesting,
        landing_page_path: lp,
        learning_stage: learning,
        effective_status, configured_status,
        rep_ad_id,
        // Shopify metrics
        sessions: curr.sessions,
        prev_sessions: prev.sessions,
        cvr: curr.cvr,
        prev_cvr: prev.cvr,
        orders: curr.orders,
        prev_orders: prev.orders,
        // Meta metrics
        spend: metaCurr.spend,
        prev_spend: metaPrev.spend,
        impressions: metaCurr.impressions,
        clicks: metaCurr.clicks,
        link_clicks: metaCurr.link_clicks,
        outbound_clicks: metaCurr.outbound_clicks,
        prev_outbound_clicks: metaPrev.outbound_clicks,
        meta_purchases: metaCurr.purchases,
        meta_purchase_value: metaCurr.purchase_value,
        // Fatigue
        fatigue,
      };
      out.push(row);

      if (fatigue.score == null) unscoredCount++;
      else {
        scoredCount++;
        if (fatigue.state === 'healthy') healthyCount++;
        else if (fatigue.state === 'watching') watchingCount++;
        else if (fatigue.state === 'fatiguing') fatiguingCount++;
        else if (fatigue.state === 'fatigued') fatiguedCount++;
        else if (fatigue.state === 'replace_now') replaceNowCount++;
      }
    }

    const summary = {
      rows: out.length,
      dropped_low_sessions: droppedLowSess,
      min_sessions_threshold: MIN_SESSIONS,
      scored: scoredCount,
      unscored: unscoredCount,
      states: {
        healthy: healthyCount,
        watching: watchingCount,
        fatiguing: fatiguingCount,
        fatigued: fatiguedCount,
        replace_now: replaceNowCount,
      },
      total_ms: Date.now() - t0,
    };
    console.log('[ad-set-fatigue] summary', summary);

    res.json({
      account_id, since, until,
      compare: { since: auto.since, until: auto.until, days: auto.days, mode: auto.mode },
      filter: { source, medium },
      meta_counts: {
        meta_daily_rows: metaDaily.length,
        meta_prior_rows: metaPriorTotals.length,
        adsets_current: adsetCurr.size,
        adsets_meta_resolved: Object.keys(adsetMeta).length,
        ad_name_map_size: adNameToAdsetName.size,
        shopify_curr_rows: shopCurr.length,
        shopify_prev_rows: shopPrev.length,
      },
      summary,
      rows: out,
    });
  } catch (err) {
    console.error('[ad-set-fatigue] ✗', err.message, err.stack ? '\n' + err.stack.split('\n').slice(0, 5).join('\n') : '');
    if (err.status === 401) return res.status(401).json({ error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────
// CREATIVE FATIGUE — per-AD scoring
// ─────────────────────────────────────────────
// Same 6-signal fatigue formula as the ad-set tab, but applied at the ad
// level. Why: fatigue is a creative phenomenon — a specific video/image
// gets old, the audience has seen it too many times, the auction starts
// punishing it. Ad sets don't fatigue; the creatives inside them do.
//
// Output is one row per ad, with adset/campaign context for grouping. The
// frontend rolls up per ad set to show "X creatives — Y healthy, Z fatigued"
// and computes a healthy-capacity / runway projection.

app.get('/api/creative-fatigue-data', requireAuth, async (req, res) => {
  const t0 = Date.now();
  const { account_id, since, until } = req.query;
  if (!account_id || !since || !until) {
    return res.status(400).json({ error: 'account_id, since, until required (YYYY-MM-DD)' });
  }
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRe.test(since) || !dateRe.test(until)) {
    return res.status(400).json({ error: 'since/until must be YYYY-MM-DD' });
  }

  // Comparison window — same convention as the ad-set tab.
  const autoCompare = (() => {
    const sd = new Date(since + 'T00:00:00Z');
    const ed = new Date(until + 'T00:00:00Z');
    const days = Math.round((ed - sd) / 86400000) + 1;
    const cEnd   = new Date(sd); cEnd.setUTCDate(cEnd.getUTCDate() - 1);
    const cStart = new Date(cEnd); cStart.setUTCDate(cStart.getUTCDate() - (days - 1));
    return {
      since: cStart.toISOString().slice(0, 10),
      until: cEnd.toISOString().slice(0, 10),
      days,
    };
  })();
  const cs = req.query.compare_since;
  const cu = req.query.compare_until;
  const useCustomCompare = cs && cu && dateRe.test(cs) && dateRe.test(cu);
  const auto = useCustomCompare
    ? { since: cs, until: cu, days: Math.round((new Date(cu) - new Date(cs)) / 86400000) + 1, mode: 'custom' }
    : { ...autoCompare, mode: 'auto-prev-period' };

  // Optional Shopify join for sessions/CVR per ad. Off by default to keep
  // the request fast; the dashboard's primary metrics are Meta-side.
  const includeShopify = req.query.include_shopify === '1' || req.query.include_shopify === 'true';
  const source = (req.query.source || 'facebook').replace(/'/g, "\\'");
  const medium = (req.query.medium || 'paid_social').replace(/'/g, "\\'");

  // Min daily spend filter (in last 7 days, $/day average). Replaces the
  // session threshold from the ad-set tab — for creative fatigue, the
  // signal-to-noise threshold is "is this ad even getting meaningful spend".
  const minDailySpend = parseFloat(req.query.min_daily_spend || '5');

  console.log('\n[creative-fatigue] ──────────────────────────────────────────');
  console.log('[creative-fatigue] request', {
    account_id, since, until,
    compare_since: auto.since, compare_until: auto.until, compare_mode: auto.mode,
    period_days: auto.days,
    include_shopify: includeShopify,
    min_daily_spend: minDailySpend,
    source: includeShopify ? source : '(skipped)',
    medium: includeShopify ? medium : '(skipped)',
  });

  const proof = generateAppSecretProof(req.accessToken);
  const ensureProof = (u) => u.includes('appsecret_proof=') ? u : (u + `&appsecret_proof=${proof}`);

  const META_FIELDS = [
    'ad_id', 'ad_name', 'adset_id', 'adset_name', 'campaign_id', 'campaign_name',
    'date_start', 'date_stop',
    'spend', 'impressions', 'reach', 'frequency', 'clicks',
    'inline_link_clicks', 'cpc', 'ctr', 'outbound_clicks',
    'actions', 'action_values',
  ].join(',');

  const fetchInsights = async (s, u, increment, label) => {
    const tStart = Date.now();
    const url = `${META_BASE_URL}/${account_id}/insights`
      + `?fields=${META_FIELDS}`
      + `&time_range=${encodeURIComponent(JSON.stringify({ since: s, until: u }))}`
      + `&level=ad`
      + `&time_increment=${increment}`
      + `&filtering=${encodeURIComponent(JSON.stringify([{ field: 'spend', operator: 'GREATER_THAN', value: 0 }]))}`
      + `&limit=100`
      + `&${metaParams(req.accessToken)}`;
    const all = [];
    let next = url;
    let pages = 0;
    while (next && pages < 50) {
      const resp = await fetch(ensureProof(next));
      const data = await resp.json();
      if (data.error) {
        if (data.error.code === 190) {
          clearTokenCookie(res);
          throw Object.assign(new Error('Session expired. Please log in again.'), { status: 401 });
        }
        throw new Error(`Meta insights error (${label}): ${data.error.message || JSON.stringify(data.error)}`);
      }
      if (Array.isArray(data.data)) all.push(...data.data);
      next = data.paging?.next || null;
      pages += 1;
    }
    console.log(`[creative-fatigue] meta-insights ${label}: ${all.length} rows in ${Date.now() - tStart}ms (${pages} pages)`);
    return all;
  };

  // Batch-fetch ad created_time so we can show "days running."
  const fetchAdMeta = async (adIds) => {
    if (!adIds.length) return {};
    const tStart = Date.now();
    const out = {};
    const slices = [];
    for (let i = 0; i < adIds.length; i += 50) slices.push(adIds.slice(i, i + 50));
    const proof2 = generateAppSecretProof(req.accessToken);
    const batchResults = await Promise.all(slices.map(async (slice) => {
      const batch = slice.map(id => ({
        method: 'GET', relative_url: `${id}?fields=created_time,effective_status,configured_status`,
      }));
      try {
        const body = new URLSearchParams({
          access_token: req.accessToken,
          appsecret_proof: proof2,
          batch: JSON.stringify(batch),
        });
        const resp = await fetch(`${META_BASE_URL}/`, {
          method: 'POST', body, signal: AbortSignal.timeout(20000),
        });
        return { slice, results: await resp.json() };
      } catch (e) {
        console.warn(`[creative-fatigue] ad-meta batch failed:`, e.message);
        return { slice, results: null };
      }
    }));
    let ok = 0, fail = 0;
    for (const { slice, results } of batchResults) {
      if (!Array.isArray(results)) { fail += slice.length; continue; }
      for (let j = 0; j < slice.length; j++) {
        const r = results[j];
        if (r && r.code === 200) {
          try { out[slice[j]] = JSON.parse(r.body); ok++; }
          catch { fail++; }
        } else {
          fail++;
        }
      }
    }
    console.log(`[creative-fatigue] ad-meta: ${ok} ok / ${fail} fail in ${Date.now() - tStart}ms`);
    return out;
  };

  // Optional Shopify pull (only when include_shopify=1).
  const fetchShopify = async (s, u, label) => {
    if (!includeShopify) return null;
    if (!SHOPIFY_URL || !SHOPIFY_TOKEN) {
      console.warn('[creative-fatigue] Shopify creds missing — skipping join');
      return null;
    }
    const tStart = Date.now();
    const endpoint = `https://${SHOPIFY_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
    const gqlQuery = `query R($q:String!){shopifyqlQuery(query:$q){tableData{columns{name dataType} rows} parseErrors}}`;
    const q = `FROM sessions
  SHOW sessions, conversion_rate
  WHERE utm_source = '${source}' AND utm_medium = '${medium}'
  GROUP BY utm_content WITH TOTALS
  SINCE ${s} UNTIL ${u}
  ORDER BY sessions DESC
  LIMIT 5000`;
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q } }),
    });
    const json = await resp.json();
    const payload = json.data?.shopifyqlQuery;
    if (payload?.parseErrors?.length) {
      console.error(`[creative-fatigue] shopify ${label} parseErrors:`, payload.parseErrors);
      return null;
    }
    const rows = payload?.tableData?.rows || [];
    console.log(`[creative-fatigue] shopify ${label}: ${rows.length} rows in ${Date.now() - tStart}ms`);
    return { columns: payload?.tableData?.columns || [], rows };
  };

  try {
    const [metaDaily, metaPriorTotals, shopCurrBlock, shopPrevBlock] = await Promise.all([
      fetchInsights(since, until, '1', 'current-daily'),
      fetchInsights(auto.since, auto.until, 'all_days', 'prior-total'),
      fetchShopify(since, until, 'current'),
      fetchShopify(auto.since, auto.until, 'prior'),
    ]);

    // ────── Per-ad rollup of current daily series ──────
    const actionVal = (arr, type) => Array.isArray(arr)
      ? (arr.find(a => a.action_type === type)?.value ? parseFloat(arr.find(a => a.action_type === type).value) : 0)
      : 0;

    // adId → { ad_name, adset_id, adset_name, campaign_id, campaign_name,
    //          daily: Map(date → agg) }
    const adsCurr = new Map();
    let droppedNoAdId = 0;
    for (const r of metaDaily) {
      if (!r.ad_id) { droppedNoAdId++; continue; }
      const id = r.ad_id;
      let entry = adsCurr.get(id);
      if (!entry) {
        entry = {
          ad_id: id,
          ad_name: r.ad_name || '',
          adset_id: r.adset_id, adset_name: r.adset_name || '(unknown)',
          campaign_id: r.campaign_id, campaign_name: r.campaign_name || '',
          daily: new Map(),
        };
        adsCurr.set(id, entry);
      }
      const date = r.date_start || r.date_stop || 'unknown';
      const dayAgg = entry.daily.get(date) || {
        date, spend: 0, impressions: 0, reach: 0, clicks: 0, link_clicks: 0,
        outbound_clicks: 0, purchases: 0, purchase_value: 0,
      };
      dayAgg.spend       += parseFloat(r.spend) || 0;
      dayAgg.impressions += parseFloat(r.impressions) || 0;
      dayAgg.reach       += parseFloat(r.reach) || 0;
      dayAgg.clicks      += parseFloat(r.clicks) || 0;
      dayAgg.link_clicks += parseFloat(r.inline_link_clicks) || 0;
      dayAgg.outbound_clicks += actionVal(r.outbound_clicks, 'outbound_click');
      dayAgg.purchases       += actionVal(r.actions, 'omni_purchase')
        || actionVal(r.actions, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.actions, 'purchase');
      dayAgg.purchase_value  += actionVal(r.action_values, 'omni_purchase')
        || actionVal(r.action_values, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.action_values, 'purchase');
      entry.daily.set(date, dayAgg);
    }
    console.log(`[creative-fatigue] meta rollup: ${adsCurr.size} ads (dropped ${droppedNoAdId} rows w/o ad_id)`);

    // ────── Prior-period totals per ad ──────
    const adsPrior = new Map();
    for (const r of metaPriorTotals) {
      if (!r.ad_id) continue;
      const id = r.ad_id;
      const cur = adsPrior.get(id) || {
        spend: 0, impressions: 0, clicks: 0, link_clicks: 0,
        outbound_clicks: 0, purchases: 0, purchase_value: 0,
      };
      cur.spend       += parseFloat(r.spend) || 0;
      cur.impressions += parseFloat(r.impressions) || 0;
      cur.clicks      += parseFloat(r.clicks) || 0;
      cur.link_clicks += parseFloat(r.inline_link_clicks) || 0;
      cur.outbound_clicks += actionVal(r.outbound_clicks, 'outbound_click');
      cur.purchases       += actionVal(r.actions, 'omni_purchase')
        || actionVal(r.actions, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.actions, 'purchase');
      cur.purchase_value  += actionVal(r.action_values, 'omni_purchase')
        || actionVal(r.action_values, 'offsite_conversion.fb_pixel_purchase')
        || actionVal(r.action_values, 'purchase');
      adsPrior.set(id, cur);
    }

    // ────── Ad metadata (created_time, status) ──────
    const adIds = [...adsCurr.keys()];
    const adMeta = await fetchAdMeta(adIds);

    // ────── Optional Shopify join ──────
    const parseShopifyByAd = (block) => {
      if (!block) return new Map();
      const cols = (block.columns || []).map(c => (c.name || '').toLowerCase());
      const iAd  = cols.indexOf('utm_content');
      const iSess= cols.indexOf('sessions');
      const iCvr = cols.indexOf('conversion_rate');
      const get  = (row, idx) => Array.isArray(row) ? row[idx] : row[block.columns[idx].name];
      const map = new Map();
      for (const row of (block.rows || [])) {
        const ad = String(get(row, iAd) ?? '').trim();
        if (!ad) continue;
        const sess = parseFloat(get(row, iSess)) || 0;
        const cvrRaw = parseFloat(get(row, iCvr)) || 0;
        const cvr = cvrRaw > 1 ? cvrRaw / 100 : cvrRaw;
        const orders = Math.round(sess * cvr);
        // ShopifyQL groups by utm_content — should already be unique. Defend anyway.
        const prev = map.get(ad);
        if (prev) {
          const totalSess = prev.sessions + Math.round(sess);
          const totalOrd  = prev.orders + orders;
          map.set(ad, { sessions: totalSess, orders: totalOrd, cvr: totalSess > 0 ? totalOrd / totalSess : 0 });
        } else {
          map.set(ad, { sessions: Math.round(sess), orders, cvr });
        }
      }
      return map;
    };
    const shopCurr = parseShopifyByAd(shopCurrBlock);
    const shopPrev = parseShopifyByAd(shopPrevBlock);
    if (includeShopify) {
      console.log(`[creative-fatigue] shopify joined: ${shopCurr.size} curr / ${shopPrev.size} prev (key = utm_content)`);
    }

    // ────── Score every ad + filter by min daily spend ──────
    const out = [];
    let kept = 0, droppedSpend = 0;
    let spendByState = { healthy: 0, watching: 0, fatiguing: 0, fatigued: 0, replace_now: 0, unknown: 0 };
    let countByState = { healthy: 0, watching: 0, fatiguing: 0, fatigued: 0, replace_now: 0, unknown: 0 };

    for (const ad of adsCurr.values()) {
      const dailySorted = [...ad.daily.values()].sort((a, b) => (a.date < b.date ? -1 : 1));
      const last7 = dailySorted.slice(-7);
      const totalSpend = dailySorted.reduce((s, x) => s + x.spend, 0);
      const last7Spend = last7.reduce((s, x) => s + x.spend, 0);
      const dailyAvgLast7 = last7.length > 0 ? last7Spend / last7.length : 0;

      if (dailyAvgLast7 < minDailySpend) {
        droppedSpend++;
        continue;
      }
      kept++;

      const fatigue = computeFatigueScore(dailySorted, null);
      const meta = adMeta[ad.ad_id] || {};
      const created = meta.created_time ? new Date(meta.created_time) : null;
      const daysRunning = created ? Math.round((Date.now() - created.getTime()) / 86400000) : null;

      const prior = adsPrior.get(ad.ad_id) || { spend: 0, impressions: 0, clicks: 0, link_clicks: 0,
                                                outbound_clicks: 0, purchases: 0, purchase_value: 0 };

      const totalImpr = dailySorted.reduce((s, x) => s + x.impressions, 0);
      const totalClicks = dailySorted.reduce((s, x) => s + x.clicks, 0);
      const totalLinkClicks = dailySorted.reduce((s, x) => s + x.link_clicks, 0);
      const totalOutbound = dailySorted.reduce((s, x) => s + x.outbound_clicks, 0);
      const totalPurchases = dailySorted.reduce((s, x) => s + x.purchases, 0);
      const totalPurchaseValue = dailySorted.reduce((s, x) => s + x.purchase_value, 0);
      const totalReachSum = dailySorted.reduce((s, x) => s + x.reach, 0);

      const isTesting = /testing/i.test(ad.campaign_name);
      const sCurr = shopCurr.get(ad.ad_name);
      const sPrev = shopPrev.get(ad.ad_name);

      const row = {
        ad_id: ad.ad_id,
        ad_name: ad.ad_name,
        adset_id: ad.adset_id, adset_name: ad.adset_name,
        campaign_id: ad.campaign_id, campaign_name: ad.campaign_name,
        is_testing: isTesting,
        created_time: meta.created_time || null,
        days_running: daysRunning,
        effective_status: meta.effective_status || null,
        configured_status: meta.configured_status || null,
        // Current period totals
        spend: totalSpend,
        prev_spend: prior.spend,
        last7_spend: last7Spend,
        daily_avg_spend_last7: dailyAvgLast7,
        impressions: totalImpr,
        clicks: totalClicks,
        link_clicks: totalLinkClicks,
        outbound_clicks: totalOutbound,
        prev_outbound_clicks: prior.outbound_clicks,
        reach_sum: totalReachSum,                  // sum across days, NOT unique
        meta_purchases: totalPurchases,
        meta_purchase_value: totalPurchaseValue,
        meta_roas: totalSpend > 0 ? totalPurchaseValue / totalSpend : null,
        // Optional Shopify
        sessions: sCurr?.sessions || null,
        prev_sessions: sPrev?.sessions || null,
        cvr: sCurr?.cvr || null,
        prev_cvr: sPrev?.cvr || null,
        orders: sCurr?.orders || null,
        prev_orders: sPrev?.orders || null,
        // Fatigue
        fatigue,
      };

      out.push(row);
      const st = fatigue.state || 'unknown';
      countByState[st] = (countByState[st] || 0) + 1;
      spendByState[st] = (spendByState[st] || 0) + dailyAvgLast7;
    }

    const summary = {
      total_ads: out.length,
      dropped_low_spend: droppedSpend,
      min_daily_spend: minDailySpend,
      counts: countByState,
      daily_spend_by_state: {
        healthy:     +spendByState.healthy.toFixed(2),
        watching:    +spendByState.watching.toFixed(2),
        fatiguing:   +spendByState.fatiguing.toFixed(2),
        fatigued:    +spendByState.fatigued.toFixed(2),
        replace_now: +spendByState.replace_now.toFixed(2),
        unknown:     +spendByState.unknown.toFixed(2),
      },
      total_daily_spend: +Object.values(spendByState).reduce((s, x) => s + x, 0).toFixed(2),
      total_ms: Date.now() - t0,
    };
    console.log('[creative-fatigue] summary', summary);

    res.json({
      account_id, since, until,
      compare: { since: auto.since, until: auto.until, days: auto.days, mode: auto.mode },
      filter: {
        source: includeShopify ? source : null,
        medium: includeShopify ? medium : null,
        include_shopify: includeShopify,
        min_daily_spend: minDailySpend,
      },
      meta_counts: {
        meta_daily_rows: metaDaily.length,
        meta_prior_rows: metaPriorTotals.length,
        ads_current: adsCurr.size,
        ads_meta_resolved: Object.keys(adMeta).length,
        shopify_curr_rows: shopCurr.size,
        shopify_prev_rows: shopPrev.size,
      },
      summary,
      rows: out,
    });
  } catch (err) {
    console.error('[creative-fatigue] ✗', err.message, err.stack ? '\n' + err.stack.split('\n').slice(0, 5).join('\n') : '');
    if (err.status === 401) return res.status(401).json({ error: err.message });
    res.status(500).json({ error: err.message });
  }
});

// --- Start server ---

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

module.exports = app;
