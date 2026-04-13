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

  const shopifyql = `FROM sessions
  SHOW sessions, conversion_rate
  GROUP BY ONLY TOP 20 utm_source, ONLY TOP 20 landing_page_path WITH
    GROUP_TOTALS, TOTALS, PERCENT_CHANGE
  SINCE ${start} UNTIL ${end}
  COMPARE TO previous_period
  ORDER BY conversion_rate__utm_source_totals DESC, conversion_rate DESC,
    utm_source ASC, landing_page_path ASC
VISUALIZE conversion_rate`;

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': SHOPIFY_TOKEN },
      body: JSON.stringify({ query: gqlQuery, variables: { q: shopifyql } }),
    });
    const json = await response.json();
    const payload = json.data?.shopifyqlQuery;

    if (payload?.parseErrors?.length) {
      return res.status(400).json({ error: 'ShopifyQL parse error', details: payload.parseErrors });
    }
    if (!payload?.tableData) {
      return res.status(500).json({ error: 'No data returned from Shopify' });
    }

    res.json({
      columns: payload.tableData.columns,
      rows: payload.tableData.rows,
    });
  } catch (err) {
    console.error('Conversion impact data error:', err);
    res.status(500).json({ error: 'Failed to fetch Shopify data' });
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
