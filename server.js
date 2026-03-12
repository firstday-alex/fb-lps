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

    // Step 3: Fetch creative details for each ad in parallel
    const adsWithCreatives = await Promise.all(
      ads.map(async (ad) => {
        try {
          // Fetch creative with multiple URL-related fields
          const creativeUrl = `${META_BASE_URL}/${ad.ad_id}`
            + `?fields=creative{id,name,thumbnail_url,image_url,object_story_spec,asset_feed_spec,link_url,effective_object_story_id}`
            + `&${metaParams(req.accessToken)}`;

          const creativeResponse = await fetch(creativeUrl);
          const creativeData = await creativeResponse.json();

          if (creativeData.error) {
            console.error(`Creative API error for ad ${ad.ad_id}:`, creativeData.error.message);
          }

          const creative = creativeData.creative || {};
          const storySpec = creative.object_story_spec || {};
          const assetFeed = creative.asset_feed_spec || {};

          let destinationUrl = extractDestinationUrl(storySpec)
            || extractAssetFeedUrl(assetFeed)
            || creative.link_url
            || null;

          // For partnership/post-based ads, fetch the creative directly for more fields
          if (!destinationUrl && creative.id) {
            try {
              const directCreativeUrl = `${META_BASE_URL}/${creative.id}`
                + `?fields=link_url,object_url,object_story_spec`
                + `&${metaParams(req.accessToken)}`;
              const directCreativeResponse = await fetch(directCreativeUrl);
              const directCreativeData = await directCreativeResponse.json();

              if (!directCreativeData.error) {
                destinationUrl = directCreativeData.link_url
                  || directCreativeData.object_url
                  || extractDestinationUrl(directCreativeData.object_story_spec || {})
                  || null;
              }
            } catch (e) {}
          }

          // Fallback 1: Read the page post attachments using page access token
          let attachmentFallbackUrl = null;
          if (!destinationUrl && creative.effective_object_story_id) {
            const pageId = creative.effective_object_story_id.split('_')[0];
            const pageToken = pageTokenMap[pageId];

            if (pageToken) {
              try {
                const attachUrl = `${META_BASE_URL}/${creative.effective_object_story_id}/attachments`
                  + `?fields=url,unshimmed_url,target,type,subattachments`
                  + `&access_token=${encodeURIComponent(pageToken)}&appsecret_proof=${generateAppSecretProof(pageToken)}`;
                const attachResponse = await fetch(attachUrl);
                const attachData = await attachResponse.json();

                if (attachData.data?.[0]) {
                  const att = attachData.data[0];
                  let candidateUrl = att.unshimmed_url || att.url || att.target?.url || null;
                  if (!candidateUrl && att.subattachments?.data?.[0]) {
                    const sub = att.subattachments.data[0];
                    candidateUrl = sub.unshimmed_url || sub.url || sub.target?.url || null;
                  }
                  if (candidateUrl) {
                    // Use external URLs directly, save facebook.com URLs as last resort
                    if (!candidateUrl.includes('facebook.com/') && !candidateUrl.includes('fb.com/')) {
                      destinationUrl = candidateUrl;
                    } else {
                      attachmentFallbackUrl = candidateUrl;
                    }
                  }
                }
              } catch (e) {}
            }
          }

          // Fallback 2: Extract CTA URL from ad preview iframe
          if (!destinationUrl) {
            const formats = ['DESKTOP_FEED_STANDARD', 'MOBILE_FEED_STANDARD'];
            for (const format of formats) {
              if (destinationUrl) break;
              try {
                const previewUrl = `${META_BASE_URL}/${ad.ad_id}/previews`
                  + `?ad_format=${format}`
                  + `&${metaParams(req.accessToken)}`;
                const previewResponse = await fetch(previewUrl);
                const previewData = await previewResponse.json();

                if (previewData.data?.[0]?.body) {
                  const body = previewData.data[0].body.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

                  // Try to extract destination URL directly from the preview HTML/JSON
                  // Look for external URLs in href attributes
                  const allHrefs = body.match(/href="(https?:\/\/[^"]+)"/g) || [];
                  const externalHrefs = allHrefs
                    .map(m => m.match(/href="([^"]+)"/)[1])
                    .map(u => { try { return decodeURIComponent(u); } catch { return u; } })
                    .filter(u => !u.includes('facebook.com') && !u.includes('fbcdn.net') && !u.includes('fb.com') && !u.includes('fbsbx.com'));

                  if (externalHrefs[0]) {
                    destinationUrl = externalHrefs[0];
                    break;
                  }

                  // Try loading the iframe
                  const iframeSrcMatch = body.match(/src="(https?:\/\/[^"]+)"/);
                  if (iframeSrcMatch) {
                    const iframeUrl = iframeSrcMatch[1];
                    const iframeResponse = await fetch(iframeUrl);
                    const iframeHtml = await iframeResponse.text();

                    // Extract URLs from l.facebook.com redirect links
                    const redirectMatches = iframeHtml.match(/l\.facebook\.com\/l\.php\?u=([^&"]+)/g) || [];
                    const redirectUrls = redirectMatches
                      .map(m => { try { return decodeURIComponent(m.split('u=')[1]); } catch { return null; } })
                      .filter(Boolean);

                    if (redirectUrls[0]) {
                      destinationUrl = redirectUrls[0];
                    } else {
                      const urlMatches = iframeHtml.match(/href="(https?:\/\/[^"]+)"/g) || [];
                      const extUrls = urlMatches
                        .map(m => m.match(/href="([^"]+)"/)[1])
                        .map(u => { try { return decodeURIComponent(u); } catch { return u; } })
                        .filter(u => !u.includes('facebook.com') && !u.includes('fbcdn.net') && !u.includes('fb.com'));
                      destinationUrl = extUrls[0] || null;
                    }
                  }
                }
              } catch (e) {}
            }
          }

          // Fallback 3: Try extracting destination from ad name URL slug
          // Ad names often contain url:slug-name or _url:slug-name patterns
          if (!destinationUrl && ad.ad_name) {
            const urlSlugMatch = ad.ad_name.match(/(?:^|[_:-])url[:_]([a-zA-Z0-9-]+)/i);
            if (urlSlugMatch) {
              const slug = urlSlugMatch[1];
              // Map known domains based on ad name brand prefix
              const brandMatch = ad.ad_name.match(/batch:(\w+)/);
              const brand = brandMatch ? brandMatch[1].toLowerCase() : '';
              if (brand === 'tdk') {
                destinationUrl = slug.toUpperCase() === 'HOMEPAGE'
                  ? 'https://firstday.com/'
                  : `https://firstday.com/pages/${slug}`;
              } else if (brand === 'trmv') {
                destinationUrl = slug.toUpperCase() === 'HOMEPAGE'
                  ? 'https://therearemanyversions.com/'
                  : `https://therearemanyversions.com/pages/${slug}`;
              }
            }
          }

          // Fallback 4: Use the facebook.com attachment URL if nothing else worked
          if (!destinationUrl && attachmentFallbackUrl) {
            destinationUrl = attachmentFallbackUrl;
          }

          const imageUrl = creative.image_url
            || storySpec?.link_data?.picture
            || creative.thumbnail_url
            || null;

          const isVideo = !!storySpec.video_data;

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
            spend: ad.spend,
            impressions: ad.impressions,
            clicks: ad.clicks,
            destination_url: destinationUrl,
            image_url: imageUrl,
            thumbnail_url: creative.thumbnail_url || null,
            is_video: isVideo,
            is_partnership_ad: isPartnershipAd
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
            is_video: false,
            is_partnership_ad: false
          };
        }
      })
    );

    // Sort by spend descending
    adsWithCreatives.sort((a, b) => parseFloat(b.spend || 0) - parseFloat(a.spend || 0));

    res.json({ ads: adsWithCreatives });
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

// --- Debug endpoint (temporary) ---

app.get('/api/debug-ad', requireAuth, async (req, res) => {
  const { ad_id } = req.query;
  if (!ad_id) return res.status(400).json({ error: 'ad_id required' });

  try {
    // Fetch ad with creative - try many fields including effective_link_url
    const adUrl = `${META_BASE_URL}/${ad_id}`
      + `?fields=creative{id,name,thumbnail_url,image_url,object_story_spec,link_url,object_url,object_story_id,effective_object_story_id}`
      + `&${metaParams(req.accessToken)}`;
    const adResponse = await fetch(adUrl);
    const adData = await adResponse.json();

    const creative = adData.creative || {};
    let creativeDirectData = null;
    let postData = null;

    if (creative.id) {
      const directUrl = `${META_BASE_URL}/${creative.id}`
        + `?fields=link_url,object_story_spec,asset_feed_spec,object_url,object_story_id,effective_object_story_id`
        + `&${metaParams(req.accessToken)}`;
      const directResponse = await fetch(directUrl);
      creativeDirectData = await directResponse.json();
    }

    // If we have an object_story_id, try fetching the post
    const storyId = creative.effective_object_story_id
      || creative.object_story_id
      || creativeDirectData?.effective_object_story_id
      || creativeDirectData?.object_story_id;

    if (storyId) {
      const postUrl = `${META_BASE_URL}/${storyId}`
        + `?fields=link`
        + `&${metaParams(req.accessToken)}`;
      const postResponse = await fetch(postUrl);
      postData = await postResponse.json();
    }

    // Try ad preview to extract URL from rendered HTML
    let previewData = null;
    let extractedUrl = null;
    try {
      const previewUrl = `${META_BASE_URL}/${ad_id}/previews`
        + `?ad_format=DESKTOP_FEED_STANDARD`
        + `&${metaParams(req.accessToken)}`;
      const previewResponse = await fetch(previewUrl);
      previewData = await previewResponse.json();

      // Try to fetch the iframe content and extract destination URL
      if (previewData.data?.[0]?.body) {
        const iframeSrcMatch = previewData.data[0].body.match(/src="([^"]+)"/);
        if (iframeSrcMatch) {
          const iframeUrl = iframeSrcMatch[1].replace(/&amp;/g, '&');
          const iframeResponse = await fetch(iframeUrl);
          const iframeHtml = await iframeResponse.text();

          // Extract external URLs from the iframe HTML (exclude facebook.com URLs)
          const urlMatches = iframeHtml.match(/href="(https?:\/\/[^"]+)"/g) || [];
          const externalUrls = urlMatches
            .map(m => m.match(/href="([^"]+)"/)[1])
            .map(u => { try { return decodeURIComponent(u); } catch { return u; } })
            .filter(u => !u.includes('facebook.com') && !u.includes('fbcdn.net') && !u.includes('fb.com'));

          // Also try to find URLs in l.facebook.com redirect links
          const redirectMatches = iframeHtml.match(/l\.facebook\.com\/l\.php\?u=([^&"]+)/g) || [];
          const redirectUrls = redirectMatches
            .map(m => { try { return decodeURIComponent(m.split('u=')[1]); } catch { return null; } })
            .filter(Boolean);

          extractedUrl = redirectUrls[0] || externalUrls[0] || null;
        }
      }
    } catch (e) {
      console.error('Preview fetch error:', e.message);
    }

    res.json({ adData, creativeDirectData, storyId, postData, extractedUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
