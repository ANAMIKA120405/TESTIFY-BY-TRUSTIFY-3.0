/**
 * urlScanHelpers.js
 * ──────────────────
 * Static data + pure functions used by urlScanController.
 * No network calls here — all instant, synchronous checks.
 */

'use strict'

// ── Trusted Domain Allow-list ─────────────────────────────────────────────────
// Exact apex domains that are definitively safe.
// Subdomains (*.google.com) are checked via endsWith().

const TRUSTED_DOMAINS = new Set([
  // Search & tech giants
  'google.com', 'google.co.uk', 'google.co.in', 'google.de', 'google.fr',
  'google.com.au', 'google.co.jp', 'google.ca', 'google.es', 'google.it',
  'googleapis.com', 'googlevideo.com', 'gstatic.com', 'ggpht.com',
  'youtube.com', 'youtu.be',
  'bing.com', 'msn.com', 'live.com', 'outlook.com', 'microsoft.com',
  'azure.com', 'office.com', 'office365.com', 'sharepoint.com', 'teams.microsoft.com',
  'windows.com', 'xbox.com', 'linkedin.com',
  // Social
  'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'messenger.com',
  'twitter.com', 'x.com', 't.co', 'twimg.com',
  'tiktok.com', 'reddit.com', 'redd.it', 'reddit.it', 'snapchat.com',
  'pinterest.com', 'tumblr.com', 'quora.com', 'discord.com', 'discordapp.com',
  // Development & cloud
  'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
  'stackoverflow.com', 'stackexchange.com', 'npmjs.com', 'pypi.org',
  'docker.com', 'kubernetes.io', 'cloudflare.com', 'netlify.com', 'vercel.com',
  'heroku.com', 'digitalocean.com', 'vultr.com',
  'aws.amazon.com', 'amazonaws.com', 'awsstatic.com',
  // E-commerce & finance (official only)
  'amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.fr',
  'amazon.com.au', 'amazon.ca', 'amazon.co.jp',
  'ebay.com', 'etsy.com', 'shopify.com',
  'paypal.com', 'paypal.me', 'stripe.com',
  'visa.com', 'mastercard.com', 'americanexpress.com',
  // Entertainment
  'netflix.com', 'netflix.net', 'nflxext.com',
  'spotify.com', 'spotifycdn.com',
  'twitch.tv', 'twitchapps.com',
  'apple.com', 'icloud.com', 'mzstatic.com',
  'adobe.com', 'adobecc.com',
  'steam.com', 'steampowered.com', 'steamcommunity.com', 'steamgames.com',
  // News & reference
  'wikipedia.org', 'wikimedia.org', 'wikidata.org',
  'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
  'reuters.com', 'bloomberg.com', 'techcrunch.com', 'theverge.com', 'wired.com',
  // Productivity & comms
  'notion.so', 'notion.com', 'trello.com', 'atlassian.com', 'jira.atlassian.com',
  'slack.com', 'zoom.us', 'webex.com', 'dropbox.com',
  'medium.com', 'substack.com', 'wordpress.com', 'ghost.io',
  // Security & research
  'virustotal.com', 'shodan.io', 'haveibeenpwned.com', 'abuse.ch', 'urlhaus-api.abuse.ch',
  'nvd.nist.gov', 'cve.mitre.org', 'owasp.org',
])

function isTrustedDomain(hostname) {
  const h = hostname.toLowerCase()
  if (TRUSTED_DOMAINS.has(h)) return true
  // Check if it's a subdomain of a trusted apex
  for (const trusted of TRUSTED_DOMAINS) {
    if (h.endsWith('.' + trusted)) return true
  }
  return false
}

// ── Extended Brand Domains ────────────────────────────────────────────────────
// Used for brand-impersonation detection.
// Maps brand keyword → array of all official domains for that brand.

const BRAND_DOMAINS = {
  google:      ['google.com', 'google.co.uk', 'google.co.in', 'googleapis.com', 'googlevideo.com', 'gstatic.com', 'youtube.com', 'youtu.be'],
  youtube:     ['youtube.com', 'youtu.be', 'yt.be', 'ytimg.com'],
  facebook:    ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'messenger.com'],
  instagram:   ['instagram.com', 'cdninstagram.com', 'fb.com'],
  whatsapp:    ['whatsapp.com', 'whatsapp.net'],
  amazon:      ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.fr', 'amazon.com.au', 'amazon.ca', 'amazon.co.jp', 'amazonaws.com', 'awsstatic.com'],
  aws:         ['amazonaws.com', 'aws.amazon.com', 'awsstatic.com', 'cloudfront.net'],
  paypal:      ['paypal.com', 'paypal.me', 'paypalobjects.com'],
  microsoft:   ['microsoft.com', 'live.com', 'outlook.com', 'azure.com', 'office.com', 'bing.com', 'msn.com', 'windows.com', 'xbox.com', 'linkedin.com', 'skype.com', 'office365.com'],
  apple:       ['apple.com', 'icloud.com', 'mzstatic.com', 'cdn-apple.com', 'apple-cloudkit.com'],
  netflix:     ['netflix.com', 'nflxext.com', 'nflxso.net', 'netflix.net'],
  spotify:     ['spotify.com', 'spotifycdn.com', 'scdn.co'],
  twitter:     ['twitter.com', 'x.com', 't.co', 'twimg.com'],
  linkedin:    ['linkedin.com', 'licdn.com'],
  github:      ['github.com', 'githubusercontent.com', 'github.io', 'githubassets.com'],
  gitlab:      ['gitlab.com', 'gitlab.io'],
  dropbox:     ['dropbox.com', 'dropboxstatic.com', 'dropboxusercontent.com'],
  adobe:       ['adobe.com', 'adobecc.com', 'adobelogin.com', 'adobestatic.com', 'typekit.com'],
  steam:       ['steampowered.com', 'steamcommunity.com', 'steamgames.com', 'steam.com', 'steamstatic.com'],
  twitch:      ['twitch.tv', 'twitchapps.com', 'jtvnw.net', 'twitchsvc.net'],
  discord:     ['discord.com', 'discordapp.com', 'discord.gg', 'discordcdn.com'],
  stripe:      ['stripe.com', 'stripe.network', 'stripecdn.com'],
  shopify:     ['shopify.com', 'shopifycdn.com', 'myshopify.com', 'shopifysvc.com'],
  ebay:        ['ebay.com', 'ebay.co.uk', 'ebay.de', 'ebay.com.au', 'ebaystatic.com'],
  walmart:     ['walmart.com', 'walmartimages.com'],
  chase:       ['chase.com', 'jpmorgan.com', 'jpmchase.com'],
  wellsfargo:  ['wellsfargo.com', 'wfcdn.com'],
  bankofamerica: ['bankofamerica.com', 'bac.com', 'ml.com'],
  coinbase:    ['coinbase.com', 'coinbaseprime.com', 'cbpro.com'],
  binance:     ['binance.com', 'binance.us', 'bnbstatic.com'],
  cloudflare:  ['cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com'],
  zoom:        ['zoom.us', 'zoom.com', 'zoomgov.com'],
  slack:       ['slack.com', 'slack-edge.com', 'slackb.com'],
  notion:      ['notion.so', 'notion.com'],
  atlassian:   ['atlassian.com', 'atlassian.net', 'jira.com', 'confluence.com', 'bitbucket.org'],
}

// ── Suspicious TLDs (extended) ────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  // High abuse rate
  '.xyz', '.top', '.club', '.click', '.info', '.ru',
  '.tk', '.ml', '.ga', '.cf', '.gq',
  // Newer high-risk gTLDs
  '.online', '.site', '.website', '.tech', '.store', '.shop',
  '.space', '.fun', '.live', '.stream', '.download', '.review',
  '.win', '.racing', '.bid', '.loan', '.cricket', '.party',
  '.science', '.work', '.accountant', '.trade', '.webcam',
  // Country codes with known high abuse
  '.cn', '.pw', '.ws', '.cc', '.to', '.biz', '.link',
  // Recently weaponized TLDs
  '.zip', '.mov',
]

// ── URL Shorteners (extended) ─────────────────────────────────────────────────

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io',
  'buff.ly', 'is.gd', 'su.pr', 'cli.gs', 'tiny.cc', 'lnkd.in',
  'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'shorturl.at', 'rb.gy',
  // Extended
  'cutt.ly', 'v.gd', 'snip.ly', 't.ly', 'bl.ink', 'rebrand.ly',
  'smarturl.it', 'yourls.org', 'shrt.st', 'mcaf.ee', 'soo.gd',
  'chilp.it', 'x.co', 'zpr.io', 'tiny.pl', 'po.st', 'tnij.org',
  'go2.do', 'bc.vc', 'ity.im', 'q.gs', 'prettylinkpro.com',
]

// ── Financial / Lure Keywords ─────────────────────────────────────────────────

const FINANCIAL_LURE_KEYWORDS = [
  'finance', 'crypto', 'wallet', 'invest', 'forex', 'bitcoin', 'ethereum',
  'loan', 'credit', 'debit', 'fund', 'capital', 'mortgage', 'insurance',
  'prize', 'claim', 'earn', 'profit', 'token', 'coin', 'nft', 'btc', 'eth',
  'trading', 'exchange', 'stake', 'yield', 'airdrop', 'ico',
  'dividend', 'roi', 'passive-income', 'giveaway', 'reward', 'bonus',
]

// ── Suspicious Path Keywords ─────────────────────────────────────────────────
// Only checked in path (not hostname) to avoid false positives

const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'update', 'secure', 'bank', 'password',
  'signin', 'sign-in', 'confirm', 'reset', 'suspend', 'locked',
  'validate', 'authenticate', 'authorize', 'credential',
]

// ── Homograph / Unicode Lookalike Detection ──────────────────────────────────
// Maps known lookalike Unicode chars to their ASCII equivalents

const LOOKALIKE_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',       // Cyrillic
  'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g',       // Cyrillic/IPA
  'ο': 'o', 'ρ': 'p', 'α': 'a', 'ε': 'e', 'ν': 'n', 'υ': 'u',        // Greek
  'ω': 'w', 'β': 'b', 'τ': 't', 'κ': 'k',                             // Greek
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't',        // Digits as letters
  '\u0020': '', '\u200b': '', '\u200c': '', '\u200d': '',               // Zero-width chars
}

function normalizeForLookalike(str) {
  let result = ''
  for (const ch of str.toLowerCase()) {
    result += LOOKALIKE_MAP[ch] ?? ch
  }
  return result
}

function detectHomograph(hostname) {
  const findings = []
  let score = 0

  // Check for non-ASCII chars in hostname
  if (/[^\x00-\x7F]/.test(hostname)) {
    score += 20
    findings.push('❌ Non-ASCII characters detected in domain — possible homograph attack')
  }

  // Check for known Cyrillic/Greek lookalikes
  const hasCyrillic = /[\u0400-\u04FF]/.test(hostname)
  const hasGreek    = /[\u0370-\u03FF]/.test(hostname)
  if (hasCyrillic) {
    score += 25
    findings.push('❌ Cyrillic characters in domain — classic IDN homograph attack')
  }
  if (hasGreek) {
    score += 25
    findings.push('❌ Greek characters in domain — IDN homograph spoofing')
  }

  // Check digit substitution (l33tspeak) for brand names
  const normalizedHost = normalizeForLookalike(hostname)
  for (const brand of Object.keys(BRAND_DOMAINS)) {
    if (
      normalizedHost.includes(brand) &&
      !hostname.toLowerCase().includes(brand)
    ) {
      score += 20
      findings.push(`⚠️ Digit/symbol substitution detected: hostname normalizes to include "${brand}"`)
      break
    }
  }

  return { score: Math.min(score, 100), findings }
}

// ── Levenshtein Typosquatting Detection ──────────────────────────────────────

function levenshtein(a, b) {
  const m = a.length
  const n = b.length
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  )
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
    }
  }
  return dp[m][n]
}

function detectTyposquatting(hostname) {
  const findings = []
  let score = 0

  // Extract just the second-level domain (e.g. "paypa1" from "paypa1.com")
  const parts = hostname.toLowerCase().split('.')
  // For "www.paypa1.com" → sld = "paypa1", for "paypa1.com" → sld = "paypa1"
  const sld = parts.length >= 2 ? parts[parts.length - 2] : parts[0]

  // Skip very short (< 4 chars) — too many false positives
  if (sld.length < 4) return { score: 0, findings: [] }

  for (const brand of Object.keys(BRAND_DOMAINS)) {
    // Skip if it's an exact match with a trusted brand key — already handled by allow-list
    if (sld === brand) continue

    const dist = levenshtein(sld, brand)

    // Distance 1: single char change → very suspicious
    if (dist === 1 && sld.length >= 5) {
      score += 40
      findings.push(`❌ Typosquatting detected: "${sld}" is 1 character away from "${brand}"`)
      break
    }
    // Distance 2: two changes → suspicious (only for longer names to avoid false positives)
    if (dist === 2 && sld.length >= 7) {
      score += 25
      findings.push(`⚠️ Possible typosquat: "${sld}" is 2 characters away from "${brand}"`)
      break
    }
  }

  if (findings.length === 0) {
    findings.push('✅ No typosquatting patterns detected')
  }

  return { score: Math.min(score, 100), findings }
}

// ── Private IP Check ─────────────────────────────────────────────────────────

const PRIVATE_IP_RANGES = [
  /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./, /^169\.254\./, /^::1$/, /^fc/i,
  /^0\.0\.0\.0/,
]

function isPrivateIp(ip) {
  return PRIVATE_IP_RANGES.some((rx) => rx.test(ip))
}

// ── Risk Level ────────────────────────────────────────────────────────────────

function getRiskLevel(score) {
  if (score <= 20) return 'Safe'
  if (score <= 50) return 'Suspicious'
  return 'Malicious'
}

function getConfidence(categories, criticalCount, isFromCache, isTrusted) {
  if (isTrusted) return 'High'
  // Count how many critical categories have high scores
  const criticalCategoryNames = ['Threat Intelligence', 'DNS Verification', 'SSL/TLS Security', 'Heuristic Analysis']
  const highCriticalCount = categories.filter(
    c => criticalCategoryNames.includes(c.name) && c.score >= 40
  ).length

  if (highCriticalCount >= 3 || criticalCount >= 4) return 'High'
  if (highCriticalCount >= 2 || criticalCount >= 2) return 'Medium'
  return 'Low'
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  TRUSTED_DOMAINS,
  BRAND_DOMAINS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
  FINANCIAL_LURE_KEYWORDS,
  SUSPICIOUS_KEYWORDS,
  PRIVATE_IP_RANGES,
  isTrustedDomain,
  isPrivateIp,
  detectHomograph,
  detectTyposquatting,
  normalizeForLookalike,
  levenshtein,
  getRiskLevel,
  getConfidence,
}
