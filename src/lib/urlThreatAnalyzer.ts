/**
 * urlThreatAnalyzer.ts
 * ─────────────────────
 * Pure heuristic threat-scoring engine — runs entirely in the browser.
 * Mirror of backend/controllers/urlScanController.js scoring logic.
 *
 * R01 +20  Suspicious keywords          R12 +20  Private/reserved IP (SSRF)
 * R02 +20  "@" in URL                   R13 +10  Subdomain depth > 4 dots
 * R03 +15  URL length > 75              R14 +15  High-risk TLD
 * R04 +20  Non-HTTPS                    R15 +10  Excessive hyphens > 2
 * R05 +20  Malicious file extension     R16 +15  Homograph substitution
 * R06 +15  Open-redirect parameter      R17 +20  Brand mismatch
 * R07 +20  SQL-injection pattern        R18 +15  Punycode / IDN domain
 * R08 +20  XSS / script injection       R19 +20  URL shortener
 * R09 +15  Path traversal               R20 +10  Non-standard port
 * R10 +10  Excessive URL-encoding       R21 +10  Long second-level domain > 25
 * R11 +25  Raw IP address               R22 +20  Financial/investment lure in hostname
 *
 * Risk levels:  0–15 Safe  |  16–55 Suspicious  |  56–100 Malicious
 */

// High-confidence phishing lures — checked against full URL
const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'update', 'secure', 'bank', 'password',
  'signin', 'sign-in', 'confirm', 'reset', 'suspend', 'locked',
  'validate', 'authenticate', 'authorize', 'credential',
]

// Financial / investment lure words — checked against hostname only (R22)
const FINANCIAL_LURE_KEYWORDS = [
  'finance', 'crypto', 'wallet', 'invest', 'forex', 'bitcoin', 'ethereum',
  'loan', 'credit', 'debit', 'fund', 'capital', 'mortgage', 'insurance',
  'prize', 'claim', 'earn', 'profit', 'token', 'coin', 'nft', 'btc', 'eth',
  'trading', 'exchange', 'stake', 'yield', 'airdrop', 'ico',
]

const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/|$)/

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^::1$/,
  /^fc/i,
]

const SUSPICIOUS_TLDS = [
  '.xyz', '.top', '.club', '.click', '.info', '.ru',
  '.tk', '.ml', '.ga', '.cf', '.gq',
]

const HOMOGRAPH_REGEX = /[a-z][013][a-z]/i

const BRAND_DOMAINS: Record<string, string[]> = {
  google:    ['google.com', 'google.co.uk', 'google.co.in', 'googleapis.com', 'googlevideo.com'],
  facebook:  ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com'],
  amazon:    ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazonaws.com'],
  paypal:    ['paypal.com', 'paypal.me'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'azure.com', 'office.com', 'bing.com', 'msn.com'],
  apple:     ['apple.com', 'icloud.com'],
  netflix:   ['netflix.com'],
  twitter:   ['twitter.com', 'x.com', 't.co'],
}

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io',
  'buff.ly', 'is.gd', 'su.pr', 'cli.gs', 'tiny.cc', 'lnkd.in',
  'db.tt', 'qr.ae', 'adf.ly', 'bitly.com', 'shorturl.at', 'rb.gy',
]

const DOWNLOAD_EXTENSIONS = /\.(exe|bat|ps1|msi|vbs|scr|jar|cmd|pif|dll|sh)(\?|#|$)/i
const REDIRECT_PARAMS      = /[?&](url|redirect|goto|redir|return|next|dest|destination|link|forward|callback)=/i
const SQLI_PATTERNS        = /(\bSELECT\b|\bUNION\b|\bINSERT\b|\bDROP\b|\bDELETE\b|--|;--|'--|%27|%3b|1=1)/i
const XSS_PATTERNS         = /<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|eval\s*\(/i
const PATH_TRAVERSAL       = /(\.\.(\/|\\|%2f|%5c)|%2e%2e)/i

export type RiskLevel = 'Safe' | 'Suspicious' | 'Malicious'

export type ScanResult = {
  url: string
  threatScore: number
  riskLevel: RiskLevel
  findings: string[]
  timestamp: string
}

function getRiskLevel(score: number): RiskLevel {
  if (score <= 15) return 'Safe'
  if (score <= 55) return 'Suspicious'
  return 'Malicious'
}

function isPrivateIp(ip: string): boolean {
  return PRIVATE_IP_RANGES.some((rx) => rx.test(ip))
}

export function analyzeUrl(rawUrl: string): ScanResult {
  const trimmed = rawUrl.trim()
  let parsed: URL

  try {
    parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Bad protocol')
    }
  } catch {
    throw new Error('Invalid URL format. URL must start with http:// or https://')
  }

  let threatScore = 0
  const findings: string[] = []

  const lowerUrl  = trimmed.toLowerCase()
  const hostname  = parsed.hostname
  const hostPort  = parsed.host
  const port      = parsed.port
  const path      = parsed.pathname + parsed.search + parsed.hash
  const lowerHost = hostname.toLowerCase()

  // R01 — Suspicious keywords (+20)
  const matched = SUSPICIOUS_KEYWORDS.filter((kw) => lowerUrl.includes(kw))
  if (matched.length > 0) {
    threatScore += 20
    findings.push(`Suspicious keyword(s) found: ${matched.map((k) => `"${k}"`).join(', ')}.`)
  }

  // R02 — "@" symbol (+20)
  if (trimmed.includes('@')) {
    threatScore += 20
    findings.push('URL contains "@" — possible credential-embedding or phishing indicator.')
  }

  // R03 — Length > 75 (+15)
  if (trimmed.length > 75) {
    threatScore += 15
    findings.push(`URL is unusually long (${trimmed.length} chars, threshold 75).`)
  }

  // R04 — Non-HTTPS (+20)
  if (parsed.protocol !== 'https:') {
    threatScore += 20
    findings.push('URL uses HTTP — data is transmitted unencrypted.')
  }

  // R05 — Dangerous file extension (+20)
  if (DOWNLOAD_EXTENSIONS.test(path)) {
    const ext = (path.match(DOWNLOAD_EXTENSIONS) ?? [])[0] ?? ''
    threatScore += 20
    findings.push(`Path targets a potentially malicious file type: "${ext.replace(/[?#].*/, '')}".`)
  }

  // R06 — Open-redirect parameter (+15)
  if (REDIRECT_PARAMS.test(parsed.search)) {
    threatScore += 15
    findings.push('Open-redirect parameter detected (url=, redirect=, goto=, etc.) — may chain to a malicious destination.')
  }

  // R07 — SQL-injection (+20)
  let decodedPath = path
  try { decodedPath = decodeURIComponent(path) } catch { /* keep raw */ }
  if (SQLI_PATTERNS.test(decodedPath)) {
    threatScore += 20
    findings.push('SQL-injection pattern detected in URL path/query.')
  }

  // R08 — XSS / script injection (+20)
  if (XSS_PATTERNS.test(decodedPath)) {
    threatScore += 20
    findings.push('Cross-site scripting (XSS) or script-injection pattern detected in URL.')
  }

  // R09 — Path traversal (+15)
  if (PATH_TRAVERSAL.test(trimmed)) {
    threatScore += 15
    findings.push('Path-traversal sequence detected (../) — possible directory traversal attack.')
  }

  // R10 — Excessive URL-encoding (+10)
  const encodedCount = (trimmed.match(/%[0-9a-f]{2}/gi) ?? []).length
  if (encodedCount > 8) {
    threatScore += 10
    findings.push(`Excessive URL-encoding (${encodedCount} encoded sequences) — possible character obfuscation.`)
  }

  // R11 — Raw IP address (+25)
  const isIp = IP_REGEX.test(hostPort + '/')
  if (isIp) {
    threatScore += 25
    findings.push(`URL uses a raw IP address (${hostname}) instead of a registered domain.`)
  }

  // R12 — Private / reserved IP (+20)
  if (isIp && isPrivateIp(hostname)) {
    threatScore += 20
    findings.push(`IP ${hostname} is in a private/reserved range — possible SSRF or internal network exposure.`)
  }

  // R13 — Subdomain depth > 4 (+10)
  const dotCount = hostname.split('.').length - 1
  if (dotCount > 4) {
    threatScore += 10
    findings.push(`Excessive subdomain depth (${dotCount} dots) — common in phishing domains.`)
  }

  // R14 — High-risk TLD (+15)
  const matchedTld = SUSPICIOUS_TLDS.find((tld) => lowerHost.endsWith(tld))
  if (matchedTld) {
    threatScore += 15
    findings.push(`Domain uses a high-risk TLD: "${matchedTld}".`)
  }

  // R15 — Excessive hyphens (+10)
  const hyphenCount = (hostname.match(/-/g) ?? []).length
  if (hyphenCount > 2) {
    threatScore += 10
    findings.push(`Hostname has ${hyphenCount} hyphens — possible typosquatting.`)
  }

  // R16 — Homograph substitution (+15)
  if (HOMOGRAPH_REGEX.test(hostname)) {
    threatScore += 15
    findings.push('Hostname uses digits as letters (0/1/3 → o/l/e) — possible homograph attack.')
  }

  // R17 — Brand mismatch (+20)
  for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
    if (lowerUrl.includes(brand)) {
      const isOfficial = officialDomains.some(
        (d) => lowerHost === d || lowerHost.endsWith('.' + d)
      )
      if (!isOfficial) {
        threatScore += 20
        findings.push(`Brand impersonation: references "${brand}" but "${hostname}" is not an official ${brand} domain.`)
        break
      }
    }
  }

  // R18 — Punycode / IDN (+15)
  if (lowerHost.includes('xn--')) {
    threatScore += 15
    findings.push('Domain contains Punycode (xn--) — possible IDN homograph spoofing.')
  }

  // R19 — URL shortener (+20)
  if (URL_SHORTENERS.some((s) => lowerHost === s || lowerHost.endsWith('.' + s))) {
    threatScore += 20
    findings.push(`URL uses a shortener service (${hostname}) — the true destination is hidden.`)
  }

  // R20 — Non-standard port (+10)
  if (port && port !== '80' && port !== '443') {
    threatScore += 10
    findings.push(`Non-standard port ${port} detected — uncommon for legitimate web services.`)
  }

  // R21 — Long second-level domain (+10)
  const parts = lowerHost.split('.')
  const sld = parts.length >= 2 ? parts[parts.length - 2] : ''
  if (!isIp && sld.length > 25) {
    threatScore += 10
    findings.push(`Second-level domain is unusually long (${sld.length} chars) — possible evasion technique.`)
  }

  // R22 — Financial / investment lure keyword in hostname (+20)
  const matchedFinance = FINANCIAL_LURE_KEYWORDS.find((kw) => lowerHost.includes(kw))
  if (matchedFinance) {
    threatScore += 20
    findings.push(
      `Hostname contains a financial/investment lure keyword ("${matchedFinance}") — ` +
      'commonly used in scam, phishing, and fraudulent finance sites. Verify this site independently.'
    )
  }

  threatScore = Math.min(threatScore, 100)

  if (findings.length === 0) {
    findings.push('No significant threat indicators detected.')
  }

  return {
    url: trimmed,
    threatScore,
    riskLevel: getRiskLevel(threatScore),
    findings,
    timestamp: new Date().toISOString(),
  }
}

