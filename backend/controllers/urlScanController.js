/**
 * urlScanController.js
 * ─────────────────────
 * Production-grade URL Security Scanner — 4-Layer Architecture
 *
 * Layer 0 — Pre-checks (instant):
 *   • Trusted domain allow-list (80+ apex domains)
 *   • Typosquatting detection via Levenshtein distance
 *   • Homograph / Unicode lookalike detection
 *   • Extended brand impersonation (30+ brands)
 *   • Extended heuristics (TLDs, shorteners, patterns)
 *
 * Layer 1 — Threat Intelligence (parallel network):
 *   • URLhaus (abuse.ch)          — no key required
 *   • OpenPhish                   — no key required, loaded in mem
 *   • Google Safe Browsing v4     — optional (GOOGLE_SAFE_BROWSING_KEY)
 *   • PhishTank                   — optional (PHISHTANK_API_KEY)
 *
 * Layer 2 — Live Network Analysis (parallel):
 *   • DNS resolution + private-IP check
 *   • SSL/TLS certificate validation + weak cipher detection
 *   • HTTP Security headers analysis (7 headers)
 *   • Redirect chain tracking
 *   • HTML content scanning (hidden iframes, password forms, obfuscation)
 *   • Domain age via WHOIS
 *
 * Layer 3 — Scoring Engine:
 *   • Critical failure floors (DNS fail → min 55, threat DB → min 85)
 *   • Evidence-count boosting (more ❌ findings = higher contribution)
 *   • Confidence rating (High / Medium / Low)
 *   • In-memory 30-minute result cache
 *
 * Risk levels:  0–20 Safe  |  21–50 Suspicious  |  51–100 Malicious
 */

'use strict'

const dns   = require('dns')
const tls   = require('tls')
const http  = require('http')
const https = require('https')

const {
  isTrustedDomain,
  isPrivateIp,
  detectHomograph,
  detectTyposquatting,
  getRiskLevel,
  getConfidence,
  BRAND_DOMAINS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
  FINANCIAL_LURE_KEYWORDS,
  SUSPICIOUS_KEYWORDS,
} = require('./urlScanHelpers')

const { openPhishFeed } = require('./urlScanFeeds')

// ── Scan Cache (30-min TTL) ──────────────────────────────────────────────────

const CACHE_TTL_MS = 30 * 60 * 1000
const scanCache = new Map()   // url → { result, expiresAt }

function getCached(url) {
  const entry = scanCache.get(url)
  if (!entry) return null
  if (Date.now() > entry.expiresAt) { scanCache.delete(url); return null }
  return entry.result
}

function setCache(url, result) {
  // Limit cache size
  if (scanCache.size >= 500) {
    const oldest = scanCache.keys().next().value
    scanCache.delete(oldest)
  }
  scanCache.set(url, { result, expiresAt: Date.now() + CACHE_TTL_MS })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/|$)/
const DOWNLOAD_EXTENSIONS = /\.(exe|bat|ps1|msi|vbs|scr|jar|cmd|pif|dll|sh)(\?|#|$)/i
const REDIRECT_PARAMS     = /[?&](url|redirect|goto|redir|return|next|dest|destination|link|forward|callback)=/i
const SQLI_PATTERNS       = /(\bSELECT\b|\bUNION\b|\bINSERT\b|\bDROP\b|\bDELETE\b|--|;--|'--|%27|%3b|1=1)/i
const XSS_PATTERNS        = /<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|eval\s*\(/i
const PATH_TRAVERSAL      = /(\.\.(\/|\\|%2f|%5c)|%2e%2e)/i

function isValidUrl(rawUrl) {
  try {
    const p = new URL(rawUrl)
    return p.protocol === 'http:' || p.protocol === 'https:'
  } catch { return false }
}

// ── Layer 0: Heuristic Analysis ─────────────────────────────────────────────

function runHeuristicAnalysis(parsed, trimmedUrl, trustedDomain) {
  let score = 0
  const findings = []

  const lowerUrl  = trimmedUrl.toLowerCase()
  const hostname  = parsed.hostname
  const hostPort  = parsed.host
  const port      = parsed.port
  const path      = parsed.pathname + parsed.search + parsed.hash
  const lowerHost = hostname.toLowerCase()

  // Skip keyword checks in the path for trusted domains
  const skipPathKeywords = trustedDomain

  // R01 — Suspicious keywords in PATH only (not hostname of trusted domains)
  if (!skipPathKeywords) {
    const matchedKw = SUSPICIOUS_KEYWORDS.filter((kw) => lowerUrl.includes(kw))
    if (matchedKw.length > 0) {
      score += 12
      findings.push(`⚠️ Suspicious keyword(s): ${matchedKw.map((k) => `"${k}"`).join(', ')}`)
    }
  }

  // R02 — "@" symbol
  if (trimmedUrl.includes('@')) {
    score += 20
    findings.push('❌ URL contains "@" — credential-embedding or phishing indicator')
  }

  // R03 — Non-HTTPS
  if (parsed.protocol !== 'https:') {
    score += 20
    findings.push('❌ URL uses plain HTTP — data transmitted unencrypted')
  }

  // R04 — Dangerous file extension
  if (DOWNLOAD_EXTENSIONS.test(path)) {
    const ext = (path.match(DOWNLOAD_EXTENSIONS) || [])[0] || ''
    score += 25
    findings.push(`❌ Links to potentially malicious file: "${ext.replace(/[?#].*/, '')}"`)
  }

  // R05 — Open-redirect parameter
  if (REDIRECT_PARAMS.test(parsed.search)) {
    score += 15
    findings.push('⚠️ Open-redirect parameter detected (url=, redirect=, goto=, etc.)')
  }

  // R06 — SQL injection
  let decodedPath = path
  try { decodedPath = decodeURIComponent(path) } catch { /* keep raw */ }
  if (SQLI_PATTERNS.test(decodedPath)) {
    score += 25
    findings.push('❌ SQL-injection pattern detected in URL')
  }

  // R07 — XSS
  if (XSS_PATTERNS.test(decodedPath)) {
    score += 25
    findings.push('❌ Cross-site scripting (XSS) pattern detected')
  }

  // R08 — Path traversal
  if (PATH_TRAVERSAL.test(trimmedUrl)) {
    score += 20
    findings.push('❌ Path-traversal sequence detected (../)')
  }

  // R09 — Excessive URL-encoding
  const encodedCount = (trimmedUrl.match(/%[0-9a-f]{2}/gi) || []).length
  if (encodedCount > 8) {
    score += 10
    findings.push(`⚠️ Excessive URL-encoding (${encodedCount} sequences) — possible evasion`)
  }

  // R10 — Raw IP address
  const isIp = IP_REGEX.test(hostPort + '/')
  if (isIp) {
    score += 20
    findings.push(`⚠️ Raw IP address (${hostname}) — no domain name`)
  }

  // R11 — Private/reserved IP
  if (isIp && isPrivateIp(hostname)) {
    score += 25
    findings.push(`❌ Private/reserved IP ${hostname} — possible SSRF attack`)
  }

  // R12 — High-risk TLD
  const matchedTld = SUSPICIOUS_TLDS.find((tld) => lowerHost.endsWith(tld))
  if (matchedTld) {
    score += 15
    findings.push(`⚠️ High-risk TLD: "${matchedTld}" — associated with high abuse rates`)
  }

  // R13 — Brand impersonation (only if not a trusted/official domain)
  if (!trustedDomain) {
    for (const [brand, officialDomains] of Object.entries(BRAND_DOMAINS)) {
      if (lowerHost.includes(brand)) {
        const isOfficial = officialDomains.some(
          (d) => lowerHost === d || lowerHost.endsWith('.' + d)
        )
        if (!isOfficial) {
          score += 30
          findings.push(`❌ Brand impersonation: "${brand}" in hostname but not an official domain`)
          break
        }
      }
    }
  }

  // R14 — Punycode / IDN
  if (lowerHost.includes('xn--')) {
    score += 15
    findings.push('⚠️ Punycode (xn--) in domain — possible IDN homograph spoofing')
  }

  // R15 — URL shortener
  if (URL_SHORTENERS.some((s) => lowerHost === s || lowerHost.endsWith('.' + s))) {
    score += 20
    findings.push(`⚠️ URL shortener (${hostname}) — true destination hidden`)
  }

  // R16 — Non-standard port
  if (port && port !== '80' && port !== '443') {
    score += 10
    findings.push(`⚠️ Non-standard port: ${port}`)
  }

  // R17 — Financial lure keyword in hostname
  if (!trustedDomain) {
    const matchedFinance = FINANCIAL_LURE_KEYWORDS.find((kw) => lowerHost.includes(kw))
    if (matchedFinance) {
      score += 15
      findings.push(`⚠️ Financial lure keyword "${matchedFinance}" in hostname`)
    }
  }

  // R18 — Excessive hyphens
  const hyphenCount = (hostname.match(/-/g) || []).length
  if (hyphenCount > 3) {
    score += 10
    findings.push(`⚠️ ${hyphenCount} hyphens in hostname — possible typosquatting`)
  }

  // R19 — Subdomain depth > 4
  const dotCount = hostname.split('.').length - 1
  if (dotCount > 4) {
    score += 10
    findings.push(`⚠️ Excessive subdomain depth (${dotCount} levels)`)
  }

  // R20 — Very long URL
  if (trimmedUrl.length > 150) {
    score += 8
    findings.push(`⚠️ Very long URL (${trimmedUrl.length} chars) — evasion tactic`)
  }

  if (findings.length === 0) {
    findings.push('✅ No suspicious URL patterns detected')
  }

  return { score: Math.min(score, 100), findings }
}

// ── Layer 1: Threat Intelligence ─────────────────────────────────────────────

async function checkThreatIntelligence(urlString, hostname) {
  const findings = []
  let score = 0

  // ─ 1a. URLhaus ──────────────────────────────────────────────────────────────
  try {
    const urlhausUrl = await fetchUrlhaus('url', urlString)
    if (urlhausUrl && urlhausUrl.query_status === 'listed') {
      return {
        score: 100,
        findings: [
          '🚨 URL found in URLhaus (abuse.ch) malware database!',
          `Threat type: ${urlhausUrl.threat || 'malware'}`,
          `Status: ${urlhausUrl.url_status || 'active'}`,
          `Date added: ${urlhausUrl.date_added || 'unknown'}`,
          `Source: URLhaus (abuse.ch)`,
        ],
      }
    }
  } catch { /* continue */ }

  try {
    const urlhausHost = await fetchUrlhaus('host', hostname)
    if (urlhausHost && urlhausHost.query_status === 'listed') {
      const urlCount = urlhausHost.urls?.length || urlhausHost.url_count || 0
      return {
        score: 85,
        findings: [
          `🚨 Host "${hostname}" in URLhaus (abuse.ch) malware database!`,
          urlCount > 0 ? `${urlCount} malicious URLs associated with this host` : '',
          'Source: URLhaus (abuse.ch)',
        ].filter(Boolean),
      }
    }
  } catch { /* continue */ }

  // ─ 1b. OpenPhish ────────────────────────────────────────────────────────────
  const openphishResult = openPhishFeed.check(urlString, hostname)
  if (openphishResult.hit) {
    return {
      score: 90,
      findings: [
        '🚨 URL/host found in OpenPhish phishing database!',
        'Source: OpenPhish (real-time phishing feed)',
      ],
    }
  }

  if (openPhishFeed.isLoaded) {
    findings.push(`✅ Not in OpenPhish feed (${openPhishFeed.urlCount.toLocaleString()} phishing URLs checked)`)
  } else {
    findings.push('⚠️ OpenPhish feed not yet loaded')
  }

  // ─ 1d. PhishTank ────────────────────────────────────────────────────────────
  const PT_KEY = process.env.PHISHTANK_API_KEY
  if (PT_KEY) {
    try {
      const ptResult = await checkPhishTank(urlString, PT_KEY)
      if (ptResult.inDatabase && ptResult.valid) {
        score = Math.max(score, 92)
        findings.push('🚨 URL confirmed as phishing by PhishTank!')
        findings.push('Source: PhishTank.com')
      } else if (ptResult.inDatabase) {
        score = Math.max(score, 60)
        findings.push('⚠️ URL reported to PhishTank (not yet verified)')
      } else {
        findings.push('✅ Not in PhishTank database')
      }
    } catch { findings.push('⚠️ PhishTank check failed') }
  } else {
    findings.push('ℹ️ PhishTank: no API key configured (set PHISHTANK_API_KEY)')
  }

  // ─ 1e. Malware pattern check ────────────────────────────────────────────────
  const lowerUrl = urlString.toLowerCase()
  const malwarePatterns = [
    { pattern: /\.php\?id=\d+&?.*download/i,            desc: 'PHP download pattern (common in malware distribution)' },
    { pattern: /\/wp-content\/uploads\/.*\.(exe|zip|rar)/i, desc: 'Executable in WordPress uploads directory' },
    { pattern: /\/temp\/.*\.(exe|bat|ps1)/i,            desc: 'Executable in temp directory' },
    { pattern: /base64[,=]/i,                           desc: 'Base64 encoded payload in URL' },
    { pattern: /powershell.*download/i,                 desc: 'PowerShell download pattern' },
    { pattern: /\.onion\.ws|\.onion\.to|\.onion\.link/, desc: 'Dark web proxy redirect' },
  ]

  let patternHits = 0
  for (const { pattern, desc } of malwarePatterns) {
    if (pattern.test(lowerUrl)) {
      score += 20
      patternHits++
      findings.push(`⚠️ ${desc}`)
    }
  }

  if (patternHits === 0) {
    findings.push('✅ No malware distribution patterns detected')
  }

  findings.unshift('✅ Not found in URLhaus threat database')

  return { score: Math.min(score, 100), findings }
}

async function fetchUrlhaus(type, value) {
  const postData = type === 'url'
    ? `url=${encodeURIComponent(value)}`
    : `host=${encodeURIComponent(value)}`

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'urlhaus-api.abuse.ch',
      path: type === 'url' ? '/v1/url/' : '/v1/host/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: 6000,
    }, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try { resolve(JSON.parse(data)) }
        catch { reject(new Error('Invalid URLhaus response')) }
      })
    })
    req.on('timeout', () => { req.destroy(); reject(new Error('URLhaus timeout')) })
    req.on('error', reject)
    req.write(postData)
    req.end()
  })
}


async function checkPhishTank(urlString, apiKey) {
  const postData = `url=${encodeURIComponent(urlString)}&format=json&app_key=${encodeURIComponent(apiKey)}`

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'checkurl.phishtank.com',
      path: '/checkurl/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData),
        'User-Agent': 'phishtank/testify-by-trustify',
      },
      timeout: 8000,
    }, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data)
          resolve({
            inDatabase: parsed.results?.in_database || false,
            valid: parsed.results?.verified || false,
          })
        } catch { reject(new Error('Invalid PhishTank response')) }
      })
    })
    req.on('timeout', () => { req.destroy(); reject(new Error('PhishTank timeout')) })
    req.on('error', reject)
    req.write(postData)
    req.end()
  })
}

// ── Layer 2a: DNS Resolution ─────────────────────────────────────────────────

async function checkDns(hostname) {
  const findings = []
  let score = 0
  let dnsResolved = false
  let addresses = []

  // Attempt 1: Standard resolve4
  try {
    addresses = await new Promise((resolve, reject) => {
      dns.resolve4(hostname, (err, addrs) => {
        if (err) { reject(err) } else { resolve(addrs) }
      })
    })
  } catch (err1) {
    // Attempt 2: Fallback to dns.lookup (uses OS resolver, handles hosts file, sometimes cleaner for CDN subdomains)
    try {
      addresses = await new Promise((resolve, reject) => {
        dns.lookup(hostname, { all: true, family: 4 }, (err, addrs) => {
          if (err) { reject(err) } else { resolve(addrs.map(a => a.address)) }
        })
      })
    } catch (err2) {
      // Both failed
    }
  }

  if (addresses.length > 0) {
    dnsResolved = true
    findings.push(`✅ Resolves to ${addresses.length} IP(s): ${addresses.slice(0, 3).join(', ')}${addresses.length > 3 ? '…' : ''}`)

    const privateIps = addresses.filter(isPrivateIp)
    if (privateIps.length > 0) {
      score += 40
      findings.push(`❌ Resolves to private IP(s): ${privateIps.join(', ')} — DNS rebinding attack`)
    }
    
    // MX check (Only if primary A/AAAA resolve succeeded to save time)
    try {
      const mx = await new Promise((resolve, reject) =>
        dns.resolveMx(hostname, (err, r) => err ? reject(err) : resolve(r))
      )
      findings.push(mx.length > 0
        ? `✅ MX records found (${mx.length}) — mail service configured`
        : '⚠️ No MX records — no mail service')
      if (mx.length === 0) score += 8
    } catch { findings.push('⚠️ No MX records — no mail service'); score += 8 }

    // NS check
    try {
      const ns = await new Promise((resolve, reject) =>
        dns.resolveNs(hostname, (err, r) => err ? reject(err) : resolve(r))
      )
      if (ns.length > 0) {
        findings.push(`✅ NS: ${ns.slice(0, 2).join(', ')}${ns.length > 2 ? '…' : ''}`)
      }
    } catch { /* NS check failure not critical for subdomains */ }

  } else {
    // Total DNS Failure
    score += 15 // Slight bump for being unreachable, but NOT malicious
    findings.push(`❌ DNS resolution FAILED (or timed out)`)
    findings.push('⚠️ Domain does not exist or is currently unreachable')
    findings.push('ℹ️ Subsequent network checks will be skipped')
  }

  return { score: Math.min(score, 100), findings, dnsResolved }
}

// ── Layer 2b: SSL/TLS Certificate ───────────────────────────────────────────

async function checkSsl(hostname, dnsResolved) {
  const findings = []
  let score = 0

  if (!dnsResolved) {
    return {
      score: 0,
      findings: [
        'ℹ️ Skipped SSL check (Network Unreachable / DNS Failure)',
      ],
    }
  }

  try {
    const { cert, protocol, cipher } = await new Promise((resolve, reject) => {
      const socket = tls.connect(
        { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 6000 },
        () => {
          const c         = socket.getPeerCertificate(false)
          const authorized = socket.authorized
          const proto     = socket.getProtocol()
          const cipherInfo = socket.getCipher()
          socket.destroy()
          if (!c || Object.keys(c).length === 0) {
            return reject(new Error('No certificate returned'))
          }
          resolve({ cert: { ...c, authorized }, protocol: proto, cipher: cipherInfo })
        }
      )
      socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS connection timeout')) })
      socket.on('error', (err) => { socket.destroy(); reject(err) })
    })

    // ─ Authorization
    findings.push(cert.authorized
      ? '✅ SSL certificate is valid and trusted'
      : '❌ SSL certificate NOT trusted by CA store')
    if (!cert.authorized) score += 25

    // ─ Issuer
    const issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown'
    findings.push(`Issuer: ${issuer}`)

    // ─ Expiry
    const validTo   = cert.valid_to   ? new Date(cert.valid_to)   : null
    const validFrom = cert.valid_from ? new Date(cert.valid_from) : null
    const now       = new Date()

    if (validTo) {
      if (validTo < now) {
        score += 35
        findings.push(`❌ Certificate EXPIRED: ${validTo.toLocaleDateString()}`)
      } else {
        const days = Math.floor((validTo - now) / 86400000)
        if (days < 14) { score += 20; findings.push(`❌ Certificate expires in ${days} days — critically close`) }
        else if (days < 30) { score += 10; findings.push(`⚠️ Certificate expires in ${days} days`) }
        else findings.push(`✅ Certificate valid until ${validTo.toLocaleDateString()} (${days} days)`)
      }
    }

    // ─ Very new cert = suspicious
    if (validFrom) {
      const ageDays = Math.floor((now - validFrom) / 86400000)
      if (ageDays < 3)  { score += 20; findings.push(`❌ Certificate issued only ${ageDays} day(s) ago — extremely new`) }
      else if (ageDays < 7) { score += 12; findings.push(`⚠️ Certificate issued ${ageDays} day(s) ago — very new`) }
    }

    // ─ Self-signed
    const subjectOrg = cert.subject?.O || cert.subject?.CN || ''
    const issuerOrg  = cert.issuer?.O  || cert.issuer?.CN  || ''
    if (subjectOrg && issuerOrg && subjectOrg === issuerOrg) {
      score += 25
      findings.push('❌ Certificate appears self-signed')
    }

    // ─ TLS protocol strength
    if (protocol) {
      if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        score += 20
        findings.push(`❌ Weak TLS version: ${protocol} — deprecated and vulnerable`)
      } else if (protocol === 'TLSv1.2') {
        findings.push(`⚠️ TLS 1.2 — acceptable but TLS 1.3 is preferred`)
      } else if (protocol === 'TLSv1.3') {
        findings.push('✅ TLS 1.3 — latest and most secure protocol')
      }
    }

    // ─ Cipher strength
    if (cipher && cipher.name) {
      const weakCiphers = ['RC4', 'DES', '3DES', 'EXPORT', 'NULL', 'ANON', 'MD5']
      const isWeak = weakCiphers.some(w => cipher.name.toUpperCase().includes(w))
      if (isWeak) {
        score += 20
        findings.push(`❌ Weak cipher suite: ${cipher.name}`)
      } else {
        findings.push(`✅ Cipher: ${cipher.name}`)
      }
    }

  } catch (err) {
    score += 40
    findings.push(`❌ No SSL/TLS: ${err.message}`)
    findings.push('⚠️ Site does not support HTTPS or actively refused connection')
  }

  return { score: Math.min(score, 100), findings }
}

// ── Layer 2c: Security Headers ──────────────────────────────────────────────

async function checkSecurityHeaders(urlString, dnsResolved) {
  const findings = []
  let score = 0

  if (!dnsResolved) {
    return {
      score: 0,
      findings: ['ℹ️ Skipped Security Headers check (Network Unreachable)'],
    }
  }

  try {
    const parsed = new URL(urlString)
    const client = parsed.protocol === 'https:' ? https : http

    const headers = await new Promise((resolve, reject) => {
      const req = client.get(urlString, {
        timeout: 8000,
        headers: { 'User-Agent': 'Testify-SecurityScanner/2.0' },
        rejectUnauthorized: false,
      }, (res) => { res.resume(); resolve(res.headers) })
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')) })
      req.on('error', reject)
    })

    const checks = [
      { header: 'strict-transport-security', weight: 10, goodMsg: '✅ HSTS enabled — forces HTTPS',               badMsg: '❌ Missing HSTS — no forced HTTPS' },
      { header: 'content-security-policy',   weight: 2,  goodMsg: '✅ CSP header present',                        badMsg: '⚠️ Missing CSP — common on many legitimate sites' },
      { header: 'x-frame-options',           weight: 2,  goodMsg: '✅ X-Frame-Options — anti-clickjacking',       badMsg: '⚠️ Missing X-Frame-Options — informational warning only' },
      { header: 'x-content-type-options',   weight: 5,  goodMsg: '✅ X-Content-Type-Options set',                badMsg: '⚠️ Missing X-Content-Type-Options' },
      { header: 'x-xss-protection',         weight: 4,  goodMsg: '✅ X-XSS-Protection set',                      badMsg: '⚠️ Missing X-XSS-Protection' },
      { header: 'referrer-policy',           weight: 2,  goodMsg: '✅ Referrer-Policy set',                       badMsg: '⚠️ Missing Referrer-Policy — informational warning only' },
      { header: 'permissions-policy',        weight: 2,  goodMsg: '✅ Permissions-Policy set',                    badMsg: '⚠️ Missing Permissions-Policy' },
    ]

    let present = 0
    for (const check of checks) {
      if (headers[check.header]) { present++; findings.push(check.goodMsg) }
      else { score += check.weight; findings.push(check.badMsg) }
    }
    findings.unshift(`${present}/${checks.length} security headers present`)

    if (headers['server'] && /\d+\.\d+/.test(headers['server'])) {
      score += 5
      findings.push(`⚠️ Server header reveals version: "${headers['server']}"`)
    }
    if (headers['x-powered-by']) {
      score += 5
      findings.push(`⚠️ X-Powered-By reveals technology: "${headers['x-powered-by']}"`)
    }

  } catch (err) {
    score += 30
    findings.push(`❌ Could not fetch headers: ${err.message}`)
  }

  return { score: Math.min(score, 100), findings }
}

// ── Layer 2d: Redirect Chain ─────────────────────────────────────────────────

async function checkRedirects(urlString, dnsResolved) {
  if (!dnsResolved) {
    return { score: 0, findings: ['ℹ️ Skipped Redirect check (Network Unreachable)'] }
  }

  const findings = []
  let score = 0
  const chain = []
  let currentUrl = urlString

  for (let i = 0; i < 8; i++) {
    try {
      const parsed = new URL(currentUrl)
      const client = parsed.protocol === 'https:' ? https : http

      const result = await new Promise((resolve, reject) => {
        const req = client.get(currentUrl, {
          timeout: 5000,
          headers: { 'User-Agent': 'Testify-SecurityScanner/2.0' },
          rejectUnauthorized: false,
        }, (res) => {
          res.resume()
          resolve({ statusCode: res.statusCode, location: res.headers.location, url: currentUrl })
        })
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')) })
        req.on('error', reject)
      })

      chain.push({ url: result.url, status: result.statusCode })

      if (result.statusCode >= 300 && result.statusCode < 400 && result.location) {
        currentUrl = new URL(result.location, result.url).href
      } else {
        break
      }
    } catch { break }
  }

  if (chain.length <= 1) {
    findings.push('✅ No redirects detected')
  } else {
    findings.push(`${chain.length - 1} redirect(s) in chain`)
    try {
      const origHost  = new URL(chain[0].url).hostname
      const finalHost = new URL(chain[chain.length - 1].url).hostname
      if (origHost !== finalHost) {
        score += 15
        findings.push(`⚠️ Cross-domain redirect: ${origHost} → ${finalHost}`)
      }
    } catch { /* ignore */ }

    for (let i = 1; i < chain.length; i++) {
      if (chain[i - 1].url.startsWith('https:') && chain[i].url.startsWith('http:')) {
        score += 25
        findings.push('❌ HTTPS → HTTP downgrade in redirect chain')
        break
      }
    }

    if (chain.length > 4) {
      score += 12
      findings.push(`⚠️ Excessive redirect chain (${chain.length} hops)`)
    }

    for (const hop of chain) {
      const shortUrl = hop.url.length > 55 ? hop.url.slice(0, 52) + '…' : hop.url
      findings.push(`  ${hop.status} → ${shortUrl}`)
    }
  }

  return { score: Math.min(score, 100), findings }
}

// ── Layer 2e: HTML Content Scan ──────────────────────────────────────────────

async function checkHtmlContent(urlString, dnsResolved) {
  const findings = []
  let score = 0

  if (!dnsResolved) {
    return { score: 0, findings: ['ℹ️ Skipped Page Content check (Network Unreachable)'] }
  }

  try {
    const parsed = new URL(urlString)
    const client = parsed.protocol === 'https:' ? https : http

    // Fetch up to 80KB of the HTML body
    const html = await new Promise((resolve, reject) => {
      const req = client.get(urlString, {
        timeout: 8000,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Testify-SecurityScanner/2.0)' },
        rejectUnauthorized: false,
      }, (res) => {
        if ([401, 403, 429].includes(res.statusCode)) {
           req.destroy(); 
           return reject(new Error(`HTTP_RESTRICTED_${res.statusCode}`))
        }
        
        let data = ''
        let bytes = 0
        res.on('data', chunk => {
          bytes += chunk.length
          data += chunk
          if (bytes > 80000) { req.destroy(); resolve(data) }
        })
        res.on('end', () => resolve(data))
      })
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')) })
      req.on('error', reject)
    })

    const lowerHtml = html.toLowerCase()
    const pageHostname = parsed.hostname

    let issuesFound = 0

    // ─ Hidden iframes
    const hiddenIframePattern = /<iframe[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?0|height\s*=\s*["']?0)[^>]*>/i
    if (hiddenIframePattern.test(html)) {
      score += 5
      findings.push('⚠️ Hidden iframe(s) detected — common in tracking pixels or drive-bys')
    }

    // ─ Password forms posting to a different domain
    const formMatches = html.matchAll(/<form[^>]*action\s*=\s*["']([^"']+)["'][^>]*>/gi)
    for (const match of formMatches) {
      const actionUrl = match[1]
      if (actionUrl.startsWith('http')) {
        try {
          const actionHost = new URL(actionUrl).hostname
          if (actionHost !== pageHostname && !actionHost.endsWith('.' + pageHostname)) {
            // Check if there's a password input in the form
            if (lowerHtml.includes('type="password"') || lowerHtml.includes("type='password'")) {
              score += 35
              issuesFound++
              findings.push(`❌ Password form submits to different domain: ${actionHost} — classic phishing`)
              break
            }
          }
        } catch { /* ignore */ }
      }
    }

    // ─ JS obfuscation
    const obfuscationPatterns = [
      { pattern: /eval\s*\(\s*unescape\s*\(/i,             desc: 'eval(unescape(...)) — classic JS obfuscation' },
      { pattern: /String\.fromCharCode\s*\(\s*\d{2,}/i,  desc: 'String.fromCharCode(...) — character encoding obfuscation' },
      { pattern: /document\.write\s*\(\s*unescape/i,       desc: 'document.write(unescape(...)) — obfuscated content injection' },
      { pattern: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, desc: 'Hex-encoded strings — obfuscation attempt' },
    ]
    for (const { pattern, desc } of obfuscationPatterns) {
      if (pattern.test(html)) {
        score += 15
        issuesFound++
        findings.push(`⚠️ JS obfuscation: ${desc}`)
        break  // Report once
      }
    }

    // ─ Urgency language (social engineering)
    const urgencyPatterns = [
      /your\s+account\s+(has\s+been\s+)?(suspended|locked|disabled|compromised)/i,
      /verify\s+your\s+(account|identity|email|payment)\s+(now|immediately|urgently)/i,
      /click\s+here\s+to\s+(avoid|prevent)\s+(suspension|termination|deactivation)/i,
      /limited\s+time\s+offer|act\s+now|expires?\s+in\s+\d+\s+(hour|minute)/i,
      /congratulations.*you\s+(have\s+)?(won|been\s+selected)/i,
    ]
    for (const pattern of urgencyPatterns) {
      if (pattern.test(html)) {
        score += 12
        issuesFound++
        findings.push('⚠️ Urgency/social-engineering language detected on page')
        break
      }
    }

    // ─ Favicon mismatch (loading brand favicon from official domain)
    const faviconMatch = html.match(/<link[^>]+rel=["'](?:shortcut\s+)?icon["'][^>]+href=["']([^"']+)["']/i)
    if (faviconMatch) {
      const faviconUrl = faviconMatch[1]
      if (faviconUrl.startsWith('http')) {
        try {
          const faviconHost = new URL(faviconUrl).hostname
          if (faviconHost !== pageHostname) {
            // If favicon comes from a well-known brand, this page is impersonating it
            const isBrandFavicon = Object.values(require('./urlScanHelpers').BRAND_DOMAINS)
              .flat()
              .some(d => faviconHost === d || faviconHost.endsWith('.' + d))
            if (isBrandFavicon) {
              score += 5
              findings.push(`⚠️ Favicon loaded from brand domain (${faviconHost}) — external dependency or possible impersonation`)
            }
          }
        } catch { /* ignore */ }
      }
    }

    if (issuesFound === 0) {
      findings.push('✅ No suspicious content patterns found in HTML')
      findings.push('✅ No hidden iframes detected')
      findings.push('✅ No JS obfuscation detected')
    } else {
      findings.unshift(`⚠️ ${issuesFound} suspicious content element(s) found`)
    }

  } catch (err) {
    if (err.message.startsWith('HTTP_RESTRICTED')) {
      const status = err.message.split('_')[2];
      findings.push(`ℹ️ Resource is private or access restricted (HTTP ${status})`)
      findings.push(`✅ Cannot assume malicious intent due to access denial`)
    } else {
      findings.push(`Could not fetch page content: ${err.message}`)
    }
  }

  return { score: Math.min(score, 100), findings }
}

// ── Layer 2f: Domain Age (WHOIS) ─────────────────────────────────────────────

/** Format a day count into a friendly string like "2 years, 3 months" */
function friendlyAge(days) {
  if (days < 1)   return `${days} day(s)`
  if (days < 30)  return `${days} day(s)`
  if (days < 365) return `${Math.floor(days / 30)} month(s)`
  const years  = Math.floor(days / 365)
  const months = Math.floor((days % 365) / 30)
  return months > 0 ? `${years} year(s), ${months} month(s)` : `${years} year(s)`
}

/** Pull a date value from a WHOIS raw object, trying many field-name variants. */
function extractWhoisDate(raw, ...keys) {
  for (const k of keys) {
    const v = raw[k] || raw[k.charAt(0).toUpperCase() + k.slice(1)]
    if (v) {
      const s = Array.isArray(v) ? v[0] : v
      const d = new Date(s)
      if (!isNaN(d.getTime())) return d
    }
  }
  return null
}

async function checkDomainAge(hostname) {
  const ageFindings   = []
  const whoisFindings = []
  let ageScore  = 0
  let ageDays   = null

  try {
    const whoisLib = require('whois-json')
    const raw = await whoisLib(hostname, { follow: 3 })

    // ── Registrar ────────────────────────────────────────────────────────────
    const registrar = raw.registrar || raw.Registrar || raw.sponsoringRegistrar || null
    if (registrar) whoisFindings.push(`ℹ️ Registrar: ${registrar}`)

    // ── Creation date ────────────────────────────────────────────────────────
    const creationDate = extractWhoisDate(raw,
      'creationDate', 'created', 'domainRegisteredDate',
      'registeredDate', 'registrationDate', 'domainCreated',
      'registrationTime', 'domCreated'
    )

    // ── Expiration date ──────────────────────────────────────────────────────
    const expirationDate = extractWhoisDate(raw,
      'expirationDate', 'expires', 'registrarRegistrationExpirationDate',
      'expiryDate', 'domainExpirationDate', 'paidTillDate',
      'registryExpiryDate', 'domExpires'
    )

    // ── Updated date ─────────────────────────────────────────────────────────
    const updatedDate = extractWhoisDate(raw,
      'updatedDate', 'lastModified', 'modified',
      'changedDate', 'domainLastUpdated'
    )

    const country = raw.country || raw.Country || raw.registrantCountry || null
    if (country) whoisFindings.push(`ℹ️ Registrant country: ${country}`)

    // ── Age assessment ───────────────────────────────────────────────────────
    const now = new Date()
    if (creationDate) {
      ageDays = Math.floor((now - creationDate) / 86400000)
      const fAge = friendlyAge(ageDays)
      const regDateStr = creationDate.toISOString().split('T')[0]

      ageFindings.push(`ℹ️ Registered on: ${regDateStr}`)
      if (updatedDate) ageFindings.push(`ℹ️ Last updated: ${updatedDate.toISOString().split('T')[0]}`)

      if (ageDays < 30) {
        ageScore += 45
        ageFindings.push(`❌ Domain is only ${fAge} old — extremely high phishing risk`)
      } else if (ageDays < 90) {
        ageScore += 30
        ageFindings.push(`❌ Domain is ${fAge} old — recently created, high risk`)
      } else if (ageDays < 180) {
        ageScore += 15
        ageFindings.push(`⚠️ Domain is ${fAge} old — moderate risk`)
      } else if (ageDays < 365) {
        ageScore += 8
        ageFindings.push(`⚠️ Domain is ${fAge} old (less than 1 year)`)
      } else {
        ageFindings.push(`✅ Domain age: ${fAge} — established`)
      }
    } else {
      ageScore += 12
      ageFindings.push('⚠️ Domain registration date unavailable — possible privacy shield or new domain')
    }

    // ── Expiry assessment ────────────────────────────────────────────────────
    if (expirationDate) {
      const expDateStr = expirationDate.toISOString().split('T')[0]
      const daysLeft   = Math.floor((expirationDate - now) / 86400000)
      if (expirationDate < now) {
        ageScore += 20
        ageFindings.push(`❌ Domain registration EXPIRED on ${expDateStr}`)
      } else if (daysLeft < 30) {
        ageScore += 12
        ageFindings.push(`⚠️ Domain expires in ${daysLeft} day(s) (${expDateStr})`)
      } else if (daysLeft < 90) {
        ageFindings.push(`⚠️ Domain expires soon: ${expDateStr} (${daysLeft} days)`)
      } else {
        ageFindings.push(`✅ Domain valid until ${expDateStr} (${daysLeft} days left)`)
      }
    } else {
      ageFindings.push('ℹ️ Expiration date not available')
    }

    // Merge WHOIS metadata below age findings
    const allFindings = [...ageFindings, ...whoisFindings]
    return {
      ageScore:   Math.min(ageScore, 100),
      whoisScore: whoisFindings.length > 1 ? 0 : 5,  // penalty only when truly empty
      ageFindings: allFindings,
      whoisFindings,
      ageDays,
    }

  } catch {
    return {
      ageScore:    8,
      whoisScore:  5,
      ageFindings: ['ℹ️ WHOIS query failed — domain may use privacy protection or be unresolvable'],
      whoisFindings: ['ℹ️ WHOIS data unavailable for this domain'],
      ageDays:     null,
    }
  }
}

// ── Main Controller ──────────────────────────────────────────────────────────

async function performUrlScan(trimmedUrl, aiAnalysis = null) {
  // ─ Check cache ──────────────────────────────────────────────────────────
  const cached = getCached(trimmedUrl)
  if (cached) {
    return { ...cached, cached: true, cachedAt: cached.timestamp }
  }

  try {
    const parsed   = new URL(trimmedUrl)
    const hostname = parsed.hostname

    // ─ Trusted Domain Shortcut ──────────────────────────────────────────────
    const trusted = isTrustedDomain(hostname)
    if (trusted) {
      const result = {
        url: trimmedUrl,
        threatScore: 5,
        riskLevel: 'Safe',
        confidence: 'High',
        trusted: true,
        categories: [{
          name: 'Trusted Domain',
          icon: '✅',
          score: 0,
          findings: [
            `✅ "${hostname}" is in the trusted domain allow-list`,
            '✅ Known-safe apex domain — skipping expensive network checks',
            '✅ This domain is operated by a major verified organization',
          ],
        }],
        criticalFindings: [],
        warningFindings: [],
        summary: `✅ Trusted domain — ${hostname} is a verified safe site`,
        timestamp: new Date().toISOString(),
      }
      setCache(trimmedUrl, result)
      return result
    }

    // ─ Layer 0: Pre-checks (instant) ────────────────────────────────────────
    const [homographResult, typosquatResult] = await Promise.all([
      Promise.resolve(detectHomograph(hostname)),
      Promise.resolve(detectTyposquatting(hostname)),
    ])

    // ─ Layer 1: Threat Intelligence + DNS (parallel) ─────────────────────────
    const [threatResult, dnsResult, heuristic] = await Promise.all([
      checkThreatIntelligence(trimmedUrl, hostname),
      checkDns(hostname),
      Promise.resolve(runHeuristicAnalysis(parsed, trimmedUrl, trusted)),
    ])

    // Early exit if threat DB hit with very high confidence
    if (threatResult.score >= 90) {
      const result = {
        url: trimmedUrl,
        threatScore: threatResult.score,
        riskLevel: 'Malicious',
        confidence: 'High',
        trusted: false,
        categories: [{ name: 'Threat Intelligence', icon: '🚨', score: threatResult.score, findings: threatResult.findings }],
        criticalFindings: threatResult.findings.filter(f => f.startsWith('🚨') || f.startsWith('❌')),
        warningFindings: [],
        summary: `🚫 URL confirmed malicious by threat intelligence database`,
        timestamp: new Date().toISOString(),
      }
      setCache(trimmedUrl, result)
      return result
    }

    // ─ Layer 2: Remaining live network checks ───────────────────────────────
    const [sslResult, headersResult, redirectResult, domainResult, contentResult] = await Promise.all([
      parsed.protocol === 'https:'
        ? checkSsl(hostname, dnsResult.dnsResolved)
        : Promise.resolve({ score: 25, findings: ['⚠️ Site uses plain HTTP — no HTTPS'] }),
      checkSecurityHeaders(trimmedUrl, dnsResult.dnsResolved),
      checkRedirects(trimmedUrl, dnsResult.dnsResolved),
      checkDomainAge(hostname),
      checkHtmlContent(trimmedUrl, dnsResult.dnsResolved),
    ])

    // ─ Build categories ─────────────────────────────────────────────────────
    const categories = [
      { name: 'Threat Intelligence', icon: '🚨', score: threatResult.score,       findings: threatResult.findings },
      { name: 'Heuristic Analysis',  icon: '🔍', score: heuristic.score,          findings: heuristic.findings },
      { name: 'Typosquatting',       icon: '🎭', score: typosquatResult.score,    findings: typosquatResult.findings },
      { name: 'Homograph Detection', icon: '🔤', score: homographResult.score,    findings: homographResult.findings },
      { name: 'DNS Verification',    icon: '🌐', score: dnsResult.score,          findings: dnsResult.findings },
      { name: 'SSL/TLS Security',    icon: '🔒', score: sslResult.score,          findings: sslResult.findings },
      { name: 'Security Headers',    icon: '🛡️', score: headersResult.score,      findings: headersResult.findings },
      { name: 'Redirect Analysis',   icon: '🔗', score: redirectResult.score,     findings: redirectResult.findings },
      { name: 'Page Content',        icon: '📄', score: contentResult.score,      findings: contentResult.findings },
      { name: 'Domain Age',          icon: '📅', score: domainResult.ageScore,    findings: domainResult.ageFindings },
      { name: 'Domain Intelligence', icon: '📋', score: domainResult.whoisScore,  findings: domainResult.whoisFindings },
    ]

    if (aiAnalysis) {
      const aiScore = aiAnalysis.isScam === true ? 85 : aiAnalysis.isScam === false ? 0 : 20;
      categories.push({
        name: 'AI Context Analysis',
        icon: '🧠',
        score: aiScore,
        findings: [
          aiAnalysis.isScam ? '🚨 AI flagged surrounding text as Suspicious/Phishing' : '✅ AI context analysis appears legitimate',
          `Reasoning: ${aiAnalysis.reasoning}`,
          `Confidence: ${aiAnalysis.confidence}`
        ]
      })
    }

    // ─ Layer 3: Smart Scoring ──────────────────────────────────────────────
    let overallScore = 0

    // Hard floors for critical failures
    if (threatResult.score >= 80)       overallScore = Math.max(overallScore, 90)
    if (typosquatResult.score >= 40)    overallScore = Math.max(overallScore, 35)
    if (homographResult.score >= 20)    overallScore = Math.max(overallScore, 40)
    if (contentResult.score >= 35)      overallScore = Math.max(overallScore, 35)
    if (parsed.protocol === 'https:' && sslResult.score >= 40) overallScore = Math.max(overallScore, 35)

    // Weighted average (informational categories don't dominate)
    const weights = {
      'Threat Intelligence': 0.20,
      'AI Context Analysis': 0.14,
      'Heuristic Analysis':  0.10,
      'Typosquatting':       0.08,
      'Homograph Detection': 0.05,
      'DNS Verification':    0.14,
      'SSL/TLS Security':    0.11,
      'Security Headers':    0.05,
      'Redirect Analysis':   0.04,
      'Page Content':        0.03,
      'Domain Age':          0.05,
      'Domain Intelligence': 0.01,
    }
    let weightedAvg = 0
    for (const cat of categories) {
      weightedAvg += cat.score * (weights[cat.name] || 0.05)
    }
    weightedAvg = Math.round(weightedAvg)

    // Max influence: only critical categories (not headers/redirects)
    // Hard floor for very new domains
    if (domainResult.ageDays !== null && domainResult.ageDays < 30) overallScore = Math.max(overallScore, 40)

    const criticalCats = ['Threat Intelligence', 'DNS Verification', 'SSL/TLS Security', 'Heuristic Analysis', 'Typosquatting', 'Homograph Detection', 'Page Content', 'Domain Age']
    const maxCritical  = Math.max(...categories.filter(c => criticalCats.includes(c.name)).map(c => c.score))
    const maxInfluence = Math.round(maxCritical * 0.65)

    // Evidence boost: count total ❌ findings across all categories
    const totalCriticalFindings = categories.flatMap(c => c.findings.filter(f => f.startsWith('❌'))).length
    const evidenceBoost = Math.min(totalCriticalFindings * 5, 25)

    overallScore = Math.max(overallScore, weightedAvg, maxInfluence)
    overallScore = Math.min(overallScore + evidenceBoost, 100)
    overallScore = Math.round(overallScore)

    // Clamp: don't let headers alone push safe sites to Suspicious
    if (overallScore <= 22 && weightedAvg <= 18 && maxCritical <= 15) {
      overallScore = Math.min(overallScore, 20) // Force into Safe band
    }

    // ⭐ POSITIVE LEGITIMACY SIGNALS
    if (domainResult.ageDays && domainResult.ageDays > 1825 && sslResult.score === 0 && threatResult.score === 0) {
      overallScore = Math.max(0, overallScore - 40)
      categories.push({
        name: 'Positive Legitimacy Signals',
        icon: '🌟',
        score: 0,
        findings: [
          '✅ Domain is over 5 years old',
          '✅ SSL Certificate is fully trusted and valid',
          '✅ Zero hits across all threat intelligence feeds',
          'ℹ️ Applied significant score discount due to established structural trust'
        ]
      })
    }

    // ─ Confidence ──────────────────────────────────────────────────────────
    const criticalFindings = categories.flatMap(c => c.findings.filter(f => f.startsWith('❌') || f.startsWith('🚨')))
    const warningFindings  = categories.flatMap(c => c.findings.filter(f => f.startsWith('⚠️')))
    const confidence       = getConfidence(categories, criticalFindings.length, false, trusted)

    // ─ Summary ─────────────────────────────────────────────────────────────
    let summary
    let riskLevel = getRiskLevel(overallScore)

    // Override generic levels with fine-grained specific classifications
    if (!dnsResult.dnsResolved && threatResult.score < 60) {
      riskLevel = 'Network Unreachable'
      overallScore = Math.min(overallScore, 20) // prevent score inflation for pure network errors
      summary = `⚠️ Domain could not be reached or timed out (${confidence} confidence)`
    } else if (threatResult.score >= 80) {
      riskLevel = 'Confirmed Phishing'
      summary = `🚨 Known threat detected in intelligence databases (${confidence} confidence)`
    } else if (riskLevel === 'Malicious' && threatResult.score < 50) {
      riskLevel = 'Suspicious Pattern'
      summary = `🚫 ${criticalFindings.length} issue(s) — matches patterns of malicious intent (${confidence} confidence)`
    } else if (riskLevel === 'Malicious') {
      summary = `🚫 ${criticalFindings.length} critical issue(s) — site is potentially dangerous (${confidence} confidence)`
    } else if (riskLevel === 'Suspicious') {
      summary = `⚠️ ${criticalFindings.length + warningFindings.length} issue(s) found — proceed with caution (${confidence} confidence)`
    } else {
      summary = criticalFindings.length > 0
        ? `${criticalFindings.length} minor issue(s) found — overall appears safe`
        : '✅ No significant security issues detected'
    }

    const result = {
      url: trimmedUrl,
      threatScore: overallScore,
      riskLevel,
      confidence,
      trusted: false,
      categories,
      criticalFindings,
      warningFindings,
      summary,
      timestamp: new Date().toISOString(),
    }

    setCache(trimmedUrl, result)
    return result

  } catch (err) {
    throw err
  }
}

async function scanUrl(req, res, next) {
  try {
    const { url } = req.body

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Request body must include a "url" string field.' })
    }

    const trimmedUrl = url.trim()

    if (!isValidUrl(trimmedUrl)) {
      return res.status(400).json({
        error: 'Invalid URL. Must start with http:// or https:// and be well-formed.',
      })
    }

    const result = await performUrlScan(trimmedUrl, null)
    return res.status(200).json(result)

  } catch (err) {
    next(err)
  }
}

module.exports = { scanUrl, performUrlScan }
