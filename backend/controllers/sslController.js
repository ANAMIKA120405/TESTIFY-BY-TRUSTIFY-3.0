/**
 * SSL/TLS Certificate Checker
 * POST /api/check-ssl
 * Uses Node built-ins: tls, dns
 */

'use strict'

const tls = require('tls')
const dns = require('dns')
const { isPrivateIp } = require('./urlScanHelpers')

/**
 * Resolve a hostname to verify it exists before attempting TLS.
 * @param {string} hostname
 * @returns {Promise<string>} resolved IP
 */
function resolveHost(hostname) {
  return new Promise((resolve, reject) => {
    dns.lookup(hostname, (err, address) => {
      if (err) reject(err)
      else resolve(address)
    })
  })
}

/**
 * Connect via TLS and retrieve the peer certificate details.
 * @param {string} hostname
 * @returns {Promise<{cert: object}>}
 */
function fetchCertificate(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,   // SNI
        // S-09: Intentionally allowing unauthorized certs so we can analyze them
        // (e.g. to reporting exact expiry dates or self-signed status) instead of just failing.
        rejectUnauthorized: false,
        timeout: 8000,
      },
      () => {
        const cert = socket.getPeerCertificate(false)
        socket.destroy()

        if (!cert || Object.keys(cert).length === 0) {
          return reject(new Error('No certificate returned by server'))
        }
        resolve({ cert })
      }
    )

    socket.on('timeout', () => {
      socket.destroy()
      reject(new Error('Connection timed out after 8 s'))
    })

    socket.on('error', (err) => {
      socket.destroy()
      reject(err)
    })
  })
}

/**
 * POST /api/check-ssl
 * Body: { domain: string }
 */
async function checkSSL(req, res) {
  const { domain } = req.body

  if (!domain || typeof domain !== 'string' || domain.trim() === '') {
    return res.status(400).json({ error: 'domain is required' })
  }

  // Strip any protocol prefix the user might have typed
  const cleanDomain = domain
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')       // remove path
    .split(':')[0]              // remove explicit port

  // 1️⃣  DNS check
  let resolvedIP
  try {
    resolvedIP = await resolveHost(cleanDomain)
  } catch {
    return res.status(422).json({
      error: `Could not resolve domain "${cleanDomain}". Check the name and try again.`,
    })
  }

  // Block private IPs to prevent SSRF or scanning internal networks
  if (isPrivateIp(resolvedIP)) {
    return res.status(403).json({
      error: 'Forbidden target',
      message: 'Scanning private or internal IP addresses is not allowed.',
    })
  }

  // 2️⃣  TLS check
  let cert
  let httpsAvailable = false

  try {
    ;({ cert } = await fetchCertificate(cleanDomain))
    httpsAvailable = true
  } catch (err) {
    // HTTPS not reachable — return High Risk without certificate details
    return res.status(200).json({
      domain: cleanDomain,
      httpsAvailable: false,
      issuer: null,
      validFrom: null,
      validTo: null,
      subject: null,
      isExpired: null,
      riskLevel: 'High Risk',
      error: err.message,
      timestamp: new Date(),
    })
  }

  // 3️⃣  Parse certificate fields
  const subject = cert.subject?.CN ?? cert.subject?.O ?? null
  const issuer  = cert.issuer?.O  ?? cert.issuer?.CN  ?? null

  // valid_from / valid_to come back as locale strings like "Jan  1 00:00:00 2024 GMT"
  const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : null
  const validTo   = cert.valid_to   ? new Date(cert.valid_to).toISOString()   : null

  const now       = new Date()
  const expiryDate = validTo ? new Date(validTo) : null
  const isExpired  = expiryDate ? expiryDate < now : null

  // 4️⃣  Risk classification
  let riskLevel
  if (!httpsAvailable) {
    riskLevel = 'High Risk'
  } else if (isExpired) {
    riskLevel = 'Medium Risk'
  } else {
    riskLevel = 'Secure'
  }

  return res.status(200).json({
    domain: cleanDomain,
    httpsAvailable,
    subject,
    issuer,
    validFrom,
    validTo,
    isExpired,
    riskLevel,
    timestamp: new Date(),
  })
}

module.exports = { checkSSL }
