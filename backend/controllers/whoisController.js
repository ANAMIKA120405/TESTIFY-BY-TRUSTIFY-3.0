/**
 * WHOIS Lookup
 * POST /api/whois-lookup
 * Uses: whois-json (npm)
 */

'use strict'

const whois = require('whois-json')

/** Safely parse a date string — returns null if invalid. */
function parseDate(value) {
  if (!value) return null
  const d = new Date(value)
  return isNaN(d.getTime()) ? null : d
}

/** Days between two Date objects. */
function daysBetween(a, b) {
  return Math.floor(Math.abs(b - a) / (1000 * 60 * 60 * 24))
}

/**
 * POST /api/whois-lookup
 * Body: { domain: string }
 */
async function whoisLookup(req, res) {
  const { domain } = req.body

  if (!domain || typeof domain !== 'string' || domain.trim() === '') {
    return res.status(400).json({ error: 'domain is required' })
  }

  const cleanDomain = domain
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .split(':')[0]

  let raw
  try {
    raw = await whois(cleanDomain)
  } catch (err) {
    return res.status(502).json({
      error: `WHOIS query failed: ${err.message}`,
    })
  }

  // --- Extract fields (whois-json uses camelCase keys) ---
  const registrar       = raw.registrar         ?? raw.Registrar         ?? null
  const creationDateRaw = raw.creationDate       ?? raw.CreationDate       ?? raw.created        ?? null
  const expirationDateRaw = raw.expirationDate   ?? raw.ExpirationDate     ?? raw.expires        ?? raw.registrarRegistrationExpirationDate ?? null
  const updatedDateRaw  = raw.updatedDate        ?? raw.UpdatedDate        ?? raw.lastModified   ?? null
  const country         = raw.country            ?? raw.Country            ?? raw.registrantCountry ?? null

  const creationDate   = parseDate(Array.isArray(creationDateRaw)   ? creationDateRaw[0]   : creationDateRaw)
  const expirationDate = parseDate(Array.isArray(expirationDateRaw) ? expirationDateRaw[0] : expirationDateRaw)
  const updatedDate    = parseDate(Array.isArray(updatedDateRaw)    ? updatedDateRaw[0]    : updatedDateRaw)

  const now = new Date()

  // --- Derived metrics ---
  const domainAgeInDays       = creationDate   ? daysBetween(creationDate, now)   : null
  const daysUntilExpiration   = expirationDate ? daysBetween(now, expirationDate) : null
  const isRecentlyRegistered  = domainAgeInDays !== null && domainAgeInDays < 90

  // Expiration is in the past when now > expirationDate
  const isExpired = expirationDate ? now > expirationDate : false
  const expiringWithin30Days = !isExpired && daysUntilExpiration !== null && daysUntilExpiration <= 30

  // --- Risk classification ---
  let riskLevel
  if (isRecentlyRegistered) {
    riskLevel = 'High Risk'
  } else if (expiringWithin30Days || isExpired) {
    riskLevel = 'Medium Risk'
  } else {
    riskLevel = 'Low Risk'
  }

  return res.status(200).json({
    domain: cleanDomain,
    registrar,
    country,
    creationDate:   creationDate   ? creationDate.toISOString()   : null,
    expirationDate: expirationDate ? expirationDate.toISOString() : null,
    updatedDate:    updatedDate    ? updatedDate.toISOString()    : null,
    domainAgeInDays,
    daysUntilExpiration,
    isRecentlyRegistered,
    isExpired,
    riskLevel,
    timestamp: new Date(),
  })
}

module.exports = { whoisLookup }
