/**
 * DNS Lookup
 * POST /api/dns-lookup
 * Uses Node built-in: dns.promises
 */

'use strict'

const dns = require('dns').promises
const { isPrivateIp } = require('./urlScanHelpers')

/**
 * Safely resolve a record type — returns [] instead of throwing.
 * @template T
 * @param {() => Promise<T[]>} fn
 * @returns {Promise<T[]>}
 */
async function safeResolve(fn) {
  try {
    return await fn()
  } catch {
    return []
  }
}

/**
 * POST /api/dns-lookup
 * Body: { domain: string }
 */
async function dnsLookup(req, res) {
  const { domain } = req.body

  if (!domain || typeof domain !== 'string' || domain.trim() === '') {
    return res.status(400).json({ error: 'domain is required' })
  }

  const cleanDomain = domain
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .split(':')[0]

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(cleanDomain) && isPrivateIp(cleanDomain)) {
    return res.status(403).json({
      error: 'Forbidden target',
      message: 'DNS lookups for private IP addresses are not allowed.',
    })
  }

  // Run all four record types in parallel; each failure is silenced individually.
  const [A, AAAA, MX, NS] = await Promise.all([
    safeResolve(() => dns.resolve4(cleanDomain)),
    safeResolve(() => dns.resolve6(cleanDomain)),
    safeResolve(() => dns.resolveMx(cleanDomain)),
    safeResolve(() => dns.resolveNs(cleanDomain)),
  ])

  return res.status(200).json({
    domain: cleanDomain,
    records: { A, AAAA, MX, NS },
    timestamp: new Date(),
  })
}

module.exports = { dnsLookup }
