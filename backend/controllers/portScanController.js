/**
 * portScanController.js
 * ──────────────────────
 * Real TCP Port Scanner using Node's built-in `net` and `dns` modules.
 *
 * Exposure scoring:
 *   +20  port 21  (FTP)    — unencrypted file transfer
 *   +20  port 22  (SSH)    — brute-force target
 *   +15  port 25  (SMTP)   — potential spam relay
 *   +25  port 3306 (MySQL) — database directly exposed
 *   +10  port 8080 (Alt-HTTP) — non-standard web surface
 *   ──── 80 / 443 excluded (expected web ports, no added risk)
 *
 * Exposure levels:
 *    0–20  → Low Exposure
 *   21–50  → Medium Exposure
 *    51+   → High Exposure
 */

'use strict'

const net = require('net')
const dns = require('dns')
const { isPrivateIp } = require('./urlScanHelpers')

// ── Config ────────────────────────────────────────────────────────────────────

const TARGET_PORTS = [
  { port: 21,   service: 'FTP'      },
  { port: 22,   service: 'SSH'      },
  { port: 25,   service: 'SMTP'     },
  { port: 53,   service: 'DNS'      },
  { port: 80,   service: 'HTTP'     },
  { port: 443,  service: 'HTTPS'    },
  { port: 3306, service: 'MySQL'    },
  { port: 8080, service: 'Alt-HTTP' },
]

const EXPOSURE_WEIGHTS = {
  21:   20,
  22:   20,
  25:   15,
  3306: 25,
  8080: 10,
}

const SOCKET_TIMEOUT_MS = 1500

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Resolve a hostname to an IPv4 address.
 * Returns the input unchanged if it already looks like an IP.
 * @param {string} target
 * @returns {Promise<string>}
 */
function resolveTarget(target) {
  // If it's already an IPv4, skip DNS lookup
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) {
    return Promise.resolve(target)
  }
  return new Promise((resolve, reject) => {
    dns.lookup(target, 4, (err, address) => {
      if (err) reject(err)
      else resolve(address)
    })
  })
}

/**
 * Attempt a TCP connection to a single port.
 * Resolves with { port, service, status: 'open' | 'closed' }.
 * Never rejects — failures are recorded as 'closed'.
 *
 * @param {string} ip
 * @param {{ port: number, service: string }} entry
 * @returns {Promise<{ port: number, service: string, status: string }>}
 */
function checkPort(ip, { port, service }) {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false

    function finish(status) {
      if (settled) return
      settled = true
      socket.destroy()
      resolve({ port, service, status })
    }

    socket.setTimeout(SOCKET_TIMEOUT_MS)

    socket.connect(port, ip)

    socket.on('connect',  () => finish('open'))
    socket.on('timeout',  () => finish('closed'))
    socket.on('error',    () => finish('closed'))
    socket.on('close',    () => finish('closed'))
  })
}

/**
 * Derive total exposure score from open ports.
 * @param {Array<{ port: number, status: string }>} results
 * @returns {number}
 */
function calcExposureScore(results) {
  return results.reduce((total, { port, status }) => {
    if (status === 'open' && EXPOSURE_WEIGHTS[port] !== undefined) {
      return total + EXPOSURE_WEIGHTS[port]
    }
    return total
  }, 0)
}

/**
 * @param {number} score
 * @returns {string}
 */
function getExposureLevel(score) {
  if (score <= 20) return 'Low Exposure'
  if (score <= 50) return 'Medium Exposure'
  return 'High Exposure'
}

// ── Controller ────────────────────────────────────────────────────────────────

/**
 * POST /api/scan-ports
 * Body: { target: string }   — hostname or IPv4
 */
async function scanPorts(req, res, next) {
  try {
    const { target } = req.body

    if (!target || typeof target !== 'string' || !target.trim()) {
      return res.status(400).json({ error: '"target" field is required and must be a non-empty string.' })
    }

    const trimmedTarget = target.trim()

    // ── DNS resolution ─────────────────────────────────────────────────────
    let resolvedIP
    try {
      resolvedIP = await resolveTarget(trimmedTarget)
    } catch (dnsErr) {
      return res.status(500).json({
        error: 'DNS resolution failed.',
        message: 'Could not resolve target hostname.',
      })
    }

    if (isPrivateIp(resolvedIP)) {
      return res.status(403).json({
        error: 'Forbidden target',
        message: 'Scanning private or internal IP addresses is not allowed.',
      })
    }

    // ── Parallel port scan ─────────────────────────────────────────────────
    const scannedPorts = await Promise.all(
      TARGET_PORTS.map((entry) => checkPort(resolvedIP, entry))
    )

    // ── Scoring ────────────────────────────────────────────────────────────
    const exposureScore = calcExposureScore(scannedPorts)
    const exposureLevel = getExposureLevel(exposureScore)

    return res.status(200).json({
      target: trimmedTarget,
      resolvedIP,
      scannedPorts,
      exposureScore,
      exposureLevel,
      timestamp: new Date(),
    })
  } catch (err) {
    next(err)
  }
}

module.exports = { scanPorts }
