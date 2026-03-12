/**
 * portScanRoutes.js
 * ──────────────────
 * Mounts port-scanning endpoints on an Express Router.
 *
 * Routes:
 *   POST /api/scan-ports  — real TCP scan of common ports for a given target
 */

'use strict'

const { Router } = require('express')
const { scanPorts } = require('../controllers/portScanController')

const router = Router()

/**
 * POST /api/scan-ports
 * ---------------------
 * Body (JSON):
 *   { "target": "example.com" }        — hostname
 *   { "target": "203.0.113.42" }       — IPv4 address
 *
 * Success 200:
 *   {
 *     target:       string,
 *     resolvedIP:   string,
 *     scannedPorts: [{ port, service, status }],
 *     exposureScore: number,
 *     exposureLevel: "Low Exposure" | "Medium Exposure" | "High Exposure",
 *     timestamp:    Date
 *   }
 *
 * Error 400:  missing / invalid target
 * Error 500:  DNS failure
 */
router.post('/', scanPorts)

module.exports = router
