/**
 * urlScanRoutes.js
 * ─────────────────
 * Mounts the URL scanning endpoints on an Express Router.
 *
 * Routes:
 *   POST /api/scan-url   — analyse a URL for threat indicators
 */

'use strict'

const { Router } = require('express')
const { scanUrl } = require('../controllers/urlScanController')

const router = Router()

/**
 * POST /api/scan-url
 * -------------------
 * Body (JSON):
 *   { "url": "https://example.com" }
 *
 * Success 200:
 *   {
 *     url:         string,
 *     threatScore: number,   // 0–100
 *     riskLevel:   "Safe" | "Suspicious" | "Malicious",
 *     findings:    string[],
 *     timestamp:   string    // ISO 8601
 *   }
 *
 * Error 400:
 *   { "error": "<validation message>" }
 */
router.post('/', scanUrl)

module.exports = router
