/**
 * hashRoutes.js
 * ──────────────
 * Mounts hash generation endpoints on an Express Router.
 *
 * Routes:
 *   POST /api/generate-hash  — generate MD5 / SHA-1 / SHA-256 hash
 */

'use strict'

const { Router } = require('express')
const { generateHash } = require('../controllers/hashController')

const router = Router()

/**
 * POST /api/generate-hash
 * ------------------------
 * Body (JSON):
 *   { "text": "hello world", "algorithm": "sha256" }
 *
 * Success 200:
 *   {
 *     originalTextLength: number,
 *     algorithm:          "md5" | "sha1" | "sha256",
 *     hash:               string,
 *     timestamp:          Date
 *   }
 *
 * Error 400:  missing / invalid text or unsupported algorithm
 */
router.post('/', generateHash)

module.exports = router
