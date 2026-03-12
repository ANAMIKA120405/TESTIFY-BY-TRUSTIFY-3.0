/**
 * hashController.js
 * ──────────────────
 * Generates cryptographic hashes using Node's built-in `crypto` module.
 *
 * Supported algorithms: md5, sha1, sha256
 */

'use strict'

const crypto = require('crypto')

const SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256']

/**
 * POST /api/generate-hash
 * Body: { text: string, algorithm: string }
 */
async function generateHash(req, res, next) {
  try {
    const { text, algorithm } = req.body

    // ── Validation ────────────────────────────────────────────────────────
    if (!text || typeof text !== 'string' || text.trim() === '') {
      return res.status(400).json({ error: '"text" field is required and must be a non-empty string.' })
    }

    if (text.length > 100000) {
      return res.status(413).json({ error: 'Payload too large. Maximum text length is 100,000 characters.' })
    }

    if (!algorithm || typeof algorithm !== 'string') {
      return res.status(400).json({
        error: '"algorithm" field is required.',
        supported: SUPPORTED_ALGORITHMS,
      })
    }

    const normalizedAlgo = algorithm.toLowerCase().trim()

    if (!SUPPORTED_ALGORITHMS.includes(normalizedAlgo)) {
      return res.status(400).json({
        error: `Unsupported algorithm "${algorithm}".`,
        supported: SUPPORTED_ALGORITHMS,
      })
    }

    // ── Hash generation ───────────────────────────────────────────────────
    const hash = crypto
      .createHash(normalizedAlgo)
      .update(text)
      .digest('hex')

    return res.status(200).json({
      originalTextLength: text.length,
      algorithm: normalizedAlgo,
      hash,
      timestamp: new Date(),
    })
  } catch (err) {
    next(err)
  }
}

module.exports = { generateHash }
