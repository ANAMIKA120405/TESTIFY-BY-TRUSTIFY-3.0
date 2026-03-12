/**
 * urlScanFeeds.js
 * ────────────────
 * Manages threat intelligence feeds that are loaded once
 * and cached in memory for fast lookups.
 *
 * Feeds managed:
 *   - OpenPhish: downloads https://openphish.com/feed.txt every 12h
 *     No API key required. Free public feed.
 */

'use strict'

const https = require('https')

const OPENPHISH_URL  = 'https://openphish.com/feed.txt'
const REFRESH_EVERY  = 12 * 60 * 60 * 1000   // 12 hours
const FETCH_TIMEOUT  = 15000                  // 15 seconds

// ── OpenPhish Feed ────────────────────────────────────────────────────────────

class OpenPhishFeed {
  constructor() {
    this._urls     = new Set()       // exact URL set
    this._hosts    = new Set()       // hostname set for partial matches
    this._loaded   = false
    this._lastLoad = null
    this._timer    = null
  }

  async initialize() {
    await this._fetch()
    // Refresh every 12 hours
    this._timer = setInterval(() => this._fetch(), REFRESH_EVERY)
    if (this._timer.unref) this._timer.unref() // don't block process exit
  }

  async _fetch() {
    try {
      const text = await this._download(OPENPHISH_URL)
      const lines = text
        .split('\n')
        .map(l => l.trim())
        .filter(l => l.startsWith('http'))

      const newUrls  = new Set()
      const newHosts = new Set()

      for (const line of lines) {
        try {
          newUrls.add(line.toLowerCase())
          const h = new URL(line).hostname.toLowerCase()
          newHosts.add(h)
        } catch { /* skip malformed */ }
      }

      this._urls   = newUrls
      this._hosts  = newHosts
      this._loaded = true
      this._lastLoad = new Date()
      console.log(`✅ OpenPhish feed loaded: ${newUrls.size} URLs (${new Date().toISOString()})`)
    } catch (err) {
      console.warn(`⚠️  OpenPhish feed fetch failed: ${err.message} — continuing without it`)
    }
  }

  _download(url) {
    return new Promise((resolve, reject) => {
      const req = https.get(url, { timeout: FETCH_TIMEOUT }, (res) => {
        // Follow redirects (max 3)
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          this._download(res.headers.location).then(resolve).catch(reject)
          res.resume()
          return
        }
        let data = ''
        res.on('data', chunk => { data += chunk })
        res.on('end', () => resolve(data))
      })
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')) })
      req.on('error', reject)
    })
  }

  /**
   * Check if a URL or its hostname is in the OpenPhish feed.
   * Returns { hit: bool, matchedUrl?: string, matchedHost?: string }
   */
  check(urlString, hostname) {
    if (!this._loaded) return { hit: false, reason: 'feed not loaded' }

    const lowerUrl  = urlString.toLowerCase()
    const lowerHost = hostname.toLowerCase()

    // 1. Exact URL match
    if (this._urls.has(lowerUrl)) {
      return { hit: true, type: 'exact_url' }
    }

    // 2. URL starts-with match (catches paths on same phishing URL)
    for (const phishUrl of this._urls) {
      if (lowerUrl.startsWith(phishUrl) || phishUrl.startsWith(lowerUrl.split('?')[0])) {
        return { hit: true, type: 'url_prefix', matched: phishUrl }
      }
    }

    // 3. Hostname match
    if (this._hosts.has(lowerHost)) {
      return { hit: true, type: 'hostname' }
    }

    return { hit: false }
  }

  get isLoaded() { return this._loaded }
  get urlCount()  { return this._urls.size }
  get loadedAt()  { return this._lastLoad }
}

// Singleton
const openPhishFeed = new OpenPhishFeed()

module.exports = { openPhishFeed }
