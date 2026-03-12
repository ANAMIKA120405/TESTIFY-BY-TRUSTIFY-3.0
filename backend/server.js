/**
 * Testify by Trustify — Backend Server
 * Entry point: registers middleware, mounts routes, starts listener.
 */

'use strict'

require('dotenv').config({ path: require('path').resolve(__dirname, '.env') })

const express   = require('express')
const cors      = require('cors')
const helmet    = require('helmet')
const rateLimit = require('express-rate-limit')

const urlScanRoutes  = require('./routes/urlScanRoutes')
const portScanRoutes = require('./routes/portScanRoutes')
const hashRoutes     = require('./routes/hashRoutes')
const sslRoutes      = require('./routes/sslRoutes')
const dnsRoutes      = require('./routes/dnsRoutes')
const whoisRoutes    = require('./routes/whoisRoutes')
const ipGeoRoutes    = require('./routes/ipGeoRoutes')
const aiChatRoutes   = require('./routes/aiChatRoutes')
const { openPhishFeed } = require('./controllers/urlScanFeeds')

const app  = express()
const PORT = process.env.PORT || 4000

// ── S-06: Security headers ────────────────────────────────────────────────────
app.use(helmet())

// ── S-04: CORS — restrict to known frontend origin ───────────────────────────
// In development the Vite dev server is at 5173.
// Set FRONTEND_URL in .env when deploying (e.g. https://yourdomain.com).
const ALLOWED_ORIGIN = process.env.FRONTEND_URL || 'http://localhost:5173'
app.use(cors({ origin: ALLOWED_ORIGIN }))

// ── S-05: Body limit — reject oversized payloads ─────────────────────────────
app.use(express.json({ limit: '10kb' }))

// ── S-02: Rate limiting ───────────────────────────────────────────────────────
// Global: 120 req / 15 min per IP (generous for a dev tool)
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please slow down and try again later.' },
}))

// Stricter limiters for expensive network-tool endpoints
const toolRateLimit = rateLimit({
  windowMs: 60 * 1000,     // 1 minute
  max: 10,                  // 10 scans/minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many scan requests — wait 60 seconds before scanning again.' },
})

// ── Debug Integrations ────────────────────────────────────────────────────────
app.get('/api/debug/integrations', (_req, res) => {
  const hasGemini = !!(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your_gemini_api_key_here' && process.env.GEMINI_API_KEY !== 'your_key_here')
  const hasGroq = !!(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY !== 'your_groq_api_key_here' && process.env.GROQ_API_KEY !== 'your_key_here')
  const hasVT = !!(process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY !== 'your_virustotal_key_here' && process.env.VIRUSTOTAL_API_KEY !== 'your_key_here')

  res.json({
    gemini: hasGemini ? 'enabled' : 'disabled',
    virustotal: hasVT ? 'enabled' : 'disabled',
    groq: hasGroq ? 'enabled' : 'disabled'
  })
})

// ── Routes ────────────────────────────────────────────────────────────────────
// Apply strict limiter to expensive endpoints BEFORE the route handler
app.use('/api/scan-url',       toolRateLimit, urlScanRoutes)
app.use('/api/scan-image',     toolRateLimit, require('./routes/imageScanRoutes'))
app.use('/api/scan-ports',     toolRateLimit, portScanRoutes)
app.use('/api/check-ssl',      toolRateLimit, sslRoutes)
app.use('/api/dns-lookup',     toolRateLimit, dnsRoutes)
app.use('/api/whois-lookup',   toolRateLimit, whoisRoutes)
app.use('/api/ip-geolocation', toolRateLimit, ipGeoRoutes)
app.use('/api/generate-hash',  hashRoutes)
app.use('/api/ai-chat',        aiChatRoutes)

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'Testify Backend', timestamp: new Date().toISOString() })
})

// ── 404 fallback ──────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Route not found' })
})

// ── S-07: Global error handler — never leak internals to client ───────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  // Log full details server-side only
  console.error('[Error]', err)
  // Return a generic message — never expose err.message to the client
  res.status(500).json({ error: 'Internal server error' })
})

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅  Testify Backend running on http://localhost:${PORT}`)
  console.log(`✅  CORS: allowing origin ${ALLOWED_ORIGIN}`)
  
  // API Validation Logging
  const hasGemini = !!(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your_gemini_api_key_here' && process.env.GEMINI_API_KEY !== 'your_key_here')
  const hasGroq = !!(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY !== 'your_groq_api_key_here' && process.env.GROQ_API_KEY !== 'your_key_here')
  const hasVT = !!(process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY !== 'your_virustotal_key_here' && process.env.VIRUSTOTAL_API_KEY !== 'your_key_here')
  
  console.log(`[API Config] Gemini API: ${hasGemini ? 'Enabled' : 'Disabled'}`)
  console.log(`[API Config] Groq API: ${hasGroq ? 'Enabled' : 'Disabled'}`)
  console.log(`[API Config] VirusTotal API: ${hasVT ? 'Enabled' : 'Disabled'}`)

  // Initialize threat feeds in background (non-blocking)
  openPhishFeed.initialize().catch(err =>
    console.warn('⚠️  OpenPhish feed initialization failed:', err.message)
  )
})

module.exports = app
