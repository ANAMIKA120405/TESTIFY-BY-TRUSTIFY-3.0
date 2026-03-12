/**
 * IP Geolocation
 * POST /api/ip-geolocation
 * Uses: axios → http://ip-api.com/json/{ip}
 */

'use strict'

const axios = require('axios')

/**
 * POST /api/ip-geolocation
 * Body: { ip: string }
 */
async function ipGeolocation(req, res) {
  const { ip } = req.body

  if (!ip || typeof ip !== 'string' || ip.trim() === '') {
    return res.status(400).json({ error: 'ip is required' })
  }

  const cleanIp = ip.trim()

  let apiData
  try {
    const response = await axios.get(`https://ipapi.co/${encodeURIComponent(cleanIp)}/json/`, {
      timeout: 8000,
    })
    apiData = response.data
  } catch (err) {
    return res.status(502).json({
      error: `Geolocation request failed: ${err.message}`,
    })
  }

  // ip-api returns { status: 'fail', message: '...' } for bad IPs
  if (apiData.status === 'fail') {
    return res.status(200).json({
      ip: cleanIp,
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      isp: null,
      organization: null,
      riskLevel: 'Invalid IP',
      error: apiData.message ?? 'IP address not found',
      timestamp: new Date(),
    })
  }

  return res.status(200).json({
    ip: cleanIp,
    country: apiData.country      ?? null,
    region:  apiData.regionName   ?? null,
    city:    apiData.city         ?? null,
    latitude:  apiData.lat        ?? null,
    longitude: apiData.lon        ?? null,
    isp:          apiData.isp     ?? null,
    organization: apiData.org     ?? null,
    riskLevel: 'Valid',
    timestamp: new Date(),
  })
}

module.exports = { ipGeolocation }
