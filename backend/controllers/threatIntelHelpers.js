'use strict'

const https = require('https')
const whois = require('whois-json')

/**
 * 2. VirusTotal API v3
 * https://www.virustotal.com/api/v3/urls
 */
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY
  if (!apiKey || apiKey === 'your_virustotal_key_here' || apiKey === 'your_key_here') {
    return { status: 'Disabled (API key not configured)' }
  }

  // VirusTotal requires the URL to be base64url encoded for lookup without scanning
  const urlBase64 = Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'www.virustotal.com',
      path: `/api/v3/urls/${urlBase64}`,
      method: 'GET',
      headers: {
        'x-apikey': apiKey
      },
      timeout: 5000
    }, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const body = JSON.parse(data)
            const stats = body.data?.attributes?.last_analysis_stats || {}
            return resolve({
              malicious: stats.malicious || 0,
              suspicious: stats.suspicious || 0,
              harmless: stats.harmless || 0,
              status: 'Scanned'
            })
          }
          resolve({ status: `Error contacting service (HTTP ${res.statusCode})` })
        } catch {
          resolve({ status: 'Error contacting service (parsing error)' })
        }
      })
    })
    req.on('error', () => resolve({ status: 'Error contacting service' }))
    req.on('timeout', () => { req.destroy(); resolve({ status: 'Error contacting service (Timeout)' }) })
    req.end()
  })
}

/**
 * 3. WHOIS Domain Age
 */
async function checkDomainAge(url) {
  try {
    const hostname = new URL(url).hostname
    const result = await whois(hostname)
    
    // Attempt to extract creation date from various common WHOIS formats
    const creationStr = result.creationDate || result.createdOn || result.creation || result.registeredOn || null
    if (!creationStr) {
      return { domainCreationDate: 'Unknown', domainAgeDays: 0, isNewDomain: false }
    }

    const creationDate = new Date(creationStr)
    if (isNaN(creationDate.getTime())) {
      return { domainCreationDate: creationStr, domainAgeDays: 0, isNewDomain: false }
    }

    const ageMs = Date.now() - creationDate.getTime()
    const domainAgeDays = Math.floor(ageMs / (1000 * 60 * 60 * 24))
    
    // If domain age < 90 days → mark as suspicious.
    const isNewDomain = domainAgeDays < 90

    return { 
      domainCreationDate: creationDate.toISOString().split('T')[0], 
      domainAgeDays, 
      isNewDomain 
    }
  } catch (err) {
    return { domainCreationDate: 'Error', domainAgeDays: 0, isNewDomain: false }
  }
}

/**
 * 4. Google Safe Browsing v4
 */
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY
  if (!apiKey || apiKey === 'your_google_safe_browsing_key_here' || apiKey === 'your_key_here') {
    return { status: 'Disabled (API key not configured)' }
  }

  const payload = JSON.stringify({
    client: {
      clientId: "testify-security",
      clientVersion: "2.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }]
    }
  })

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'safebrowsing.googleapis.com',
      path: `/v4/threatMatches:find?key=${apiKey}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 5000
    }, (res) => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const body = JSON.parse(data)
            if (body.matches && body.matches.length > 0) {
              // Return the highest severity threat type found
              return resolve({ status: body.matches[0].threatType })
            }
            return resolve({ status: 'SAFE' })
          }
          resolve({ status: `Error (HTTP ${res.statusCode})` })
        } catch {
          resolve({ status: 'Error (parsing error)' })
        }
      })
    })

    req.on('error', () => resolve({ status: 'Error contacting service' }))
    req.on('timeout', () => { req.destroy(); resolve({ status: 'Error contacting service (Timeout)' }) })
    
    req.write(payload)
    req.end()
  })
}

/**
 * Step 7 — Create Phishing Risk Score
 * Calculate risk score using the specified weighted criteria.
 */
function calculatePhishingRiskScore(intelData) {
  let riskScore = 0

  // new domain → +30
  if (intelData.domainAgeDays > 0 && intelData.isNewDomain) {
    riskScore += 30
  }

  // VirusTotal malicious detections → +40
  if (intelData.virusTotalResult && intelData.virusTotalResult.malicious > 0) {
    riskScore += 40
  }

  // Google Safe Browsing detections → +40
  if (intelData.safeBrowsingResult && 
      intelData.safeBrowsingResult.status !== 'SAFE' && 
      !intelData.safeBrowsingResult.status.includes('Disabled') &&
      !intelData.safeBrowsingResult.status.includes('Error')) {
    riskScore += 40
  }

  // suspicious keywords → +15
  if (intelData.suspiciousKeywordCount > 0 || intelData.financialKeywordCount > 0) {
    riskScore += 15
  }

  // typosquatting patterns → +15
  if (intelData.isTyposquatting) {
    riskScore += 15
  }

  // Cap at 100
  if (riskScore > 100) riskScore = 100

  let riskLevel = 'LOW'
  if (riskScore >= 50) riskLevel = 'HIGH'
  else if (riskScore >= 20) riskLevel = 'MEDIUM'

  return { riskScore, riskLevel }
}

module.exports = {
  checkVirusTotal,
  checkDomainAge,
  checkGoogleSafeBrowsing,
  calculatePhishingRiskScore
}
