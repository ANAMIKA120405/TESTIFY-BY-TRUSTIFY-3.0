'use strict'

const Tesseract = require('tesseract.js')
const { performUrlScan } = require('./urlScanController')
const { FINANCIAL_LURE_KEYWORDS, SUSPICIOUS_KEYWORDS } = require('./urlScanHelpers')
const https = require('https')
const { GoogleGenAI } = require('@google/genai')

async function analyzeContentWithAI(text) {
  const apiKey = process.env.GROQ_API_KEY;
  const geminiKey = process.env.GEMINI_API_KEY;
  
  if (!text || !text.trim()) return null;
  
  const hasGroq = apiKey && apiKey !== 'your_groq_api_key_here' && apiKey !== 'your_key_here';
  const hasGemini = geminiKey && geminiKey !== 'your_gemini_api_key_here' && geminiKey !== 'your_key_here';
  
  if (!hasGroq && !hasGemini) {
    return {
      isScam: null,
      confidence: 'None',
      reasoning: 'AI Analysis Disabled (API key not configured)'
    };
  }

  const SYSTEM_PROMPT = `You are an AI Security Analyst integrated into a cybersecurity tool.
Your job is to read text (extracted via OCR from an image, or pasted by a user) and determine if the context suggests a scam, phishing attempt, social engineering, or is otherwise suspicious.
Specifically, look for language patterns associated with phishing, and analyze the context around any URLs found in the text.
Common scams include:
- Fake job offers requiring upfront payment or personal info.
- Urgent SMS/emails about locked accounts or missed deliveries containing suspicious links.
- Unrealistic financial opportunities, "free" money, or crypto giveaways.
- Impersonation of brands or authorities trying to direct users to unofficial URLs.

Analyze the text and return ONLY a strict JSON object with these keys:
{
  "isScam": boolean, // true if suspicious/scam, false if legitimate or benign
  "confidence": "High" | "Medium" | "Low",
  "reasoning": "A concise, 1-3 sentence explanation of why you made this determination."
}
Return ONLY valid JSON. Do not use markdown blocks (\`\`\`json) or add any conversational text.`;

  // Use Gemini if available
  if (hasGemini && !hasGroq) {
    try {
      const ai = new GoogleGenAI({ apiKey: geminiKey });
      
      const config = {
        systemInstruction: SYSTEM_PROMPT,
        temperature: 0.1,
        maxOutputTokens: 500,
        responseMimeType: 'application/json',
      };
      
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: [{ role: 'user', parts: [{ text: `Analyze the following text:\n\n${text}` }] }],
        config,
      });
      
      if (response.text) {
         return JSON.parse(response.text);
      }
      return null;
    } catch (err) {
      console.error('[Gemini Analysis Error]', err);
      return null;
    }
  }

  // Fallback to Groq
  const payload = JSON.stringify({
    model: 'llama-3.3-70b-versatile',
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: `Analyze the following text:\n\n${text}` }
    ],
    max_tokens: 500,
    temperature: 0.1,
    response_format: { type: "json_object" }
  });

  return new Promise((resolve) => {
    const req = https.request({
      hostname: 'api.groq.com',
      path: '/openai/v1/chat/completions',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk });
      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const body = JSON.parse(data);
            const content = body.choices?.[0]?.message?.content;
            if (content) {
              resolve(JSON.parse(content));
              return;
            }
          }
          resolve(null);
        } catch {
          resolve(null);
        }
      });
    });
    
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(payload);
    req.end();
  });
}

function isValidUrl(rawUrl) {
  try {
    const p = new URL(rawUrl)
    return p.protocol === 'http:' || p.protocol === 'https:'
  } catch { return false }
}

/**
 * cleanOcrText — fixes common Tesseract artefacts before URL extraction.
 *
 * Problems addressed:
 *  1. URLs split across lines  →  https://example\n.com  →  https://example.com
 *  2. Spaces injected mid-URL by OCR  →  https:// x .com  →  https://x.com
 *  3. Trailing OCR noise on URLs (punctuation like . , ) etc.)
 *  4. Redundant whitespace
 */
function cleanOcrText(rawText) {
  if (!rawText) return ''

  const lines = rawText.split('\n')
  const merged = []

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()

    // If the *previous* merged line ends with a URL fragment and this line
    // starts with a URL continuation character (.  /  alphanumeric), merge them.
    if (
      merged.length > 0 &&
      /^[./][a-zA-Z0-9\-_~:%@!$&'()*+,;=?#/]/.test(line) &&
      /(https?:\/\/|www\.)[a-zA-Z0-9]/.test(merged[merged.length - 1])
    ) {
      merged[merged.length - 1] += line
    } else {
      // If this line ends with a partial URL and the *next* line looks like
      // a continuation, merge proactively before pushing.
      if (
        i + 1 < lines.length &&
        /https?:\/\/[a-zA-Z0-9\-._~:%?#[\]@!$&'()*+,;=/]*$/.test(line) &&
        /^[./a-zA-Z0-9\-_~:%@!$&'()*+,;=?#]/.test(lines[i + 1].trim())
      ) {
        merged.push(line + lines[i + 1].trim())
        i++ // skip the next line — already consumed
      } else {
        merged.push(line)
      }
    }
  }

  let text = merged.join('\n')

  // Fix spaces OCR inserts inside the protocol  →  "https:// example" → "https://example"
  text = text.replace(/https?:\/\/\s+/gi, m => m.replace(/\s+/g, ''))

  // Fix OCR spaces around dots inside URL-like tokens  →  "example .com" → "example.com"
  text = text.replace(/([a-zA-Z0-9\-]+)\s+\.\s*([a-zA-Z]{2,})/g, '$1.$2')

  // Collapse multiple spaces/tabs (but keep newlines for keyword scanning)
  text = text.replace(/[ \t]{2,}/g, ' ')

  return text.trim()
}

/**
 * extractUrls — two-pass URL harvester.
 *
 * Pass 1 — full URLs starting with http:// or https://
 * Pass 2 — www. prefixed domains (protocol-less)
 *
 * Every match is stripped of trailing punctuation and validated via isValidUrl().
 */
function extractUrls(text) {
  const found = new Set()

  const stripTrailing = u => {
    let s = u
    while (/['".,;:)\]>]$/.test(s)) s = s.slice(0, -1)
    return s
  }

  // Pass 1: full https?:// URLs
  const withProto = text.match(/https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/gi) || []
  withProto.forEach(u => found.add(stripTrailing(u)))

  // Pass 2: www. domain without protocol
  const withWww = text.match(/\bwww\.[a-zA-Z0-9\-]+(?:\.[a-zA-Z]{2,})+(?:\/[^\s]*)?\b/gi) || []
  withWww.forEach(u => found.add('https://' + stripTrailing(u)))

  // Pass 3: bare subdomains/domains without protocol or www, e.g. lms.talentely.com/profile
  // Requires at least two dot-separated labels where the last is a known-ish TLD (2-6 chars)
  // Must NOT already start with https?:// or www. (those are handled above)
  const bareDomain = text.match(
    /\b(?!www\.)(?!https?:\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}[a-zA-Z]{2,6}(?:\/[^\s]*)?/g
  ) || []
  bareDomain.forEach(u => {
    const stripped = stripTrailing(u)
    // Reject pure numbers (e.g. "1.2.3.4" resolved separately) and very short fragments
    if (/^\d+(\.\d+)+/.test(stripped)) return
    if (stripped.length < 5) return
    // Must contain at least one dot
    if (!stripped.includes('.')) return
    const candidate = 'https://' + stripped
    // Only add if not already covered by pass 1/2
    if (!isValidUrl(candidate)) return
    const alreadyCovered = [...found].some(f => f.includes(stripped))
    if (!alreadyCovered) found.add(candidate)
  })

  return [...found].filter(isValidUrl)
}

async function scanImage(req, res, next) {
  try {
    const { text = '', imageUrl = '' } = req.body
    let imageSource = null

    if (req.file) {
      imageSource = req.file.buffer
    } else if (imageUrl && isValidUrl(imageUrl)) {
      imageSource = imageUrl
    }

    // ── OCR ──────────────────────────────────────────────────────────────────
    let rawOcrText = ''
    if (imageSource) {
      const { data: { text: tesseractText } } = await Tesseract.recognize(imageSource, 'eng')
      rawOcrText = tesseractText
    }

    // Clean OCR output before anything else
    const extractedText = cleanOcrText(rawOcrText)
    console.log('[OCR] Raw:\n', rawOcrText)
    console.log('[OCR] Cleaned:\n', extractedText)

    // Combine user-provided text + cleaned OCR text
    const fullText = [text, extractedText].filter(Boolean).join('\n')

    // ── Keyword detection ─────────────────────────────────────────────────────
    const lowerText = fullText.toLowerCase()
    const matchedSuspicious = SUSPICIOUS_KEYWORDS.filter(kw => lowerText.includes(kw))
    const matchedFinance    = FINANCIAL_LURE_KEYWORDS.filter(kw => lowerText.includes(kw))

    // ── URL extraction ────────────────────────────────────────────────────────
    const uniqueUrls = extractUrls(fullText)
    console.log('[URLs] Detected:', uniqueUrls)

    // Limit to max 10 URLs to prevent abuse/timeouts
    const urlsToScan = uniqueUrls.slice(0, 10)
    
    // Perform AI Analysis on the combined text independently of URLs FIRST
    let aiAnalysis = null
    if (fullText.trim().length > 10) {
       aiAnalysis = await analyzeContentWithAI(fullText)
    }
    
    const scans = await Promise.all(urlsToScan.map(async (u) => {
      try {
        const result = await performUrlScan(u, aiAnalysis)
        return {
          url: result.url || u,
          score: result.threatScore,
          status: result.riskLevel,
          confidence: result.confidence,
          trusted: result.trusted,
          categories: result.categories || [],
          criticalFindings: result.criticalFindings || [],
          warningFindings: result.warningFindings || [],
          summary: result.summary,
          timestamp: result.timestamp
        }
      } catch (err) {
        return {
          url: u,
          error: true,
          message: err.message || 'Scan failed',
          score: 0,
          status: 'Unknown'
        }
      }
    }))
    
    // Step 8: Return structured result
    res.status(200).json({
      extractedText: extractedText.trim(),
      urlsFound: uniqueUrls.length,
      suspiciousKeywords: matchedSuspicious,
      financialKeywords: matchedFinance,
      scanResults: scans,
      aiAnalysis
    })
    
  } catch (err) {
    next(err)
  }
}

module.exports = { scanImage }
