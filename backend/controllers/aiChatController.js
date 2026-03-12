/**
 * aiChatController.js
 * ────────────────────
 * S-01 Fix: Routes AI requests through the backend so the
 * Groq API key stays server-side and is never exposed to browsers.
 *
 * Reads: GROQ_API_KEY from process.env (no VITE_ prefix — server only).
 * POST /api/ai-chat   Body: { messages: Array<{role, content}> }
 */

'use strict'

const https = require('https')

const { GoogleGenAI } = require('@google/genai')

const GROQ_API_KEY = process.env.GROQ_API_KEY
const GEMINI_API_KEY = process.env.GEMINI_API_KEY

const SYSTEM_PROMPT = `You are an AI Security Assistant embedded inside "Testify by Trustify", a cybersecurity dashboard application. Your role is to help users:
- Understand cybersecurity concepts, threats, and best practices
- Interpret scan results and findings from the dashboard (URL Scanner, Attack Surface Map, Dark Web Monitor, Security Box)
- Provide remediation recommendations for discovered vulnerabilities
- Answer questions about security posture, tools, and defensive strategies
- Explain technical security topics in clear, actionable language

Always be concise, professional, and security-focused. When discussing vulnerabilities, include severity context and remediation steps.`

/**
 * POST /api/ai-chat
 * Body: { messages: [{ role: 'user'|'assistant', content: string }] }
 */
async function aiChat(req, res, next) {
  try {
    if (!GROQ_API_KEY && !GEMINI_API_KEY) {
      return res.status(503).json({
        error: 'AI Assistant is not configured. Set GROQ_API_KEY or GEMINI_API_KEY in backend/.env to enable it.',
      })
    }

    const { messages } = req.body

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: '"messages" must be a non-empty array.' })
    }

    // Validate messages shape
    const validRoles = new Set(['user', 'assistant', 'system'])
    for (const msg of messages) {
      if (!msg.role || !validRoles.has(msg.role) || typeof msg.content !== 'string') {
        return res.status(400).json({ error: 'Each message must have a valid "role" and string "content".' })
      }
    }

    // Cap conversation history to last 20 messages to prevent abuse
    const trimmedMessages = messages.slice(-20)

    // Use Gemini if available and Groq is not
    const aiProvider = GROQ_API_KEY ? 'groq' : 'gemini';

    if (aiProvider === 'gemini') {
      const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY })
      
      const config = {
        systemInstruction: SYSTEM_PROMPT,
        temperature: 0.7,
        maxOutputTokens: 1024,
      }
      
      const geminiMessages = trimmedMessages.map(m => ({
        role: m.role === 'assistant' ? 'model' : m.role,
        parts: [{ text: m.content }]
      }))

      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: geminiMessages,
        config,
      })
      
      return res.status(200).json({ content: response.text })
    }

    // Fallback to Groq if that's the configured provider
    const payload = JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        ...trimmedMessages,
      ],
      max_tokens: 1024,
      temperature: 0.7,
    })

    const groqResponse = await new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: 'api.groq.com',
          path: '/openai/v1/chat/completions',
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${GROQ_API_KEY}`,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          },
          timeout: 30000,
        },
        (groqRes) => {
          let data = ''
          groqRes.on('data', chunk => { data += chunk })
          groqRes.on('end', () => {
            try {
              resolve({ status: groqRes.statusCode, body: JSON.parse(data) })
            } catch {
              reject(new Error('Invalid JSON from Groq API'))
            }
          })
        }
      )
      req.on('timeout', () => { req.destroy(); reject(new Error('Groq API timeout')) })
      req.on('error', reject)
      req.write(payload)
      req.end()
    })

    if (groqResponse.status !== 200) {
      // Don't forward Groq's raw error (may contain key info in some edge cases)
      console.error('[Groq API Error]', groqResponse.status, groqResponse.body)
      return res.status(502).json({ error: 'AI service returned an error. Please try again.' })
    }

    const content = groqResponse.body?.choices?.[0]?.message?.content ?? ''
    return res.status(200).json({ content })

  } catch (err) {
    next(err)
  }
}

module.exports = { aiChat }
