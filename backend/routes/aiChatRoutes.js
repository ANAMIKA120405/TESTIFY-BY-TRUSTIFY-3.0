/**
 * aiChatRoutes.js
 * ─────────────────
 * S-01 Fix: New route to keep the Groq API key hidden on the server.
 */

'use strict'

const express = require('express')
const { aiChat } = require('../controllers/aiChatController')

const router = express.Router()

router.post('/', aiChat)

module.exports = router
