'use strict'

const { Router } = require('express')
const { whoisLookup } = require('../controllers/whoisController')

const router = Router()

router.post('/', whoisLookup)

module.exports = router
