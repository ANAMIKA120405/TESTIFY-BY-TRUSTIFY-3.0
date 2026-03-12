'use strict'

const { Router } = require('express')
const { dnsLookup } = require('../controllers/dnsController')

const router = Router()

router.post('/', dnsLookup)

module.exports = router
