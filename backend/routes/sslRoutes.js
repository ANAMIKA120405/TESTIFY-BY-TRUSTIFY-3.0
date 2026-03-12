'use strict'

const { Router } = require('express')
const { checkSSL } = require('../controllers/sslController')

const router = Router()

router.post('/', checkSSL)

module.exports = router
