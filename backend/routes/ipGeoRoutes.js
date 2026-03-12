'use strict'

const { Router } = require('express')
const { ipGeolocation } = require('../controllers/ipGeoController')

const router = Router()

router.post('/', ipGeolocation)

module.exports = router
