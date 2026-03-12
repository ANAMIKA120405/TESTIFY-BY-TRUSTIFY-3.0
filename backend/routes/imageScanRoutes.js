'use strict'

const express = require('express')
const multer = require('multer')
const { scanImage } = require('../controllers/imageScanController')

const router = express.Router()

// Keep images in memory for direct buffer processing
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
})

router.post('/', upload.single('image'), scanImage)

module.exports = router
