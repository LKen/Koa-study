const router = require('koa-router')()
const login = require('../controllers/login')

router.get('/', login)

module.exports = router

