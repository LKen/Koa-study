const router = require('koa-router')()
const c_auth = require('../controllers/auth')
const prefix = '/auth'
const formatterUrl = (url) => prefix + url

const routers = router
  .get(formatterUrl('/getVerifiedCode.action'), c_auth.getVerifiedCode)
  .post(formatterUrl('/sendCipherCode.action'), c_auth.checkCode)
module.exports = routers
