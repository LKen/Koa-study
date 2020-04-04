const { getTokenByProxy } = require('../services/auth')
const { systemLogger } = require('../logger')
const conf = require('../config')

/**
 * 截取IP
 */
// function fetchIp(url) {
//   if (typeof url === 'undefined') return ''
//   const res = url.match(/^(https?|ftp):\/\/([a-zA-Z0-9.-]+(:[a-zA-Z0-9.&%$-]+)*@)*((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))(:[0-9]+)*(\/($|[a-zA-Z0-9.,?'\\+&%$#=~_-]+))*$/)
//   return res[4]
// }

module.exports = async(ctx, next) => {
  try {
    const token = await getTokenByProxy()
    ctx.cookies.set(
      'token',
      token,
      {
        path: '/',
        httpOnly: false,
        overwrite: false,
        maxAge: 10 * 60 * 1000
      }
    )
    ctx.redirect(`${conf.proxy}/nodeServer.html`)
  } catch (err) {
    systemLogger.error(err.config.url + '--' + err.message)
  }
}
