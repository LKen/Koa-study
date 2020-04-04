const path = require('path')
const Koa = require('koa')
const app = new Koa()
const views = require('koa-views')
const json = require('koa-json')
const onerror = require('koa-onerror')
const bodyparser = require('koa-bodyparser')
const logger = require('koa-logger') // 控制日志在控制台输出
const session = require('koa-session')
// const redisStore = require('koa-redis')
const { systemLogger, accessLogger } = require('./logger')
const routers = require('./routers/index')

// 存放sessionId的cookie配置
app.keys = ['gosunyun']

const CONFIG = {
  key: 'koa:sess', // 这玩意不能改，不知道为什么

  /** (number || 'session') maxAge in ms (default is 1 days) */
  /** 'session' will result in a cookie that expires when session/browser is closed */
  /** Warning: If a session cookie is stolen, this cookie will never expire */
  maxAge: 86400000,
  autoCommit: true, /** (boolean) automatically commit headers (default true) */
  overwrite: true, /** (boolean) can overwrite or not (default true) */
  httpOnly: true, /** 是否设置HttpOnly，如果在Cookie中设置了"HttpOnly"属性，那么通过程序(JS脚本、Applet等)将无法读取到Cookie信息，这样能有效的防止XSS攻击 */
  rolling: true, /** 是否每次响应时刷新Session的有效期 */
  renew: false, /** 是否在Session快过期时刷新Session的有效期 */
  signed: true
}

// error handler
onerror(app)

// middlewares
app.use(bodyparser({
  enableTypes: ['json', 'form', 'text']
}))
app.use(json())
app.use(logger())
app.use(accessLogger()) // 控制访问级日志输出
app.use(require('koa-static')(path.join(__dirname, '../public')))

app.use(views(path.join(__dirname, 'views'), {
  extension: 'ejs'
}))

// 使用session中间件
app.use(session(CONFIG, app))

// ! 每个路由开始的中间件
app.use(async(ctx, next) => {
  const start = new Date()
  await next()
  const ms = new Date() - start
  console.log(`${ctx.method} ${ctx.url} - ${ms}ms`) // logger
})

// 初始化路由中间件
app.use(routers.routes(), routers.allowedMethods())

// error-handling
app.on('error', (err, ctx) => {
  systemLogger.error(err)
  console.error('server error', err, ctx)
})

module.exports = app
