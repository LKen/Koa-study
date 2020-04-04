const path = require('path')
const log4js = require('koa-log4')
const conf = require('./config')
const logPath = conf.log_address || path.join(process.cwd(), 'log/')

log4js.configure({
  appenders: {
    access: {
      type: 'dateFile',
      pattern: '-yyyy-MM-dd.log', // 生成文件的规则
      alwaysIncludePattern: true, // 文件名始终以日期区分
      filename: path.join(logPath, 'access.log') // 生成文件名
    },
    application: {
      type: 'dateFile',
      pattern: '-yyyy-MM-dd.log',
      alwaysIncludePattern: true, // 文件名始终以日期区分
      filename: path.join(logPath, 'application.log')
    },
    out: {
      type: 'console',
      replaceConsole: true
    }
  },
  categories: {
    default: { appenders: ['out'], level: 'info' },
    access: {
      appenders: ['access'],
      level: 'info'
    },
    application: { appenders: ['application'], level: 'WARN' }
  }
})

module.exports = {
  accessLogger: () => log4js.koaLogger(log4js.getLogger('access'), {
    format: ':remote-addr - -' +
    ' [:req[Content-Type]]' +
    ' ":method :url HTTP/:http-version"' +
    ' :response-timems' +
    ' :status :content-lengthB ":referrer"' +
    ' ":user-agent"'
  }), // 记录所有访问级别的日志
  systemLogger: log4js.getLogger('application') // 记录所有应用级别的日志
}
