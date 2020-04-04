const { fetchCode, checkByUKey } = require('../services/auth')
const CODE = require('../http-error-code/auth.js')
const __opt = {
  ret: '',
  message: '',
  data: '',
  code: ''
}

module.exports = {
  /**
   * 获取验证码 存进 session, 并返回客户端
   * @param {*} ctx
   */
  async getVerifiedCode(ctx) {
    ctx.set('Content-Type', 'application/json;charset=UTF-8')
    ctx.set('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
    ctx.set('Expires', '0')
    ctx.set('Pragma', 'no-cache')

    const result = Object.assign({}, __opt)
    const code = fetchCode()
    // 存放在 session, array 存放多个，多方调用
    if (Array.isArray(ctx.session.unverifiedCodes)) {
      ctx.session.unverifiedCodes.push(code)
    } else {
      ctx.session.unverifiedCodes = [code]
    }

    ctx.session.views = 123
    result.ret = Number(1)
    result.message = '获取验证码成功'
    result.data = code

    ctx.body = JSON.stringify(result)
    return true
  },

  // async getVerifiedCode(ctx) {
  //   ctx.session.unverifiedCodes = [code]
  //   ctx.body = JSON.stringify({})
  // },

  // async checkCode(ctx) {
  //   ctx.set('Content-Type', 'application/json;charset=UTF-8')
  //   const plaintList = ctx.session.unverifiedCodes
  //   ctx.body = JSON.stringify({})
  // }

  async checkCode(ctx) {
    // ctx.set('Access-Control-Allow-Origin', '*')
    // ctx.set('Access-Control-Allow-Methods', 'OPTIONS, GET, PUT, POST, DELETE')
    // ctx.set('Access-Control-Allow-Headers', 'x-requested-with, accept, origin, content-type')
    // ctx.set('Access-Control-Allow-Credentials', true)

    ctx.set('Content-Type', 'application/json;charset=UTF-8')

    const result = Object.assign({}, __opt)
    const { code } = ctx.request.body
    if (!code) {
      result.ret = Number(-1)
      result.code = 'INVALID_DATA'
      result.message = CODE[result.code]
      result.data = null
    } else {
      const plaintList = ctx.session.unverifiedCodes
      try {
        let r
        const bool = plaintList.some((plaint, index, arr) => {
          r = checkByUKey(code, plaint) // 业务层进行对比
          return r && arr.splice(index, 1) // * 删除验证成功的验证码
        })
        if (!bool) throw new Error(CODE['ERROR_VERIFICATION'])
        result.ret = Number(1)
        result.message = '校验成功'
      } catch (err) {
        console.log(err) // ! 输出日志文件

        result.ret = Number(-1)
        result.code = 'ERROR_VERIFICATION'
        result.message = CODE[result.code]
        result.data = null
      }
    }

    ctx.body = JSON.stringify(result)
  }
}
