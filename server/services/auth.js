/*
 * File: auth.js
 * Project: test2
 * File Created: Tuesday, 31st March 2020 6:39:16 pm
 * Author: KLEN (liangchuqiang@gosuncn.com)
 * Description: 处理 UJey 加密狗的业务
 * -----
 * Last Modified: Friday, 3rd April 2020 5:56:42 pm
 * Modified By: KLEN (liangchuqiang@gosuncn.com>)
 * -----
 * Copyright 2018 - 2020 广州高新兴机器人有限公司, 广州高新兴机器人有限公司
 * -----
 */
const axios = require('axios')
const conf = require('../config')
const { createUuid } = require('../utils')
const SoftKey = require('../libs/SoftKey')
const mSoftKey = new SoftKey()
const _ukey_id = ''
const _ukey = ''

const randomization = createUuid

module.exports = {
  /**
   * 随机产生验证码 业务
   */
  fetchCode() {
    return randomization()
  },

  /**
   * 利用加密狗对密文解密，进行比对 业务
   * @param {String} encrypt 密文
   * @param {String} plaint 明文 fetchCode() 产生的
   */
  checkByUKey(encrypt, plaint) {
    // const MsgMoreUKey = '发现系统中有多把锁，请只插入要操作的锁。'
    // const MsgNoUKey = '未能在系统中发现加密锁.'

    // let KeyPath, lasterror

    // KeyPath = mSoftKey.FindPort(1)
    // lasterror = mSoftKey.GetLastError()

    // if (lasterror === 0) {
    //   throw new Error(MsgMoreUKey)
    // }

    // KeyPath = mSoftKey.FindPort(0)
    // lasterror = mSoftKey.GetLastError()

    // if (lasterror !== 0) {
    //   throw new Error(MsgNoUKey)
    // }
    // console.log(KeyPath)

    // ? 这里的规则需要和前端一样
    return mSoftKey.StrEnc(plaint + 'somekey here' + _ukey_id, _ukey).toUpperCase() === encrypt.toUpperCase()
  },

  /**
   * 代理获取其他服务的 token， 并返回
   */
  async getTokenByProxy() {
    const res = await axios
      .get(conf.proxy + '/soms/access/token', {
        params: {
          'user': 'some',
          'secret': 'some'
        }
      })
    if (res.status === 200 && res.data.errorCode === 0) {
      return res.data.access_token
    }
    return false
  }
}
