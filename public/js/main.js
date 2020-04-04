/*
 * File: main.js
 * Project: test2
 * File Created: Monday, 30th March 2020 5:11:42 pm
 * Author: KLEN (liangchuqiang@gosuncn.com)
 * Description: Entry of verification
 * -----
 * Last Modified: Friday, 3rd April 2020 7:40:52 pm
 * Modified By: KLEN (liangchuqiang@gosuncn.com>)
 * -----
 * Copyright 2018 - 2020 广州高新兴机器人有限公司, 广州高新兴机器人有限公司
 * -----
 */
/* global SoftKey3W, ActiveXObject, $ */
var ERROR_EVENTS = {
  '100': '未检测到UKey 加密锁驱动的安装，或者驱动服务意外停止，请检查是否安装',
  '101': '未检测到UKey的插入，请检查是否正确插入UKey',
  '102': '网络错误，后台服务出了小差...',
  '103': '验证失败',
  '104': 'UKey 加密狗被拔出，请检查',
  '105': '使用增强算法一对字符串进行加密时错误',
  '106': '读取锁的ID时错误',
  '150': '接口错误'
}

/**
 * 1. 检查本地环境 IE or else
 * 2. 检车是否插入Ukey
 * 3. 检测是否安装了客户端
 *
 */
var bConnect = 0 // 检测是否连接驱动
var device_path = '' // UKey 驱动路径
var encrypt_txt = '' // UKey 加密后的密文
var ukey_id = '' // UKey id
var completed = false // 是否完成整个验证流程
var s_simnew1 // 控件实例 或者 封装websocket的 实例
var digitArray = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']

$.ajaxSetup({
  cache: false,
  headers: {
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
  },
  dataType: 'json'
})

/**
 * TODO 自定义错误
 * @param {String} msg 错误文案
 */
function ProcessError(msg) {
  // 实例化自定义错误时所传的错误信息参数
  this.message = msg
  // name 指明该错误类型（同时在控制台所打印的错误类型即由此字段指明），不指明默认为Error
  this.name = this.constructor.name
  // 捕获到当前执行环境的堆栈追踪信息，为自定义错误实例添加 `stack` 字段进行保存，
  // 第二个参数的含义为：堆栈追踪只会展示到 `ProcessError`这个函数（即自定义错误的构造函数）被调用之前。
  // this.stack = (new Error()).stack
  Error.captureStackTrace(this, ProcessError)
}
ProcessError.prototype = new Error()
ProcessError.prototype.constructor = ProcessError // * 指定自定义的构造器， 使用 instanceof 区分普通类型

/**
 * * 流程错误处理
 * @param {JSON} err 错误信息
 */
function handleError(err, msg) {
  try {
    var e,
      txt,
      ext

    if (typeof err === 'string') {
      e = JSON.parse(err)
      txt = ERROR_EVENTS[e.code]
    } else if (err instanceof ProcessError) {
      e = JSON.parse(err.message)
      if (e.type === 'process') {
        // 做一些状态处理
        txt = ERROR_EVENTS[e.code]
      }
    } else {
      console.log(err)
      return false
    }
    // non-null
    if (txt) {
      ext = msg ? '（' + msg + '）' : ''
      $('.loading__result').removeClass('is-hidden').html('错误：' + txt + ext)
      $('.loading__dot').hide()
      console.log(txt)
    }
  } catch (err) {
    console.log(err)
  }
}

function processError(code) {
  if (typeof code === 'undefined') return
  return JSON.stringify({
    type: 'process',
    code: code
  })
}

/**
 * 清空页面错误
 */
function resetError() {
  $('.loading__dot').show()
  $('.loading__result').addClass('is-hidden').html('')
}

/**
 * ? 请求后台获取随机数
 */
function getVerifiedCode() {
  var dtd = $.Deferred()

  $('.loading__txt').html('正在与服务器进行验证')
  var self = this
  $.ajax({
    url: '/api/auth/getVerifiedCode.action',
    type: 'get',
    success: function(res) {
      if (res.ret !== 1) {
        handleError(processError('150'))
        return false
      }
      // 使用UKey去加密异步获取的
      var random = res.data || ''
      if (!random) {
        self.handleError(processError('103'))
        return false
      }

      dtd.resolve(random)
    },
    error: function(err) {
      console.log(err)
      dtd.reject(err)
    }
  })

  return dtd
}

/**
 * ? 将密文发送回给服务器
 * @param {String} encrypt 将验证码加密后的密文
 */
function sendCipherCode(encrypt) {
  var dtd = $.Deferred()

  $.ajax({
    url: '/api/auth/sendCipherCode.action',
    type: 'post',
    contentType: 'application/x-www-form-urlencoded',
    data: {
      code: encrypt
    },
    success: function(res) {
      if (res.ret !== 1) {
        handleError(processError('150'), res.message)
        return false
      }
      $('.loading__txt').html('UKey 验证成功!!!')
      setTimeout(function() {
        window.location.href = '/login' // koa redirect
        dtd.resolve()
      }, 300)
    },
    error: function(err) {
      console.log(err)
      dtd.reject(err)
    }
  })

  return dtd
}

/**
 * 转化为十六进制
 * @param {String} n
 */
function toHex(n) {
  var result = ''
  var start = true

  for (var i = 32; i > 0;) {
    i -= 4
    var digit = (n >> i) & 0xf

    if (!start || digit !== 0) {
      start = false
      result += digitArray[digit]
    }
  }

  return (result === '' ? '0' : result)
}

/**
 * TODO 处理在IE 下的情况
 */
function handleIE10() {
  resetError()
  $('.loading__txt').html('检查本地环境')

  s_simnew1 = new ActiveXObject('Syunew3A.s_simnew3')
  device_path = s_simnew1.FindPort(0)// 查找加密锁
  if (s_simnew1.LastError !== 0) {
    self.handleError(processError('101'))
    return false
  }
  ukey_id = toHex(s_simnew1.GetID_1(device_path)) + toHex(s_simnew1.GetID_2(device_path))
  if (s_simnew1.LastError !== 0) {
    self.handleError(processError('106'))
    return false
  }

  $.when(getVerifiedCode())
    .then(function(code) {
    // ! 使用增强算法一对字符串进行加密， 必须是 [字符串]
      return s_simnew1.EncString(code + '@@' + ukey_id.toUpperCase(), device_path)
    })
    .then(function(encrypt) {
      if (s_simnew1.LastError !== 0) {
        self.handleError(processError('105'))
        return false
      }
      encrypt && sendCipherCode(encrypt)
    })
}

/**
 * * Websocket 连接成功，流程回调 非IE
 */
function handleProcess() {
  // 如果是IE10及以下浏览器，则使用AVCTIVEX控件的方式
  if (navigator.userAgent.indexOf('MSIE') > 0 && !navigator.userAgent.indexOf('opera') > -1) return handleIE10()
  try {
    resetError()
    $('.loading__txt').html('检查本地环境')

    if (s_simnew1) s_simnew1.Socket_UK.close() // 再次进入前，需要清除

    if (bConnect === 0) throw new ProcessError(processError('100'))

    s_simnew1 = new SoftKey3W() // 再次创建UK类， 用于业务交流，可以主动断开
    s_simnew1.Socket_UK.onopen = function() {
      s_simnew1.ResetOrder()// * 这里调用ResetOrder将计数清零，这样，消息处理处就会收到0序号的消息，通过计数及序号的方式，从而生产流程
    }
    // 写代码时一定要注意，每调用我们的一个UKEY函数，就会生产一个计数，即增加一个序号，较好的逻辑是一个序号的消息处理中，只调用我们一个UKEY的函数
    var self = this
    s_simnew1.Socket_UK.onmessage = function got_packet(Msg) {
      var UK_Data = JSON.parse(Msg.data)
      if (UK_Data.type !== 'Process') return // 如果不是流程处理消息，则跳过

      switch (UK_Data.order) {
        case 0: {
          s_simnew1.FindPort(0)// 查找加密锁
          $('.loading__txt').html('检查本地UKey')
          break
        }
        case 1: {
          if (UK_Data.LastError !== 0) {
            s_simnew1.Socket_UK.close()
            self.handleError(processError('101'))
            return false
          }
          device_path = UK_Data.return_value
          s_simnew1.GetID_1(device_path) // 前四个字节
          break
        }
        case 2: {
          if (UK_Data.LastError !== 0) {
            s_simnew1.Socket_UK.close()
            self.handleError(processError('106'))
            return false
          }
          ukey_id = toHex(UK_Data.return_value)
          s_simnew1.GetID_2(device_path) // 后四个字节
          break
        }

        case 3: {
          if (UK_Data.LastError !== 0) {
            s_simnew1.Socket_UK.close()
            self.handleError(processError('106'))
            return false
          }
          ukey_id += toHex(UK_Data.return_value)

          $.when(getVerifiedCode())
            .then(function(code) {
              // ! 使用增强算法一对字符串进行加密， 必须是 [字符串]
              s_simnew1.EncString(code + '@@' + ukey_id.toUpperCase(), device_path)
            })
          break
        }
        case 4: {
          if (UK_Data.LastError !== 0) {
            s_simnew1.Socket_UK.close()
            self.handleError(processError('105'))
            return false
          }
          encrypt_txt = UK_Data.return_value
          $.when(sendCipherCode(encrypt_txt))
          break
        }
      }
    }
  } catch (err) {
    handleError(err)
  }
}

window.onload = function() {
  // 如果是IE10及以下浏览器，则跳过不处理，
  if (navigator.userAgent.indexOf('MSIE') > 0 && !navigator.userAgent.indexOf('opera') > -1) {
    handleProcess() // 进入主流程
    return
  }
  try {
    var s_pnp = new SoftKey3W() // 检测连接
    s_pnp.Socket_UK.onopen = function() {
      bConnect = 1// 代表已经连接，用于判断是否安装了客户端服务
      handleProcess() // 进入主流程
    }

    // 在使用事件插拨时，注意，一定不要关掉Sockey，否则无法监测事件插拨
    s_pnp.Socket_UK.onmessage = function got_packet(Msg) {
      var PnpData = JSON.parse(Msg.data)
      if (PnpData.type === 'PnpEvent') { // 如果是插拨事件处理消息
        if (PnpData.IsIn) {
          device_path = PnpData.DevicePath
          if (!completed) handleProcess() // 进入主流程
        } else {
          $('.loading__txt').html('UKey 检测错误')
          handleError(processError('104'))
        }
      }
    }

    s_pnp.Socket_UK.onclose = function() {
      handleError(processError('100'))
    }
  } catch (e) {
    handleError(e)
  }
}
