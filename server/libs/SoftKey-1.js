// JScript source code

var GETVERSION = 0x01
var GETID = 0x02
var GETVEREX = 0x05
var CAL_TEA = 0x08
var SET_TEAKEY = 0x09
var READBYTE = 0x10
var WRITEBYTE = 0x11
var YTREADBUF = 0x12
var YTWRITEBUF = 0x13
var MYRESET = 0x20
var YTREBOOT = 0x24
var SET_ECC_PARA = 0x30
var GET_ECC_PARA = 0x31
var SET_ECC_KEY = 0x32
var GET_ECC_KEY = 0x33
var MYENC = 0x34
var MYDEC = 0X35
var SET_PIN = 0X36
var GEN_KEYPAIR = 0x37
var YTVERIFY = 0x52
var GET_CHIPID = 0x53

// errcode
var FAILEDGENKEYPAIR = -21
var FAILENC = -22
var FAILDEC = -23
var FAILPINPWD = -24
var USBStatusFail = -50
var ERR_SET_REPORT = -94
var ERR_GET_REPORT = -93

var MAX_LEN = 2031

var SM2_ADDBYTE = 97//
var MAX_ENCLEN = 128 //
var MAX_DECLEN = (MAX_ENCLEN + SM2_ADDBYTE) //
var SM2_USENAME_LEN = 80//

var ECC_MAXLEN = 32
var PIN_LEN = 16

var MAX_TRANSE_LEN = 21
var SM2_MAX_TRANSE_LEN = 255

var ID_LEN = 16

class SoftKey {

  // TODO
  StrEnc(InString, Key) {
    var n; var m
    var nlen

    var b = Buffer.from(InString)
    var zero_buf = Buffer.from([0])
    b = Buffer.concat([b, zero_buf])
    nlen = b.length
    if (b.length < 8) {
      nlen = 8
    }

    var outb = Buffer.alloc(nlen)
    var inb = Buffer.alloc(nlen)
    b.copy(inb)// 如果少于8，则会补0，这里主要是用于补0
    b.copy(outb)

    for (n = 0; n <= (nlen - 8); n = n + 8) {
      var tmpoutb = this.sub_EnCode(inb, n, Key)
      for (m = 0; m < 8; m++) {
        outb[m + n] = tmpoutb[m]
      }
    }

    return outb.toString('hex')
  }

  // TODO 
  sub_EnCode(inb, pos, Key) {
    var cnDelta, y, z, a, b, c, d
    var outb = new Uint8Array(8)
    var n, i, nlen
    var sum
    var temp, temp_1

    var buf = new Array(16)
    var temp_string

    cnDelta = 2654435769
    sum = 0

    nlen = Key.length
    i = 0
    for (n = 1; n <= nlen; n = n + 2) {
      temp_string = Key.substring(n - 1, n - 1 + 2)
      buf[i] = this.HexToInt(temp_string)
      i = i + 1
    }
    a = 0; b = 0; c = 0; d = 0
    for (n = 0; n <= 3; n++) {
      a = (buf[n] << (n * 8)) | a
      b = (buf[n + 4] << (n * 8)) | b
      c = (buf[n + 4 + 4] << (n * 8)) | c
      d = (buf[n + 4 + 4 + 4] << (n * 8)) | d
    }

    y = 0
    z = 0
    for (n = 0; n <= 3; n++) {
      y = (inb[n + pos] << (n * 8)) | y
      z = (inb[n + 4 + pos] << (n * 8)) | z
    }

    n = 32

    while (n > 0) {
      sum = cnDelta + sum

      temp = (z << 4) & 0xFFFFFFFF

      temp = (temp + a) & 0xFFFFFFFF
      temp_1 = (z + sum) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp_1 = (z >>> 5) & 0xFFFFFFFF
      temp_1 = (temp_1 + b) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp = (temp + y) & 0xFFFFFFFF
      y = temp & 0xFFFFFFFF
      // y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);

      temp = (y << 4) & 0xFFFFFFFF
      temp = (temp + c) & 0xFFFFFFFF
      temp_1 = (y + sum) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp_1 = (y >>> 5) & 0xFFFFFFFF
      temp_1 = (temp_1 + d) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp = (z + temp) & 0xFFFFFFFF
      z = temp & 0xFFFFFFFF
      //  z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);

      n = n - 1
    }

    for (n = 0; n <= 3; n++) {
      outb[n] = ((y >>> (n * 8)) & 255)
      outb[n + 4] = ((z >>> (n * 8)) & 255)
    }
    return outb
  }

  // TODO
  HexToInt(s) {
    var hexch = '0123456789ABCDEF'
    var i, j
    var r, n, k
    var ch
    s = s.toUpperCase()

    k = 1; r = 0
    for (i = s.length; i > 0; i--) {
      ch = s.substring(i - 1, i - 1 + 1)
      n = 0
      for (j = 0; j < 16; j++) {
        if (ch == hexch.substring(j, j + 1)) {
          n = j
        }
      }
      r += (n * k)
      k *= 16
    }
    return r
  }
}

// vid,pid
SoftKey.VID = 0x3689
SoftKey.PID = 0x8762
SoftKey.PID_NEW = 0X2020
SoftKey.VID_NEW = 0X3689
SoftKey.PID_NEW_2 = 0X2020
SoftKey.VID_NEW_2 = 0X2020

module.exports = SoftKey

