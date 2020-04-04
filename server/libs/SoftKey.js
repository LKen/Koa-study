// JScript source code

var HID = require('node-hid')
const sm3 = require('sm3')

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
  SoftKey() {
    // connection object
    SoftKey.connection = null
  }

  GetLastError() {
    return this.lasterror
  }

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

  StrDec(InString, Key)//
  {
    var n, m
    var inb = new Buffer(InString, 'hex')
    var outb = Buffer.alloc(inb.length)
    inb.copy(outb)

    for (n = 0; n <= inb.length - 8; n = n + 8) {
      var tmpoutb = this.sub_DeCode(inb, n, Key)
      for (m = 0; m < 8; m++) {
        outb[m + n] = tmpoutb[m]
      }
    }

    return outb.toString()
  }

  EnCode(inb, Key) {
    this.sub_EnCode(inb, 0, Key)
  }

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

  DeCode() {
    sub_DeCode(inb, 0, Key)
  }

  sub_DeCode(inb, pos, Key) {
    var cnDelta, y, z, a, b, c, d
    var outb = new Uint8Array(8)
    var n, i, nlen
    var sum
    var temp, temp_1

    var buf = new Array(16)
    var temp_string

    cnDelta = 2654435769
    sum = 3337565984

    nlen = Key.length
    i = 0
    for (n = 1; n <= nlen; n = n + 2) {
      temp_ = Key.substring(n - 1, n - 1 + 2)
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
      temp = (y << 4) & 0xFFFFFFFF
      temp = (temp + c) & 0xFFFFFFFF
      temp_1 = (y + sum) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp_1 = (y >>> 5) & 0xFFFFFFFF
      temp_1 = (temp_1 + d) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp = (z - temp) & 0xFFFFFFFF
      z = temp & 0xFFFFFFFF
      //  z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);

      temp = (z << 4) & 0xFFFFFFFF
      temp = (temp + a) & 0xFFFFFFFF
      temp_1 = (z + sum) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp_1 = (z >>> 5) & 0xFFFFFFFF
      temp_1 = (temp_1 + b) & 0xFFFFFFFF
      temp = (temp ^ temp_1) & 0xFFFFFFFF
      temp = (y - temp) & 0xFFFFFFFF
      y = temp & 0xFFFFFFFF
      // y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);

      sum = sum - cnDelta
      n = n - 1
    }

    for (n = 0; n <= 3; n++) {
      outb[n] = ((y >>> (n * 8)) & 255)
      outb[n + 4] = ((z >>> (n * 8)) & 255)
    }
    return outb
  }

  MacthUKeyID(mDevices) {
    if ((mDevices.vendorId == SoftKey.VID && mDevices.productId == SoftKey.PID) ||
      (mDevices.vendorId == SoftKey.VID_NEW && mDevices.productId == SoftKey.PID_NEW) ||
      (mDevices.vendorId == SoftKey.VID_NEW_2 && mDevices.productId == SoftKey.PID_NEW_2)) {
      return true
    }
    return false
  }

  // ///////////////////
  AddZero(InKey) {
    var nlen
    var n
    nlen = InKey.length
    for (n = nlen; n <= 7; n++) {
      InKey = '0' + InKey
    }
    return InKey
  }

  myconvert(HKey, LKey) {
    HKey = this.AddZero(HKey)
    LKey = this.AddZero(LKey)
    var out_data = new Uint8Array(8)
    var n
    for (n = 0; n <= 3; n++) {
      out_data[n] = this.HexToInt(HKey.substring(n * 2, n * 2 + 2))
    }
    for (n = 0; n <= 3; n++) {
      out_data[n + 4] = this.HexToInt(LKey.substring(n * 2, n * 2 + 2))
    }
    return out_data
  }

  // //bin2hex  & hex2bin
  ByteArrayToHexString(Inb, len) {
    var outstring = ''
    for (var n = 0; n <= len - 1; n++) {
      outstring = outstring + this.myhex(Inb[n])
    }
    return outstring
  }

  HexStringToByteArray(InString) {
    var nlen
    var retutn_len
    var n, i
    var b
    var temp
    nlen = InString.length
    if (nlen < 16) retutn_len = 16
    retutn_len = nlen / 2
    b = new Uint8Array(retutn_len)
    i = 0
    for (n = 0; n < nlen; n = n + 2) {
      temp = InString.substring(n, n + 2)
      b[i] = this.HexToInt(temp)
      i = i + 1
    }
    return b
  }
  // //////

  // decimal to hex && hex2dec
  myhex(value) {
    if (value < 16) { return '0' + value.toString(16) }
    return value.toString(16)
  }

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
  // //////////////

  // ///////////// send cmd only ,no carry data
  SendNoWithData(CmdFlag) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    this.SendWithData(CmdFlag, array_in)
    return this.lasterror
  }
  // /////////////////////////
  /* SendWithDataNoErr(CmdFlag,array_in,KeyPath) {

      this.lasterror=0;
      var featureReport = [2, 0];

      featureReport[1] = CmdFlag;

      for (var i = 1; i < array_in.length; i++) {
          featureReport[i + 1] =array_in[i];
      }
      if(KeyPath==null)
      {
          this.lasterror= -92;
          return array_out;
      }
      this.connection = new  HID.HID(KeyPath)
      if(this.connection==null)
      {
          this.lasterror= -92;
          return array_out;
      }
      var Outlen=this.connection.sendFeatureReport( featureReport);
      if(Outlen<2) {this.connection.close();this.lasterror= ERR_SET_REPORT;return undefined;}
      var array_out=this.connection.getFeatureReport(1,SM2_MAX_TRANSE_LEN) ;
      this.connection.close();
      if(array_out.length<1){this.lasterror=ERR_GET_REPORT; return undefined;}

      return array_out;

  }*/
  // /////////send cmd and data
  SendWithDataNoErr(CmdFlag, array_in, KeyPath) {
    this.lasterror = 0
    var featureReport = [2]
    for (var n = 1; n <= SM2_MAX_TRANSE_LEN + 1; n++) {
      featureReport[n] = 0
    }

    featureReport[1] = CmdFlag

    for (var i = 1; i < array_in.length; i++) {
      featureReport[i + 1] = array_in[i]
    }
    if (KeyPath == null) {
      this.lasterror = -92
      return array_out
    }
    this.connection = new HID.HID(KeyPath)
    if (this.connection == null) {
      this.lasterror = -92
      return array_out
    }
    var Outlen = this.connection.sendFeatureReport(featureReport)
    if (Outlen < 2) { this.connection.close(); this.lasterror = ERR_SET_REPORT; return undefined }
    var array_out = this.connection.getFeatureReport(1, 510)
    this.connection.close()
    if (array_out.length < 1) { this.lasterror = ERR_GET_REPORT; return undefined }

    return array_out
  }

  SendWithData(CmdFlag, array_in, KeyPath) {
    var array_out = this.SendWithDataNoErr(CmdFlag, array_in, KeyPath)

    if (array_out[0] != 0) {
      this.lasterror = array_out[0] - 256
    } else {
      this.lasterror = 0
    }

    return array_out
  }
  // /////////////
  GetOneByteDataFromUsbKey(cmd, KeyPath) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var array_out
    array_out = this.SendWithDataNoErr(cmd, array_in, KeyPath)
    if (this.lasterror) return undefined
    return array_out[0]
  }
  // //////

  FindPort(start) {
    this.lasterror = 0
    var KeyPath = ''
    var count = 0
    var devices = HID.devices()
    devices.forEach(mDevice => {
      if (this.MacthUKeyID(mDevice)) {
        if (count == start) {
          KeyPath = mDevice.path
          return KeyPath
        }
        count++
      }
    })
    if (KeyPath != '') {
      this.lasterror = 0
    } else {
      this.lasterror = -92
    }
    return KeyPath
  }

  // //////////////////////////////////////////////////////////////////////////////////

  NT_GetIDVersionEx(KeyPath) {
    return this.GetOneByteDataFromUsbKey(5, KeyPath)
  }

  NT_GetIDVersion(KeyPath) {
    return this.GetOneByteDataFromUsbKey(1, KeyPath)
  }
  // ///

  GetID(KeyPath) {
    var IDInfo = {
      ID_1: '',
      ID_2: ''
    }
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var array_out
    var t1 = new Buffer.alloc(4)
    var t2 = new Buffer.alloc(4)
    array_out = this.SendWithDataNoErr(2, array_in, KeyPath)
    if (this.lasterror != 0) { return '' }
    t1[0] = array_out[0]; t1[1] = array_out[1]; t1[2] = array_out[2]; t1[3] = array_out[3]
    t2[0] = array_out[4]; t2[1] = array_out[5]; t2[2] = array_out[6]; t2[3] = array_out[7]
    IDInfo.ID_1 = t1.toString('hex')
    IDInfo.ID_2 = t2.toString('hex')
    return IDInfo
  }

  GetChipID(KeyPath) {
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var array_out

    var OutChipID = ''; var outb = new Uint8Array(ID_LEN)

    array_out = this.SendWithDataNoErr(GET_CHIPID, array_in, KeyPath)
    if (this.lasterror != 0) { return '' }
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail
      return OutChipID
    }

    outb = array_out.slice(1, ID_LEN + 1)

    OutChipID = this.ByteArrayToHexString(outb, 16)
    OutChipID = OutChipID.toUpperCase()
    return OutChipID
  }
  // //////

  // ///
  FindPort_2(start, in_data, verf_data) {
    var n
    var count = 0
    var out_data = 0
    for (n = 0; n < 256; n++) {
      var KeyPath = this.FindPort(n)
      if (this.lasterror != 0) return null
      out_data = this.sWriteEx(in_data, KeyPath)
      if (this.lasterror != 0) return null
      if (out_data == verf_data) {
        if (start == count) return KeyPath
        count++
      }
    }
    return null
  }

  SetWritePassword(W_HKey, W_LKey, new_HKey, new_LKey, KeyPath) {
    var address
    var ary1 = this.myconvert(W_HKey, W_LKey)
    var ary2 = this.myconvert(new_HKey, new_LKey)
    address = 504

    this.lasterror = this.Sub_WriteByte(ary2, address, 8, ary1, 0, KeyPath)

    return this.lasterror
  }

  SetReadPassword(W_HKey, W_LKey, new_HKey, new_LKey, KeyPath) {
    var address
    var ary1 = this.myconvert(W_HKey, W_LKey)
    var ary2 = this.myconvert(new_HKey, new_LKey)
    address = 496

    this.lasterror = this.Sub_WriteByte(ary2, address, 8, ary1, 0, KeyPath)

    return this.lasterror
  }

  NT_SetCal(cmd, indata, IsHi, pos, KeyPath) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var n
    array_in[1] = IsHi
    for (n = 0; n < 8; n++) {
      array_in[2 + n] = indata[n + pos]
    }

    var array_out = this.SendWithData(cmd, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0) {
      this.lasterror = -82
    }
    return this.lasterror
  }

  Sub_SetCal(cmd, Key, KeyPath) {
    var KeyBuf = this.HexStringToByteArray(Key)
    this.lasterror = this.NT_SetCal(cmd, KeyBuf, 0, 8, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    return this.NT_SetCal(cmd, KeyBuf, 1, 0, KeyPath)
  }

  SetCal_2(Key, KeyPath) {
    return this.Sub_SetCal(SET_TEAKEY, Key, KeyPath)
  }

  SetCal_New(Key, KeyPath) {
    return this.Sub_SetCal(13, Key, KeyPath)
  }

  Sub_EncString(cmd, InString, KeyPath) {
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
      var tmpoutb = this.NT_Cal(cmd, inb, n, KeyPath)
      for (m = 0; m < 8; m++) {
        outb[m + n] = tmpoutb[m]
      }
      if (this.lasterror != 0) ''
    }

    return outb.toString('hex')
  }

  EncString(InString, KeyPath) {
    return this.Sub_EncString(8, InString, KeyPath)
  }

  EncString_New(InString, KeyPath) {
    return this.Sub_EncString(12, InString, KeyPath)
  }

  NT_Cal(cmd, InBuf, pos, KeyPath) {
    var n
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var outbuf = new Uint8Array(8)
    for (n = 1; n <= 8; n++) {
      array_in[n] = InBuf[n - 1 + pos]
    }
    var array_out = this.SendWithDataNoErr(cmd, array_in, KeyPath)
    if (this.lasterror != 0) return undefined
    for (n = 0; n < 8; n++) {
      outbuf[n + pos] = array_out[n]
    }
    if (array_out[8] != 0x55) {
      this.lasterror = -20
    }
    return outbuf
  }

  Cal(Inbuf, KeyPath) {
    return this.NT_Cal(8, Inbuf, 0, KeyPath)
  }

  Cal_New(Inbuf, KeyPath) {
    return this.NT_Cal(12, Inbuf, 0, KeyPath)
  }

  SimpleCalData(cmd, in_data, KeyPath) {
    var t1
    var t2
    var t3
    var t4
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    array_in[1] = (in_data & 255)
    array_in[2] = ((in_data >> 8) & 255)
    array_in[3] = ((in_data >> 16) & 255)
    array_in[4] = ((in_data >> 24) & 255)

    var array_out
    array_out = this.SendWithDataNoErr(cmd, array_in, KeyPath)
    if (this.lasterror != 0) { return 0 }
    t1 = array_out[0]
    t2 = array_out[1]
    t3 = array_out[2]
    t4 = array_out[3]

    return t1 | (t2 << 8) | (t3 << 16) | (t4 << 24)
  }

  sWriteEx(in_data, KeyPath) {
    return this.SimpleCalData(0x03, in_data, KeyPath)
  }

  sWrite_2Ex(in_data, KeyPath) {
    return this.SimpleCalData(0x04, in_data, KeyPath)
  }

  // ///////////////////
  Sub_WriteByte(indata, address, nlen, password, pos, KeyPath) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var addr_l
    var addr_h
    var n
    if ((address + nlen - 1) > (MAX_LEN + 17) || (address < 0)) return -81
    addr_h = (address >> 8) * 2
    addr_l = address & 255

    array_in[1] = addr_h
    array_in[2] = addr_l
    array_in[3] = nlen

    for (n = 0; n <= 7; n++) {
      array_in[4 + n] = password[n]
    }
    for (n = 0; n < nlen; n++) {
      array_in[12 + n] = indata[n + pos]
    }

    var array_out = this.SendWithDataNoErr(0x13, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0) {
      this.lasterror = -82
    }
    return this.lasterror
  }
  // ////////////

  Sub_ReadByte(address, nlen, password, KeyPath) {
    var outData = new Uint8Array(nlen)
    var array_out
    var ret
    if (nlen > MAX_TRANSE_LEN) {
      this.lasterror = ERR_OVER_SEC_MAX_LEN
      return outData
    }
    if ((address + nlen > MAX_LEN)) {
      this.lasterror == ERR_OVER_SEC_MAX_LEN
      return outData
    }

    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var addr_l
    var addr_h
    var n

    addr_h = (address >> 8) * 2
    addr_l = address & 255

    array_in[1] = addr_h
    array_in[2] = addr_l
    array_in[3] = nlen

    for (n = 0; n <= 7; n++) {
      array_in[4 + n] = password[n]
    }

    array_out = this.SendWithDataNoErr(0x12, array_in, KeyPath)
    if (this.lasterror != 0) return undefined
    if (array_out[0] != 0) {
      this.lasterror = -82; return outData
    }
    for (n = 0; n < (nlen); n++) {
      outData[n] = array_out[n + 1]
    }
    return outData
  }

  // ///////////////////////////
  YWriteEx(indata, address, nlen, HKey, LKey, KeyPath) {
    var ret = 0
    var n; var trashLen = 16

    if ((address + nlen - 1 > MAX_LEN) || (address < 0)) return -81

    trashLen = trashLen - 8

    var password = this.myconvert(HKey, LKey)
    var tmplen
    var pos = 0
    while (nlen > 0) {
      if (nlen > trashLen) { tmplen = trashLen } else { tmplen = nlen }
      this.lasterror = this.Sub_WriteByte(indata, address + pos, tmplen, password, pos, KeyPath)
      if (this.lasterror != 0) { return this.lasterror }
      nlen = nlen - trashLen
      pos = pos + trashLen
    }

    return this.lasterror
  }

  // /////////////////////////////
  YWriteString(InString, Address, HKey, LKey, KeyPath) {
    var Buf = Buffer.from(InString)
    this.YWriteEx(Buf, Address, Buf.length, HKey, LKey, KeyPath)
    if (this.lasterror < 0) return this.lasterror
    return Buf.length
  }

  // /////////////
  YReadEx(address, nlen, HKey, LKey, KeyPath) {
    var ret = 0
    var password = new Uint8Array(8)
    var n; var trashLen = 16
    var OutData = Buffer.alloc(0)
    var tmp_OutData

    if ((address + nlen - 1 > MAX_LEN) || (address < 0)) return (-81)

    password = this.myconvert(HKey, LKey)
    var tmplen
    var pos = 0
    while (nlen > 0) {
      if (nlen > trashLen) { tmplen = trashLen } else { tmplen = nlen }
      tmp_OutData = this.Sub_ReadByte(address + pos, tmplen, password, KeyPath)
      if (this.lasterror != 0) { return OutData }
      OutData = Buffer.concat([OutData, tmp_OutData])
      nlen = nlen - trashLen
      pos = pos + trashLen
    }

    return OutData
  }
  // ////////////

  YReadString(Address, nlen, HKey, LKey, KeyPath) {
    var outData = this.YReadEx(Address, nlen, HKey, LKey, KeyPath)

    return outData.toString()
  }

  // /////////////////////////////////////////////////// other api
  NT_ReSet(KeyPath) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var array_out = this.SendWithDataNoErr(MYRESET, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0) {
      this.lasterror = -82
    }
    return this.lasterror
  }

  ReSet(KeyPath) {
    this.lasterror = this.NT_ReSet(KeyPath)
    return this.lasterror
  }

  y_setcal(indata, password, KeyPath) {
    var n
    var array_in = new Uint8Array(MAX_TRANSE_LEN)

    array_in[1] = 0
    array_in[2] = 0
    array_in[3] = 8
    for (n = 0; n <= 7; n++) {
      array_in[4 + n] = password[n]
    }
    for (n = 0; n < 8; n++) {
      array_in[12 + n] = indata[n]
    }
    var array_out = this.SendWithDataNoErr(6, array_in, KeyPath)
    if (this.lasterror) return this.lasterror
    if (array_out[0] != 0) {
      this.lasterror = -82
    }
    return this.lasterror
  }

  SetCal(HKey, LKey, new_HKey, new_LKey, KeyPath) {
    var ary1 = this.myconvert(HKey, LKey)
    var ary2 = this.myconvert(new_HKey, new_LKey)

    this.lasterror = this.y_setcal(ary2, ary1, KeyPath)

    return this.lasterror
  }

  NT_SetID(InBuf, KeyPath) {
    var n
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    for (n = 1; n <= 8; n++) {
      array_in[n] = InBuf[n - 2]
    }
    var array_out = this.SendWithDataNoErr(7, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0) {
      this.lasterror = -82
    }
    return this.lasterror
  }

  SetID(Seed, KeyPath) {
    var KeyBuf = this.HexStringToByteArray(Seed)

    return this.NT_SetID(KeyBuf, KeyPath)
  }

  GetProduceDate(KeyPath) {
    var n
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var OutProduceDate = Buffer.alloc(8)
    var array_out = this.SendWithDataNoErr(15, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    for (n = 0; n < 8; n++) {
      OutProduceDate[n] = array_out[n]
    }
    return OutProduceDate.toString('hex')
  }

  SetHidOnly(IsHidOnly, KeyPath) {
    return this.NT_SetHidOnly(IsHidOnly, KeyPath)
  }
  NT_SetHidOnly(IsHidOnly, KeyPath) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)

    if (IsHidOnly) array_in[1] = 0; else array_in[1] = 0xff
    var array_out = this.SendWithDataNoErr(0x55, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0) {
      return -82
    }
    return 0
  }

  SetUReadOnly(KeyPath) {
    return this.NT_SetUReadOnly(KeyPath)
  }
  NT_SetUReadOnly(KeyPath) {
    var array_in = new Uint8Array(MAX_TRANSE_LEN)
    var array_out = this.SendWithDataNoErr(0x56, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0) {
      return -82
    }
    return 0
  }

  NT_Set_SM2_KeyPair(PriKey, PubKeyX, PubKeyY, sm2_UerName, KeyPath) {
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var n = 0

    for (n = 0; n < ECC_MAXLEN; n++) {
      array_in[1 + n + ECC_MAXLEN * 0] = PriKey[n]
      array_in[1 + n + ECC_MAXLEN * 1] = PubKeyX[n]
      array_in[1 + n + ECC_MAXLEN * 2] = PubKeyY[n]
    }
    for (n = 0; n < SM2_USENAME_LEN; n++) {
      array_in[1 + n + ECC_MAXLEN * 3] = sm2_UerName[n]
    }

    var array_out = this.SendWithDataNoErr(0x32, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0x20) this.lasterror = USBStatusFail

    return this.lasterror
  }

  NT_GenKeyPair(KeyPath) {
    var KEYPAIR = {
      PriKey: null,
      PubKeyX: null,
      PubKeyY: null
    }
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var n = 0

    var array_out = this.SendWithDataNoErr(GEN_KEYPAIR, array_in, KeyPath)
    if (this.lasterror != 0) return undefined
    if (array_out[0] != 0x20) {
      this.lasterror = FAILEDGENKEYPAIR; return undefined
    }
    KEYPAIR.PriKey = array_out.slice(1, 1 + ECC_MAXLEN)
    KEYPAIR.PubKeyX = array_out.slice(1 + ECC_MAXLEN, ECC_MAXLEN * 2 + 1)
    KEYPAIR.PubKeyY = array_out.slice(1 + ECC_MAXLEN * 2, ECC_MAXLEN * 3 + 1)
    return KEYPAIR
  }

  NT_Get_SM2_PubKey(KeyPath) {
    var SM2_PubKeyInfo = {
      KGx: null,
      KGy: null,
      sm2_UerName: null
    }
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var n = 0

    var array_out = this.SendWithDataNoErr(0x33, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail; return this.lasterror
    }

    SM2_PubKeyInfo.KGx = array_out.slice(1, 1 + ECC_MAXLEN * 1)
    SM2_PubKeyInfo.KGy = array_out.slice(1 + ECC_MAXLEN * 1, 1 + ECC_MAXLEN * 2)

    SM2_PubKeyInfo.sm2_UerName = array_out.slice(1 + ECC_MAXLEN * 2, 1 + ECC_MAXLEN * 2 + SM2_USENAME_LEN)

    return SM2_PubKeyInfo
  }

  NT_Set_Pin(old_pin, new_pin, KeyPath) {
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var n = 0

    var b_oldpin = Buffer.from(old_pin)
    var b_newpin = Buffer.from(new_pin)
    for (n = 0; n < PIN_LEN; n++) {
      array_in[1 + PIN_LEN * 0 + n] = b_oldpin[n]
      array_in[1 + PIN_LEN * 1 + n] = b_newpin[n]
    }

    var array_out = this.SendWithDataNoErr(SET_PIN, array_in, KeyPath)
    if (this.lasterror != 0) return this.lasterror
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail; return this.lasterror
    }
    if (array_out[1] != 0x20) {
      this.lasterror = FAILPINPWD
    }
    return this.lasterror
  }

  NT_SM2_Enc(inbuf, inlen, KeyPath) {
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var outbuf = new Uint8Array(inlen + SM2_ADDBYTE)
    var n = 0

    array_in[1] = inlen
    for (n = 0; n < inlen; n++) {
      array_in[2 + n] = inbuf[n]
    }
    var array_out = this.SendWithDataNoErr(MYENC, array_in, KeyPath)
    if (this.lasterror != 0) {
      return outbuf
    }
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail
      return outbuf
    }
    if (array_out[1] == 0) {
      this.lasterror = FAILENC
      return outbuf
    }

    for (n = 0; n < (inlen + SM2_ADDBYTE); n++) {
      outbuf[n] = array_out[2 + n]
    }

    return outbuf
  }

  NT_SM2_Dec(inbuf, inlen, pin, KeyPath) {
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var outbuf = new Uint8Array(inlen - SM2_ADDBYTE)
    var n = 0

    var b_pin = Buffer.from(pin)
    for (n = 0; n < PIN_LEN; n++) {
      array_in[1 + PIN_LEN * 0 + n] = b_pin[n]
    }
    array_in[1 + PIN_LEN] = inlen
    for (n = 0; n < inlen; n++) {
      array_in[1 + PIN_LEN + 1 + n] = inbuf[n]
    }
    var array_out = this.SendWithDataNoErr(MYDEC, array_in, KeyPath)
    if (this.lasterror != 0) {
      return outbuf
    }
    if (array_out[2] != 0x20) {
      this.lasterror = FAILPINPWD; return outbuf
    }
    if (array_out[1] == 0) {
      this.lasterror = FAILENC; return outbuf
    }
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail; return outbuf
    }
    for (n = 0; n < (inlen - SM2_ADDBYTE); n++) {
      outbuf[n] = array_out[3 + n]
    }

    return outbuf
  }

  sub_NT_Sign(cmd, inbuf, pin, KeyPath) {
    var outbuf = new Uint8Array(ECC_MAXLEN * 2)
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var n = 0

    var b_pin = Buffer.from(pin)
    for (n = 0; n < PIN_LEN; n++) {
      array_in[1 + PIN_LEN * 0 + n] = b_pin[n]
    }
    for (n = 0; n < 32; n++) {
      array_in[1 + PIN_LEN + n] = inbuf[n]
    }
    var array_out = this.SendWithDataNoErr(cmd, array_in, KeyPath)
    if (this.lasterror != 0) {
      return outbuf
    }
    if (array_out[1] != 0x20) {
      this.lasterror = FAILPINPWD
      return outbuf
    }
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail
      return outbuf
    }
    for (n = 0; n < ECC_MAXLEN * 2; n++) {
      outbuf[n] = array_out[2 + n]
    }

    return outbuf
  }

  NT_Sign(inbuf, pin, KeyPath) {
    return this.sub_NT_Sign(0x51, inbuf, pin, KeyPath)
  }

  NT_Sign_2(inbuf, pin, KeyPath) {
    return this.sub_NT_Sign(0x53, inbuf, pin, KeyPath)
  }

  NT_Verfiy(inbuf, InSignBuf, KeyPath) {
    var array_in = new Uint8Array(SM2_MAX_TRANSE_LEN)
    var n = 0

    for (n = 0; n < ECC_MAXLEN; n++) {
      array_in[1 + n] = inbuf[n]
    }
    for (n = 0; n < ECC_MAXLEN * 2; n++) {
      array_in[1 + ECC_MAXLEN + n] = InSignBuf[n]
    }
    var array_out = this.SendWithDataNoErr(YTVERIFY, array_in, KeyPath)
    if (this.lasterror != 0) return false
    var outbiao = (array_out[1] != 0)
    if (array_out[0] != 0x20) {
      this.lasterror = USBStatusFail; return false
    }

    return outbiao
  }

  YT_GenKeyPair(KeyPath) {
    var n
    var KeyPairInfo = {
      PriKey: '',
      PubKeyX: '',
      PubKeyY: ''
    }
    var KEYPAIR = this.NT_GenKeyPair(KeyPath)
    if (this.lasterror) return KeyPairInfo
    KeyPairInfo.PriKey = this.ByteArrayToHexString(KEYPAIR.PriKey, ECC_MAXLEN)
    KeyPairInfo.PubKeyX = this.ByteArrayToHexString(KEYPAIR.PubKeyX, ECC_MAXLEN)
    KeyPairInfo.PubKeyY = this.ByteArrayToHexString(KEYPAIR.PubKeyY, ECC_MAXLEN)

    return KeyPairInfo
  }

  Set_SM2_KeyPair(PriKey, PubKeyX, PubKeyY, SM2_UserName, KeyPath) {
    var b_PriKey = this.HexStringToByteArray(PriKey)
    var b_PubKeyX = this.HexStringToByteArray(PubKeyX)
    var b_PubKeyY = this.HexStringToByteArray(PubKeyY)

    var b_SM2UserName = Buffer.from(SM2_UserName)

    return this.NT_Set_SM2_KeyPair(b_PriKey, b_PubKeyX, b_PubKeyY, b_SM2UserName, KeyPath)
  }

  Get_SM2_PubKey(KeyPath) {
    var PubKeyInfo = {
      PubKeyX: '',
      PubKeyY: '',
      sm2UserName: ''
    }

    var SM2_PubKeyInfo = this.NT_Get_SM2_PubKey(KeyPath)

    PubKeyInfo.PubKeyX = this.ByteArrayToHexString(SM2_PubKeyInfo.KGx, ECC_MAXLEN)
    PubKeyInfo.PubKeyY = this.ByteArrayToHexString(SM2_PubKeyInfo.KGy, ECC_MAXLEN)
    PubKeyInfo.sm2UserName = new Buffer(SM2_PubKeyInfo.sm2_UerName).toString()
    return PubKeyInfo
  }

  SM2_EncBuf(InBuf, inlen, KeyPath) {
    var n; var temp_inlen; var incount = 0; var outcount = 0
    var temp_InBuf = new Uint8Array(MAX_ENCLEN + SM2_ADDBYTE)
    var OutBuf = Buffer.alloc(0)
    // InBuf.copy(OutBuf);
    while (inlen > 0) {
      if (inlen > MAX_ENCLEN) { temp_inlen = MAX_ENCLEN } else { temp_inlen = inlen }
      for (n = 0; n < temp_inlen; n++) {
        temp_InBuf[n] = InBuf[incount + n]
      }
      var temp_OutBuf = this.NT_SM2_Enc(temp_InBuf, temp_inlen, KeyPath)
      if (this.lasterror) return OutBuf
      OutBuf = Buffer.concat([OutBuf, temp_OutBuf])
      inlen = inlen - MAX_ENCLEN
      incount = incount + MAX_ENCLEN
      outcount = outcount + MAX_DECLEN
    }

    return OutBuf
  }

  SM2_DecBuf(InBuf, inlen, pin, KeyPath) {
    var temp_inlen; var n; var incount = 0; var outcount = 0
    var temp_InBuf = new Uint8Array(MAX_ENCLEN + SM2_ADDBYTE)
    var OutBuf = Buffer.alloc(InBuf.length)
    // var b=new Buffer(InBuf)
    // b.copy(OutBuf);
    var OutBuf = Buffer.alloc(0)
    while (inlen > 0) {
      if (inlen > MAX_DECLEN) { temp_inlen = MAX_DECLEN } else { temp_inlen = inlen }
      for (n = 0; n < temp_inlen; n++) {
        temp_InBuf[n] = InBuf[incount + n]
      }
      var temp_OutBuf = this.NT_SM2_Dec(InBuf, temp_inlen, pin, KeyPath)
      if (this.lasterror) return OutBuf
      OutBuf = Buffer.concat([OutBuf, temp_OutBuf])
      inlen = inlen - MAX_DECLEN
      incount = incount + MAX_DECLEN
      outcount = outcount + MAX_ENCLEN
    }
    return OutBuf
  }

  SM2_EncString(InString, KeyPath) {
    var InBuf = Buffer.from(InString)
    var OutBuf = this.SM2_EncBuf(InBuf, InBuf.length, KeyPath)
    if (this.lasterror) return OutBuf
    return this.ByteArrayToHexString(OutBuf, OutBuf.length)
  }

  SM2_DecString(InString, pin, KeyPath) {
    var InBuf = this.HexStringToByteArray(InString)

    var OutBuf = this.SM2_DecBuf(InBuf, InBuf.length, pin, KeyPath)

    return OutBuf.toString()
  }

  YtSetPin(old_pin, new_pin, KeyPath) {
    return this.NT_Set_Pin(old_pin, new_pin, KeyPath)
  }

  Sub_YtSign(cmd, msg, pin, KeyPath) {
    var OutSign

    var MsgHashValue = sm3(msg)
    var Inbuf = new Buffer.from(MsgHashValue, 'hex')
    var OutBuf = this.sub_NT_Sign(cmd, Inbuf, pin, KeyPath)
    if (this.lasterror != 0) return OutSign
    OutSign = new Buffer(OutBuf).toString('hex')
    return OutSign
  }

  YtSign(msg, pin, KeyPath) {
    return this.Sub_YtSign(0x51, msg, pin, KeyPath)
  }

  YtSign_2(msg, pin, KeyPath) {
    return this.Sub_YtSign(0x53, msg, pin, KeyPath)
  }

  CheckKeyByFindort_2() {
    // 使用普通算法查找指定的加密锁
    var DevicePath = '' // 用于储存加密锁的路径
    DevicePath = this.FindPort_2(0, 1, -2107676555)
    return this.lasterror
  }

  // 使用带长度的方法从指定的地址中读取字符串
  ReadStringEx(addr, DevicePath) {
    var nlen
    // 先从地址0读取以前写入的字符串长度
    var OutData = this.YReadEx(addr, 1, 'FFFFFFFF', 'FFFFFFFF', DevicePath)
    if (this.lasterror != 0) return ''
    nlen = OutData[0]
    // 再读取相应长度的字符串
    return this.YReadString(addr + 1, nlen, 'FFFFFFFF', 'FFFFFFFF', DevicePath)
  }
  // 使用从储存读取相应的数据的方式来检查是否存在指定的加密锁
  CheckKeyByReadEprom() {
    var n, ret

    // @NoUseCode_data return 1;//如果没有使用这个功能，直接返回1
    for (n = 0; n < 255; n++) {
      var DevicePath = this.FindPort(n)// 用于储存加密锁的路径
      if (this.lasterror != 0) return this.lasterror
      var outString = this.ReadStringEx(0, DevicePath)
      if ((this.lasterror == 0) && (outString == 'admin')) return 0
    }
    return -92
  }
  // 使用增强算法一检查加密锁，这个方法可以有效地防止仿真
  CheckKeyByEncstring() {
    // 推荐加密方案：生成随机数，让锁做加密运算，同时在程序中使用代码做同样的加密运算，然后进行比较

    var n, ret

    var InString

    // @NoUseKeyEx return 1;//如果没有使用这个功能，直接返回1
    var number1 = Math.floor(Math.random() * 65535)
    var number2 = Math.floor(Math.random() * 65535)

    InString = number1.toString() + number2.toString()

    for (n = 0; n < 255; n++) {
      var DevicePath = this.FindPort(n)// 用于储存加密锁的路径
      if (this.lasterror != 0) return this.lasterror
      if (this.Sub_CheckKeyByEncString(InString, DevicePath) == 0) return 0
    }
    return -92
  }

  Sub_CheckKeyByEncString(InString, DevicePath) {
    // 使用增强算法一对字符串进行加密

    var outString = this.EncString(InString, DevicePath)
    if (this.lasterror != 0) return this.lasterror
    var outString_2 = this.StrEnc(InString, '6CB0737364C34BBBBC20AF4E97630DC2')
    if (outString_2.toUpperCase() == outString.toUpperCase())// 比较结果是否相符
    {
      return 0
    }

    return -92
  }

  // ?使用增强算法二检查加密锁，这个方法可以有效地防止软复制
  CheckKeyByEncstring_New() {
    var n, ret
    var myrnd = Math.floor(Math.random() * 500)
    var EncInString = ['16938', '15122', '23209', '5369', '29384', '11039', '9419', '1982', '18179', '18647', '7273', '20106', '2468', '23517', '29342', '15890', '1173', '11892', '20645', '17063', '15072', '24443', '25046', '16954', '17070', '21622', '32173', '7774', '16204', '19335',
      '29123', '22083', '31520', '3439', '27602', '18622', '8632', '16273', '949', '5696', '6588', '21998', '25955', '8922', '32501', '9514', '6906', '14399', '15439', '5253', '30385', '18368', '17875', '28641', '7397', '19536', '29354', '22977', '11788', '19585',
      '30496', '23879', '4291', '31876', '32415', '8244', '23491', '44', '26031', '13547', '24550', '19690', '5116', '3182', '21030', '11218', '30286', '2142', '5534', '23443', '6290', '11518', '9607', '21122', '24526', '29487', '7994', '8335', '25647', '14964',
      '27699', '29004', '27390', '23279', '3083', '11757', '166', '22369', '32379', '16194', '12975', '12077', '19808', '28605', '27076', '20565', '14001', '28017', '25520', '10618', '30345', '27664', '19803', '23518', '12579', '26347', '31953', '3430', '31960', '758',
      '19259', '23183', '3106', '4288', '3812', '26751', '30618', '11901', '13620', '5879', '10237', '2560', '31926', '21079', '24610', '17080', '20244', '1444', '26372', '27576', '15129', '11390', '20925', '11701', '3758', '1320', '28040', '2301', '4317', '25219',
      '18878', '14212', '23503', '7699', '25048', '11996', '22225', '10743', '26482', '16950', '20554', '17139', '11334', '25700', '14277', '17001', '11308', '2523', '30700', '4187', '14111', '10920', '28810', '13674', '15161', '25729', '4233', '3289', '11957', '15542',
      '4080', '5770', '6636', '571', '18924', '26877', '16727', '20383', '14022', '17239', '28562', '11542', '1513', '16216', '24406', '21106', '22493', '9060', '17790', '2341', '6221', '21626', '31489', '11840', '30723', '26686', '18173', '21621', '1771', '22258',
      '18602', '1560', '28171', '19831', '354', '10009', '18832', '8017', '32414', '30474', '8900', '22687', '9210', '13087', '2575', '28709', '5424', '22568', '20732', '6470', '16407', '1176', '25653', '13825', '1709', '31359', '17797', '26874', '2313', '16786',
      '9685', '18291', '3943', '26913', '7983', '11086', '5152', '27167', '3773', '9484', '28077', '10526', '3785', '3536', '6314', '6224', '4285', '14683', '8656', '31109', '5924', '18447', '12281', '16434', '4006', '6384', '11808', '4967', '19726', '23454',
      '5469', '28630', '8519', '16988', '22251', '27091', '5978', '21515', '26149', '3919', '19825', '24110', '25220', '27097', '28374', '1768', '24994', '8360', '19955', '32503', '22841', '14987', '7763', '21441', '10531', '32756', '20126', '24903', '17754', '31990',
      '672', '25642', '32760', '9028', '11586', '11181', '29496', '3117', '19085', '27569', '2931', '23204', '14765', '11962', '12579', '15677', '14059', '26599', '4834', '4137', '30129', '9469', '3946', '7993', '23178', '24667', '16277', '2015', '21790', '29446',
      '8285', '15150', '23097', '9886', '23772', '8152', '32195', '26470', '14413', '21550', '11465', '5696', '6153', '4132', '1906', '31404', '11658', '10057', '23304', '21711', '16489', '10961', '15352', '3946', '6243', '11150', '16329', '4574', '1871', '7154',
      '22311', '12845', '4904', '21006', '18394', '18170', '16392', '10645', '18126', '22919', '31273', '17880', '12812', '30645', '8167', '29641', '27326', '9736', '11192', '11261', '20270', '29087', '32313', '13474', '21702', '8767', '18467', '25483', '16913', '3144',
      '5201', '45', '2231', '701', '29114', '17813', '16260', '26942', '15740', '1145', '15456', '26128', '3279', '25897', '20055', '13332', '14092', '18840', '6035', '5323', '32687', '20312', '1884', '25175', '24657', '29082', '29724', '16764', '29356', '19249',
      '21856', '29593', '31386', '30862', '7632', '18611', '4118', '6597', '13621', '12651', '26936', '29829', '4731', '28929', '17467', '13859', '30122', '28505', '29050', '21903', '16879', '10998', '32109', '5468', '30608', '19191', '31408', '9659', '19963', '20769',
      '27645', '26238', '28087', '27603', '20012', '18713', '19056', '26642', '16952', '21148', '7407', '17279', '22332', '15802', '32029', '24154', '29808', '15557', '7174', '19848', '25392', '23469', '7635', '19593', '30964', '520', '5070', '20351', '24920', '5380',
      '5729', '13614', '2070', '14708', '32534', '6390', '8966', '13772', '17048', '17625', '23587', '29724', '27311', '17275', '7048', '9239', '12359', '4636', '29037', '32014']
    var EncOutString = ['A2F95FD5FF9CDD84', '5650F5738D23002C', '5622030C647166F8', 'D0BAC2B4F6F7D3D1', '39E18CEBEE210ED5', '4AF224AE37F7A3C2', '0604B05F79414F81', 'F8EF5653DE89F603', 'D5E935D5099D8576', '83DFEF1492D332FE', '3E24956CE4CEBCB7', 'D1FE8781E9285209', '4FB8A3D5251D5480', '99E6D1374D7B8AD2', '055ADF527E0739AB', '31AD7B1ABA1B3F14', '5E7A2913723FE734', '044113168EB31F4E', 'DC16163F1CC5A5BF', '839405E81024B89B', 'D177A31156CA5CEC', '6C9880012D8FAC9F', '294B1B918CC5F58E', '2FC6E579F862226D', 'EDB542C47F4F2E4E', '021439F92A7AC01E', '3BF1BE16A04020C2', '59ABF876BC3656D4', '82AB244B64E6D365', 'F33BC8A1C7AC9650',
      '6DAAC377A44CBD84', '8B7C9B59682E71DE', '729F7A9896FDAD14', '8F608D24942B741B', '4997DBEBA6F86398', 'CADD0633F3246ABA', '382B38C681C47869', 'A07D7932E35AE2A2', '55B54211802E8F5C', 'B3BF75E21EE6289F', '10061D94156A0ABB', 'D0E67A3BC9A66E42', '71332BCF54FDFEAB', 'A9921CE9C0DF5FFC', '5D320DB31A64F888', '7541E31E0BA5D87A', '38332BC0FFB72AA1', '3ABA2F34FAE048C9', '67845FD6D236AB79', '608089834E8F1DB4', '60DB11815098CA9E', 'CCBCE7778C690F44', 'DC3F6EA293B48396', '3853424ED623174E', 'EB18209A7ECEE14C', '3040338AFEAB35A1', '15ED447D5FEA8023', '26E59AD58C8158EC', '12536AE207694392', '831F43FF1D23E6BD',
      'BE22E8A319E0D97D', '6ADAFC5E90EEB09A', '33337CD260F21BA3', '15CEC9BE662D1DFF', '226E529A26E2D490', '1D3F9FC043266A95', 'A1729A72B3DAEB9A', '962E7B769FE6AF4F', '7BB8833110624DA5', 'D03A767859ADAC84', '221DA484E35EA64E', '9A455ED7DD830D60', '04CFFB79F1F5F217', 'B6A4A5330DBBBF8B', '778CDDBB3495C349', 'BCD0554D6DCD5003', '4A279136397E14B2', '938F153FAE46FBA2', '910DD45276F8AB79', '0E9617F0A5137ADF', '6780233016CA9BA7', '7E987C223FEA5F17', '6AB377E3ABD6A2C6', '6080E0583F62AA90', '253ED111CF918632', '616E96D141FD82D6', '90238289E023475B', '1AA20F2CC09C7D55', 'D78D409D9ACEA6C0', '6ED8229B38A1497C',
      '0055915E7DE3F637', '36398C3F3DCA514E', '1F8E22558B1ACA18', 'CDFF9BDB317D09EC', '4A4D7830859FF6AD', '16CC789598D1C29A', '76E33070B490597D', 'F53272C1E152301C', 'B2C5E45114147F25', 'F993E5A697AC097C', '4E8E1072C3109863', '1ABACB2888B8FDFC', '1494929210C35DE9', 'C930DA24BA6321BA', '894E04C78DC63458', '52A3ACEE34A1E308', 'C4E3DA297868659D', 'EB286AF5D55E52A3', 'F7AE49B2E08BF607', 'B3B0725ACADC0208', '2C1CB56EB0830CC1', '0E45A849A81277AF', '6BC9ACFFD39C59DA', '9306376A454199D5', 'E2DFABFD2AC2F30C', 'C662676EFAA07310', 'ABAD31275D9D0534', '01D63EF616BF3D90', '09FFABE446371CD9', '9813B9F8F7C42ADB',
      '05E99BB67D889FF2', '8B8F13705EED5EFD', '716DF70D3A64D626', '0F2C7C01879B0F39', '89B87E8AC2B9F606', '7D4DF0A69A70F338', 'FDE69B744FC6D11D', '6C0AB0092EFF9275', 'FA7E83CF7FCCBB7F', '0E00363EB06E59A2', 'A2E85A59AB2B1B5A', '43F89714031A9344', '712DECAD70447B51', 'DC5A02C6E4A32138', '0E33B111E5B21D8C', 'CFD491F38520E2FD', 'E6F02EC70B4F43D1', '1708B28751A4A524', '2C51E6B431E29E4C', '2729FA970AA0CBFB', 'E62047ED9BC53655', '9FEA6BF68C8C77E6', '55C06C6E73F1728A', '7235B4B7F0333A78', '311DA9AD6653EDE7', 'AEB658349F6CDFAB', '0CF59ADA1EBC741B', 'A751E75DDCB6839F', '3CFEE9FEBFA407BA', '78812788613336D5',
      '32F4175CB3D66A67', '52C3DB153AEC9F35', '2742F9152323D00B', '675A7B3288FEF000', '4232E441AA002360', 'D1D7094594338A2E', 'C5973D11F7DFE133', '2B3A090F3BE80D42', '042131C91CDEE2AD', 'CD7C3679D00935FA', 'B52DE1F7A4C69B71', 'DCF97CBFAE898881', '23F090573C45D08B', '1E8526C2136D9BDA', 'E4669FB12E9B0CD6', '09DFFEF9858360DA', '051351BC791A1207', '28B611E220758E54', '8214F84C26B64167', '7BFC702C7FD90F98', '270E9E0AD879267C', 'FAB0661C4EA0FE48', '93DCCBC1317252E5', 'C1FCCA6A971110D1', 'B033BCE6426EE3C4', '5514DBBB628513D6', 'A9A15C0E3A5BF0E5', 'A0061585AC2DA462', '48109F366845855A', '1D4732C73758AA9F',
      'FACB3747FD1B52D9', '56452E90D416B7CA', '84390589B4719575', '7BF82275D0AF822C', '419238853F5144A8', 'C30ACFB7DD64499A', 'E9C1C56375895FED', '6A0406BB469EF10E', 'A7E0B18D62299329', '7E87EA82914FCE17', 'E1271B25627664DC', '2187DFA366E81B3E', '77CA7AEED61BC78D', 'CEAAF28C41DC74BE', '98365F30530FA7AB', '7F460948832C2D61', '2BBFC1784C251DBE', '2C999DC623C4CC5B', '04C4F65F4C9BA211', '94A215C1801FC13C', '280F3D642AEFA2D2', 'EEB5D7FCC51AD49B', 'A7A745D1B0FAE8C9', '4F01A1FB54C8BD19', 'EBB08D7F9C9BBC0C', 'C7B94E2F4693E82E', '246AA940ED9C2103', '50BE8A9153FEE0DA', '717B7044C5FD15C2', '2C87E0DECE535DE1',
      '097E8C52CBB78001', '91D15000A5827092', '3A87C9517E5693FF', 'E2EFA19D47925108', '69977262A868E158', '37AC81412D7AD188', '8CF1812E01CD8BBD', 'DF3A1104C6742061', 'DBF6EEC8E271F939', 'C1396403E30FC9E0', '5C2B2BA7F88A77DC', 'A1A23FC677C01044', '2EB901D7073574E3', '2CBBD46B9F7FD6A3', 'FB8DAB7F26D7B8D0', '0D182A50A6CAB6A1', '8D49B1ED64D0AB45', 'B8858970A85B404A', 'B2791061313636C7', '88F34C626F3F72FA', 'E86383D80FD27817', '71079ABF2B0E8552', '68531C3BC59ED129', 'D95BE5633F086566', 'B529A081908D5428', '5D6C3036F5851ACD', '56973CE87D5B9009', 'D85FEEDD7739F876', 'F3C9E9000915C7BC', 'FAC9D39B909DA733',
      '0C94F3BEA0B9B2D5', '44B180A7DA121607', '652E3BFADB64D2A5', '95B4821AE610F394', '68063AF43FDCEF83', 'B5F1749B13EA803D', '19219958BBA5EACB', '0FDDB2AF9CB0B1BB', 'CE58C30F00596724', '7DEA2D199BEABD03', '1C8BE02E3F6778B5', 'A5A9A4E5559BBAE7', '74010BBCDDB9F8D9', '48FFC0C810826576', '57F5914128AA2AE4', '5897A48F97CB8E8B', 'AFD1F2F3B9FA938E', 'AE74D37A0783C5E8', 'CBCF70CEC1EE6FB0', 'D091040BCE99EE75', '07FE26AB7EBA141C', '325E4C2F7F511F83', 'C0989B492AB1823E', 'E8C316F0933FD28C', '16F585A2298B154F', '575DF477C3FDD717', 'ED0328E1662B7064', '375759BCE0210495', 'F485BA276D60E118', '07A8B3BCC62991DF',
      'FA49229901DEF04F', '187AB18393F08683', 'A450884C8CA4484F', 'A4D7EAF7CB579095', '4ED79A091A5BFABD', '2FEF5C690894BB5A', '73E446FE7527C254', '107DC96AE4AE06A4', '4C4E5867E6562008', 'E6B1DF7736E8071B', '670B668269BA0686', 'ABCFA4F5A0D7EEBD', 'FC69C478C95B5F07', '843532341FA64E85', 'C10BA76B4C007FB1', '39E7788DFE072DB6', 'C1716CACDCEE6256', '1A291E0F94E5C6C4', '6916CFB4004E1F12', '090C18A65733975C', '6031412EE0B62416', '222D04CE7EB19DAD', 'B952B6302FCB6254', '0BF62D47CE91F241', '34FCC11B0484ADB9', '8E54349409FFA146', 'CD87E6FA8A263B9E', '1335DE3C0164B425', '7BD19AC3B07498E7', 'CECFE3D00C13538C',
      '433A8DAE400551B0', 'B52289E0AE82D9B1', 'AEF8D1D0007BAEB3', '85E8B7254D4D9451', 'FAD2369B7C5A8025', '0E798FDDF492B240', '8BB5BBBCC03E276A', 'E1354D16192C10BA', 'EF043671E18AF7C4', '2CB58F13F7AD4872', '992566F87D58408E', '9AD99666B5B107AB', '941135E0203EA14A', '44D0989BD46EC944', 'E2DFABFD2AC2F30C', '8ECCCEEAFC4454EF', '1AA823CB5479AB03', '5B74154A0FC9233F', 'CF3912879A83B003', '245E78F257713DBA', '15551B54E3846AF0', '10B6A170FB242A33', 'F4EA622714E044B6', '18BE5A40025BA644', 'FA0DD786B4A4FC07', '0B54809A397A1646', 'B6A02DDE87F13ABB', '3EBD426B29957294', '697DBB216BF797F4', '04E9EAD697876FE1',
      'E489573B5F2DC0B9', '4E9261A8901529E6', '2884D5C77FCFCC28', '175E07B1E60EF813', '441940FC22F1D9F2', '3E7D6BF2BD2AF8BD', 'A1D640D53E1F9972', 'C19F92CD4B5A1AB9', '7F93EB3632172AA2', '7F8B7A3949B1EDC0', '6AF4FB88D3462561', 'B3BF75E21EE6289F', 'BEB091B76C6FCBDC', '9B054644F6EDEADE', 'EC709F932E1EC040', '1FD9F772AD0A27C5', '646110C445774FAC', '2802A3A433A28AF2', 'FBB79EFCD80CA878', '4A4640A137A88DEE', '0B934831EE40718C', '41E5026532BBEBA5', '0470B7A174F909E1', 'F4EA622714E044B6', '73F03EE79795040B', '0F88A0C0FA0ACE00', '9A1E4676AEAD47CD', '2EEE0214EACC6C48', 'DC7D705167B66BE4', '70C73688F0356B61',
      'C443D5D279C3BDCE', '4D74D2516CE8197C', '2914D618D530C780', 'E771633B49093BF6', '07890488252E679F', '11DE6218981335CE', 'C0EA8240579EBD68', 'DFFB2AB3B7A38501', '16A3E8D60402B76C', 'AA49E102B36A69A1', '54457385A9618B2E', '0FDB728C58AF98FA', 'EF47AAE9D7A8450E', '8A1352A8785EC037', '0DFDE60C6FFFC1F4', 'CA4CF805C6505B2B', '08EB0696D3AC3F40', '127F1D7945487F2A', '1B7989C96446273C', 'AB896EC8058F524A', '41F8891297DD818B', 'CD69A0F659E2B882', '7A25A37133DA28BE', 'E68F635F6638CB2D', '1446807F9AA0C064', 'CB50C94B4DA7726C', '4743ADA548EFCF17', '86E3DE22C6FC8B33', '0D9CBB34AF440173', 'A8727F223A367323',
      '22D061908D655AA5', '377B898CD7C5952A', '5C576ED1C2CDE538', '99D969B6A07744AE', '8A374322AFA5E129', 'FBC8E453A05D1A9A', 'FD0286CA639A4FEA', 'D57B9D5BF0C96988', '0531572C6095B632', '21DFF69DA7675270', 'AA8172F451F6DA86', 'D2FFA12DA97B031B', 'CB32B671B9E925AA', 'DBEB12194EF4A102', 'DF9B1A88A6184F88', '5A5BD65644637E2C', 'A64CFC1B5E26A141', '4321826C5F2E8E8F', 'A33781208CB23930', '602646507E192419', '7968F94D45E5D586', '751996E062B3BDAD', 'FE43C340CBF01963', '453D1E5887894E21', '89C37A4CDF64664F', '1AACCA5C6EE25201', '1393D9A2740EEEB1', 'AC16682A63BFFCBB', 'C3568B11EF389510', '5A43BABDE70CC001',
      '68221BEC0CC87B26', 'C1D9B89C5734FA57', 'AC82FA0CF0E2C62B', '8674E6EDF78F431E', '2B1FE2EEB257FD53', '2B23A9198782A111', '0CA0905F48087BBC', 'C4D68BB93203DD63', 'E97067C3BE109DD2', '1FEAFCA0B6A410D6', '3128946238A3032C', '88D0CDA4033C3AC4', '73B3A04310596257', 'FE383C38B70D1C88', '48E214B7FB753225', '29BD5CA2B6640CAE', '5DE6676614361A79', '464F57D4A1F8AB9E', 'D4E1E8E7313E229C', 'EF5B37493AD32C93', 'D03EC7B008DB1CD8', '7DE4AF785F39CE21', 'F4C4DA0230E77103', '1349BEB853D4F6FC', '6F1934072576B647', 'FF4E58A343760C95', '4499BA33FB842ACB', '7601888D33FBF1DF', '3A85A6720469D690', '1DEDED58AD9D52D2',
      'CBC7A48284515D65', 'E1E440E731BEB867', 'F04DBB51009710DB', '3773AD7D80FD22D8', '59C6087ACB615FC3', '78631BABD5050446', '284E6923157F1719', '12149C8EEBE71B70', 'AF6282DEC0902CBE', 'CE4C0AC6C0136BD6', 'ECCF77086D076CA7', '08E11C6D2FD97710', '0ED0D0481ED246F2', 'E8717FF62EEBBFC1', '5F3D13BF25CF1592', '9010A4E33CB5CB16', '2FED659B37E5D7E7', '916BD14DD4AAEDE4', '42EF16B316345E0B', '45091BE6EA5721D5', 'B323BFEDB80DBC96', '7D7A291DCCCDF3DC', 'BBBDC6F5D2DD8BAD', '61FF7DD5EACD8669', 'A1A8C9BA56AA261E', '8BF077BDD63AF022', '2F43D013C130D781', '0409287D1EF94B63', 'FF7E439A0374E5E3', 'D12B49C7B7BBD8F2',
      'C28854779B016BDD', '46792DC5F501E0CA', 'A3F211E0D077A907', '079ABEF86E023B5F', '9C63C9A7124E9FA2', '33FCE00F3A5E50EE', '7B6CD959A830F8EF', '53BA3FD7E0C8DB70', 'E352D3310C83E8AC', 'E003BA1241AE3C93', 'F5D560ED2EA5AC91', '1393D9A2740EEEB1', 'C38F2A22311ABBEB', '2395148EC59398B7', '136DAD8B96233BBD', '002EE2D90223E7C4', '3460EAA03F84A3FE', 'A84F9F5C0D770CF3', '45A658EDF85CE021', '913C3331873DA79C']
    // @NoUseNewKeyEx return 1;//如果没有使用这个功能，直接返回1
    // @NoSupNewKeyEx  return 2;//如果没有使用这个功能，直接返回2

    var mEncInString = EncInString[myrnd]
    var mEncOutString = EncOutString[myrnd]
    for (n = 0; n < 255; n++) {
      var DevicePath = this.FindPort(n)// 用于储存加密锁的路径
      if (this.lasterror != 0) return this.lasterror

      var outString = this.EncString_New(mEncInString, DevicePath)
      if ((this.lasterror == 0) && (outString.toUpperCase() == mEncOutString.toUpperCase())) return 0
    }
    return -92
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

