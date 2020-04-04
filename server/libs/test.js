const SoftKey = require('./SoftKey')

const mSoftKey = new SoftKey()

module.exports = async () => {
  let lasterror
  const txt = mSoftKey.StrEnc('123', '6CB0737364C34BBBBC20AF4E97630DC2')
  
  lasterror = mSoftKey.GetLastError()
  if (lasterror === 0) {
    console.log(txt)
  }
}