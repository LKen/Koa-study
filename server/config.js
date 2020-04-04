const path = require('path')
const fs = require('fs')
const dir = path.join(process.cwd(), './config.json')
const conf = fs.readFileSync(dir, 'utf8')

module.exports = JSON.parse(conf)
