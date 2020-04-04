/*
 * File: index.js
 * Project: test2
 * File Created: Tuesday, 31st March 2020 5:17:02 pm
 * Author: KLEN (liangchuqiang@gosuncn.com)
 * Description: 基础工具库
 * -----
 * Last Modified: Tuesday, 31st March 2020 6:46:48 pm
 * Modified By: KLEN (liangchuqiang@gosuncn.com>)
 * -----
 * Copyright 2018 - 2020 广州高新兴机器人有限公司, 广州高新兴机器人有限公司
 * -----
 */

module.exports = {
  createUuid: function() {
    /**
     * bits 12-15 of the time_hi_and_version field to 0010
     */
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 0x10 | 0
      const v = c === 'x' ? r : (r & 0x3 | 0x8)
      return v.toString(0x10)
    })
  }
}
