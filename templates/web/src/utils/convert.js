
/**
 * 数据库各种状态的转换
 * @author guanzhongkai
 */
var Convert = {
  /**
   * @param {1 现金 2 微信 3 支付宝 4 网银 5 优免券} payType 
   */
  getPayType: function (payType) {
    switch (payType) {
      case 1: return '现金'
      case 2: return '微信'
      case 3: return '支付宝'
      case 4: return '网银'
      case 5: return '优惠券'
      default: return '未识别'
    }
  },
  /**
   * 
   */
  getPayStatus: function (payStatus) {
    switch (payStatus) {
      case 0: return '待支付'
      case 1: return '支付成功'
      case 2: return '支付失败'
      case 7: return '已退款'
      default: return '未识别'
    }
  },
  /**
   * 
   * @param {支付来源 1月卡 2场内预付 3岗亭缴费 4无牌车缴费 5无感支付} paySource 
   */
  getPaySource: function (paySource) {
    switch (paySource) {
      case 1: return '月卡'
      case 2: return '场内预付'
      case 3: return '岗亭缴费'
      case 4: return '无牌车缴费'
      case 5: return '无感支付'
      default: return '未识别'
    }
  },

  /**
   * 
   * @param {单位为分} cent
   * 转为元，保留两位小数 
   */
  getFormatMoney: function (cent) {
    if (parseInt(cent) == 0) {
      return '0.00'
    } else {
      var f = parseFloat(cent) / parseFloat(100)
      return f.toFixed(2)
    }
  },

  getPayStatusArray: function () {
    const array = [{
      value: '0',
      label: '待支付'
    }, {
      value: '1',
      label: '支付成功'
    }, {
      value: '2',
      label: '支付失败'
    }, {
      value: '7',
      label: '已退款'
    }
    ]
    return array
  },

  getPayTypeArray: function () {
    const array = [{
      value: '1',
      label: '现金'
    }, {
      value: '2',
      label: '微信'
    }, {
      value: '3',
      label: '支付宝'
    }, {
      value: '4',
      label: '网银'
    }, {
      value: '5',
      label: '优惠券'
    }
    ]
    return array
  },
  getPaySourceArray: function () {
    const array = [{
      value: '1',
      label: '月卡'
    }, {
      value: '2',
      label: '场内预付'
    }, {
      value: '3',
      label: '岗亭缴费'
    }, {
      value: '4',
      label: '无牌车缴费'
    }, {
      value: '5',
      label: '无感支付'
    }
    ]
    return array
  },

  getExportLimit: function () {
    return 50000
  }
}

export { Convert }

