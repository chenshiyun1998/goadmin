import moment from 'moment'

let month = moment().format("MM")
let year = moment().format("YYYY")
let day = moment().format("DD")
let startSuffix = " 00:00:00"
let endSuffix = " 23:59:59"
// let ymd = YYYY + '-' + MM + '-' + DD
// let YYYY = "YYYY"
// let DD = "DD"
// let MM = "MM"
let ymd = "YYYY-MM-DD"
let ymdhms = "YYYY-MM-DD HH:mm:ss"
let ym = "YYYY-MM"

var DateUtils = {
  //获取当日的最后时间
  getTodayEnd() {
    return moment().format(ymd) + endSuffix
  },
  //获取当日的开始时间
  getTodayStart() {
    return moment().format(ymd) + startSuffix
  },
  //获取昨天的开始时间
  getYesterdayStart() {
    return moment().subtract(1, 'days').format(ymd) + startSuffix
  },
  //获取昨天的结束时间
  getYesterdayEnd() {
    return moment().subtract(1, 'days').format(ymd) + endSuffix
  },
  //获取本月第一天
  getThisMonthFirstDay() {
    return moment().startOf('month').format(ymd) + startSuffix
  },
  //上月第一天
  getLastMonthFirstDay() {
    return moment().subtract('months', 1).startOf('month').format(ymd) + startSuffix
  },
  //上月最后一天
  getLastMonthEndDay() {
    return moment().subtract('months', 1).endOf('month').format(ymd) + endSuffix
  },
  //本季度第一天
  getThisQuarterFirstDay() {
    return moment().startOf('quarter').format(ymd) + startSuffix
  },
  //上季度第一天
  getLastQuarterFirstDay() {
    return moment().subtract('months', 3).startOf('quarter').format(ymd) + startSuffix
  },
  //上季度最后一天
  getLastQuarterEndDay() {
    return moment().startOf('quarter').subtract('days', 1).format(ymd) + endSuffix
  },
  //获取半年前
  getHalfYearAgoDay() {
    return moment().subtract('months', 6).format(ymd) + startSuffix
  },
  //获取一年前
  getYearAgotDay() {
    return moment().subtract('months', 12).format(ymd) + startSuffix
  },
  //近一周
  getNearlyWeekStart() {
    return moment().subtract('days', 7).format(ymd) + startSuffix
  },
  //近一月
  getNearlyMonthStart() {
    return moment().subtract('days', 30).format(ymd) + startSuffix
  },
  //近三月
  getThreeMonthStart() {
    return moment().subtract('days', 90).format(ymd) + startSuffix
  },
  //获取以前日期
  getSubtractDayStart(day) {
    return moment().subtract('days', day).format(ymd) + startSuffix
  },
  //秒转停车时长天，小时，分钟
  secondToDate(msd) {
    var time = msd
    if (null != time && "" != time) {
      if (time >= 60 && time < 60 * 60) {
        time = parseInt(time / 60.0) + "分";
      } else if (time >= 60 * 60 && time < 60 * 60 * 24) {
        time = parseInt(time / 3600.0) + "小时" + parseInt((parseFloat(time / 3600.0) -parseInt(time / 3600.0)) * 60) + "分";
      } else if (time >= 60 * 60 * 24) {
        time = parseInt(time / 3600.0 / 24) + "天" + parseInt((parseFloat(time / 3600.0 / 24) -
          parseInt(time / 3600.0 / 24)) * 24) + "小时" + parseInt((parseFloat(time / 3600.0) -
            parseInt(time / 3600.0)) * 60) + "分";
      } else {
        time = "0";
      }
    }
    return time;
  }
}

export {
  DateUtils
}
