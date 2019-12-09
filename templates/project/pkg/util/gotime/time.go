package gotime

import (
	"fmt"
	"openapi/pkg/util/gostring"
	"strconv"
	"time"
)

const (
	dateFormatyyyyMMdd       = "20060102"
	dateFormat               = "2006-01-02"
	timeFormat               = "15:04:05"
	timeFormatHHmmss         = "150405"
	dateTimeFormat           = "2006-01-02 15:04:05"
	dateFormatyyyyMMddHHmmss = "20060102150405"
)

//获取今日开始时间和结束时间,例如: 2018-05-18 00:00:01, 2018-05-18 23:59:59
func GetTodayRangeTime() (time.Time, time.Time) {
	now := time.Now()
	nowStart := GetBeginDateTime(now)
	nowEnd := GetEndDateTime(now)

	return nowStart, nowEnd
}

//获取今日开始时间和结束时间,例如: 2018-05-18 00:00:01, 2018-05-18 23:59:59
func GetTodayRangeTimeStr() (string, string) {
	nowStart, nowEnd := GetTodayRangeTime()
	return DetailFormat(nowStart), DetailFormat(nowEnd)
}

//获取最近7日开始时间和结束时间,例如: 2018-05-11 00:00:01, 2018-05-17 23:59:59
func GetWeekRangeTime() (time.Time, time.Time) {
	now := time.Now()
	week := GetBeforeDate(now, 7)
	weekStart := GetBeginDateTime(week)
	weekEnd := GetEndDateTime(now)

	return weekStart, weekEnd
}

//获取最近7日开始时间和结束时间,例如: 2018-05-11 00:00:01, 2018-05-17 23:59:59
func GetWeekRangeTimeStr() (string, string) {
	weekStart, weekEnd := GetWeekRangeTime()
	return DetailFormat(weekStart), DetailFormat(weekEnd)
}

//获取上月开始时间和结束时间,例如: 2018-05-01 00:00:01, 2018-05-31 23:59:59
func GetLastMonthRangeTime() (time.Time, time.Time) {
	now := time.Now()

	lastMonthEndTime := time.Date(now.Year(), now.Month(), 1, 23, 59, 59, 0, time.Local).AddDate(0, 0, -1)
	lastMonthBeginTime := time.Date(now.Year(), now.Month()-1, 1, 0, 0, 0, 0, time.Local)
	return lastMonthBeginTime, lastMonthEndTime
}

//获取n个月前的开始时间 2018-05-01 00:00:01
func AddMonthBeginTime(month int) time.Time {
	now := time.Now().AddDate(0, month, 0)

	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
}

//获取今年上月开始时间和结束时间,例如: 2018-05-01 00:00:01, 2018-05-31 23:59:59
func GetMonthRangeTime() (time.Time, time.Time) {
	now := time.Now()
	smonth := GetSMonth(now)
	sday := GetSDays(now.Day())
	year := now.Year()
	firstOfMonth := GetBeginDateTimeByStr(fmt.Sprintf("%d-%s-01", year, smonth))
	endOfMonth := GetEndDateTimeByStr(fmt.Sprintf("%d-%s-%s", year, smonth, sday))

	return firstOfMonth, endOfMonth
}

//获取去年本月开始时间和结束时间,例如: 2018-05-01 00:00:01, 2018-05-31 23:59:59
func GetMonthOfLastYearRangeTime() (time.Time, time.Time) {
	date := time.Now().AddDate(-1, 0, 0)
	smonth := GetSMonth(date)
	sday := GetSDays(date.Day())
	year := date.Year()
	firstOfMonth := GetBeginDateTimeByStr(fmt.Sprintf("%d-%s-01", year, smonth))
	endOfMonth := GetEndDateTimeByStr(fmt.Sprintf("%d-%s-%s", year, smonth, sday))

	return firstOfMonth, endOfMonth
}

//获取今年指定季度开始时间和结束时间,例如1季度: 2018-01-01 00:00:01, 2018-03-31 23:59:59
func GetJdRangeTime(jd int) (time.Time, time.Time) {
	now := time.Now()
	year := now.Year()

	startMonth := (jd-1)*3 + 1
	endMonth := jd * 3

	sStartMonth := GetSMonth2(startMonth)
	sEndMonth := GetSMonth2(endMonth)
	endMonthDays := GetMonthDays(year, endMonth)
	sEndMonthDays := GetSDays(endMonthDays)
	start := GetBeginDateTimeByStr(fmt.Sprintf("%d-%s-01", year, sStartMonth))
	end := GetEndDateTimeByStr(fmt.Sprintf("%d-%s-%s", year, sEndMonth, sEndMonthDays))

	return start, end
}

//获取当前季度时间范围
func GetCurrentJdRangeTime() (time.Time, time.Time) {
	jd := GetCurrentJd()
	return GetJdRangeTime(jd)
}

//获取上一个季度时间范围
func GetLastJdRangeTime() (time.Time, time.Time) {
	jd := GetCurrentJd() - 1
	if jd == 0 {
		jd = 4
		return GetJdOfLastYearRangeTime(jd)
	}

	return GetJdRangeTime(jd)
}

//获取今年全年时间范围
func GetFullYearRangeTime() (time.Time, time.Time) {
	now := time.Now()
	year := now.Year()
	days := GetMonthDays(year, 12)
	sdays := GetSDays(days)
	start := GetBeginDateTimeByStr(fmt.Sprintf("%d-01-01", year))
	end := GetEndDateTimeByStr(fmt.Sprintf("%d-12-%s", year, sdays))

	return start, end
}

//获取去年全年时间范围
func GetLastFullYearRangeTime() (time.Time, time.Time) {
	now := time.Now().AddDate(-1, 0, 0)
	year := now.Year()
	days := GetMonthDays(year, 12)
	sdays := GetSDays(days)
	start := GetBeginDateTimeByStr(fmt.Sprintf("%d-01-01", year))
	end := GetEndDateTimeByStr(fmt.Sprintf("%d-12-%s", year, sdays))

	return start, end
}

//获取近半年时间范围
func GetHalfYearRangeTime() (time.Time, time.Time) {
	date := time.Now().AddDate(0, -6, 0)
	start := GetBeginDateTime(date)
	end := GetEndDateTime(time.Now())

	return start, end
}

//获取当前季度
func GetCurrentJd() int {
	now := time.Now()
	month := GetMonth(now)

	jd := 1
	if month >= 4 && month <= 6 {
		jd = 2
	} else if month >= 7 && month <= 9 {
		jd = 3
	} else if month >= 10 && month <= 12 {
		jd = 4
	}

	return jd
}

//获取去年季度时间
func GetJdOfLastYearRangeTime(jd int) (time.Time, time.Time) {
	date := time.Now().AddDate(-1, 0, 0)
	year := date.Year()

	startMonth := (jd-1)*3 + 1
	endMonth := jd * 3

	sStartMonth := GetSMonth2(startMonth)
	sEndMonth := GetSMonth2(endMonth)
	endMonthDays := GetMonthDays(year, endMonth)
	sEndMonthDays := GetSDays(endMonthDays)
	start := GetBeginDateTimeByStr(fmt.Sprintf("%d-%s-01", year, sStartMonth))
	end := GetEndDateTimeByStr(fmt.Sprintf("%d-%s-%s", year, sEndMonth, sEndMonthDays))

	return start, end
}

//获取某一天日期的开始时间，如: 2018-05-01 00:00:00
func GetBeginDateTime(begin time.Time) time.Time {
	time := time.Date(begin.Year(), begin.Month(), begin.Day(), 0, 0, 0, 0, time.Local)
	return time
}

//获取某一天日期的开始时间，如: 2018-05-01 00:00:00
func GetBeginDateTimeByStr(begin string) time.Time {
	date := ParseDate(begin)
	time := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.Local)
	return time
}

//获取某一天日期的结束时间，如: 2018-05-01 23:59:59
func GetEndDateTime(end time.Time) time.Time {
	time := time.Date(end.Year(), end.Month(), end.Day(), 23, 59, 59, 0, time.Local)
	return time
}

//获取某一天日期的结束时间，如: 2018-05-01 23:59:59
func GetEndDateTimeByStr(end string) time.Time {
	date := ParseDate(end)
	time := time.Date(date.Year(), date.Month(), date.Day(), 23, 59, 59, 0, time.Local)
	return time
}

//获取指定日期几天前的日期
func GetBeforeDate(date time.Time, day int) time.Time {
	end := date.AddDate(0, 0, -day)
	return end
}

//获取指定时间几分钟前的时间
func GetBeforeHours(date time.Time, hour int) time.Time {
	h, _ := time.ParseDuration("-" + strconv.Itoa(hour) + "h")
	end := date.Add(h)
	return end
}

//获取指定时间几分钟前的时间
func GetBeforeMinutes(date time.Time, minute int) time.Time {
	m, _ := time.ParseDuration("-" + strconv.Itoa(minute) + "m")
	end := date.Add(m)
	return end
}

//获取指定日期几天后的日期
func GetAfterDate(date time.Time, day int) time.Time {
	end := date.AddDate(0, 0, day)
	return end
}

//获取指定日期几月后的日期
func GetAfterMonth(date time.Time, month int) time.Time {
	end := date.AddDate(0, month, 0)
	return end
}

//获取指定时间几小时后的时间
func GetAfterHours(date time.Time, hours int) time.Time {
	h, _ := time.ParseDuration(strconv.Itoa(hours) + "h")
	end := date.Add(h)
	return end
}

//获取指定时间几分钟后的时间
func GetAfterMinutes(date time.Time, minute int) time.Time {
	m, _ := time.ParseDuration(strconv.Itoa(minute) + "m")
	end := date.Add(m)
	return end
}

//获取指定时间几秒钟后的时间
func GetAfterSeconds(date time.Time, seconds int) time.Time {
	s, _ := time.ParseDuration(strconv.Itoa(seconds) + "s")
	end := date.Add(s)
	return end
}

//将字符串日期转换为日期类型
func ParseDate(strDate string) time.Time {
	loc, _ := time.LoadLocation("Local") //重要：获取时区
	mytime, _ := time.ParseInLocation(dateFormat, strDate, loc)
	return mytime
}

//将日期类型转换为字符串类型
func DateFormat(date time.Time) string {
	return date.Format(dateFormat)
}

//日期-->yyyyMMdd
func DateFormatyyyyMMdd(date time.Time) string {
	return date.Format(dateFormatyyyyMMdd)
}

/**
日期-->yyyyMMddHHmmss
*/
func DateFormatyyyyMMddHHmmss(date time.Time) string {
	return date.Format(dateFormatyyyyMMddHHmmss)
}

/**
yyyyMMddHHmmss-->日期
*/
func ParseToDateFormatyyyyMMddHHmmss(strDate string) time.Time {
	loc, _ := time.LoadLocation("Local") //重要：获取时区
	mytime, _ := time.ParseInLocation(dateFormatyyyyMMddHHmmss, strDate, loc)
	return mytime
}

func SetCreatedAt(date time.Time) time.Time {
	return ParseToDate(DateTimeFormat(date))
}

func DateTimeFormat(date time.Time) string {
	return date.Format(dateTimeFormat)
}

/**
日期-->HHmmss
*/
func DateTimeFormatHHmmss(date time.Time) string {
	return date.Format(timeFormatHHmmss)
}

func ParseToDate(strDate string) time.Time {
	loc, _ := time.LoadLocation("Local") //重要：获取时区
	mytime, _ := time.ParseInLocation(dateTimeFormat, strDate, loc)
	return mytime
}

//获取指定日期所在的月份
func GetMonth(dt time.Time) int {
	smonth := dt.Month().String()
	month := GetMonthNum(smonth)
	return month
}

//获取指定日期所在的月份，如果是小于10的月份，显示为01,02.....09
func GetSMonth(dt time.Time) string {
	smth := dt.Month().String()
	month := GetMonthNum(smth)

	smonth := fmt.Sprintf("%d", month)
	if month < 10 {
		smonth = fmt.Sprintf("0%s", smonth)
	}
	return smonth
}

//获取指定数字月份的字符串月份，如果是小于10的月份，显示为01,02.....09
func GetSMonth2(month int) string {
	smonth := fmt.Sprintf("%d", month)
	if month < 10 {
		smonth = fmt.Sprintf("0%s", smonth)
	}
	return smonth
}

func GetSDays(days int) string {
	sDays := fmt.Sprintf("%d", days)
	if days < 10 {
		sDays = fmt.Sprintf("0%s", sDays)
	}
	return sDays
}

//获取2个时间相隔天数
func GetDiffDays(dtBegin time.Time, dtEnd time.Time) int {
	days := 0
	subHours := dtEnd.Sub(dtBegin).Hours()
	if subHours <= 0 {
		days = 0 //所以天数相差0天
	} else { //如果差值大于0  说玩家的天数相差的起码有一天之前上
		days = int(subHours / 24)
		if (int(subHours) % 24) > 0 {
			days = days + 1
		}
	}
	return days
}

//获取指定月份的天数
func GetMonthDays(year int, month int) int {
	days := 30
	if month != 2 {
		if month == 4 || month == 6 || month == 9 || month == 11 {
			days = 30

		} else {
			days = 31
		}
	} else {
		if ((year%4) == 0 && (year%100) != 0) || (year%400) == 0 {
			days = 29
		} else {
			days = 28
		}
	}
	return days
}

//获取指定日期所在月份的天数
func GetMonthDays2(dt time.Time) int {
	month := GetMonth(dt)
	days := GetMonthDays(dt.Year(), month)
	return days
}

//获取指定日期所在月份的天数
func GetMonthDays3(date string) int {
	beginDate := ParseDate(date)
	month := GetMonth(beginDate)
	days := GetMonthDays(beginDate.Year(), month)
	return days
}

//根据月份英文获取月份数字
func GetMonthNum(monthEn string) int {
	switch monthEn {
	case "January":
		return 1
	case "February":
		return 2
	case "March":
		return 3
	case "April":
		return 4
	case "May":
		return 5
	case "June":
		return 6
	case "July":
		return 7
	case "August":
		return 8
	case "September":
		return 9
	case "October":
		return 10
	case "November":
		return 11
	case "December":
		return 12
	}
	return 0
}

func Format(dt time.Time, layout string) string {
	return dt.Format(layout)
}

//把时间格式化为简单日期字符串，例如"2018-08-08"
func SimpleFormat(dt time.Time) string {
	return Format(dt, dateFormat)
}

//把时间格式化为详细日期字符串，例如"2018-08-08 08:08:08"
func DetailFormat(dt time.Time) string {
	return Format(dt, dateTimeFormat)
}

func DateAndTime(yyyyMMddHHmmss string) (string, string) {
	return gostring.Substr(yyyyMMddHHmmss, 0, 8), gostring.Substr(yyyyMMddHHmmss, 8, 6)
}
