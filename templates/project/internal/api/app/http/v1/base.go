package v1

import (
	"fmt"
	"goprojects/internal/common/middleware/jwt"
	"goprojects/internal/model/dto"
	"goprojects/pkg/util/gojson"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gogf/gf/g/os/glog"
	"github.com/gogf/gf/g/util/gconv"
)

func ResponseError(c *gin.Context, err interface{}) {
	toJson(c, gin.H{"code": 500, "msg": err})
	c.Abort()
}

func ResponseErrorf(c *gin.Context, format string, err interface{}) {
	toJson(c, gin.H{"code": 500, "msg": fmt.Sprintf(format, err)})
	c.Abort()
}

func ResponseOK(c *gin.Context, data interface{}) {
	if v, ok := data.(*dto.Pages); ok {
		toJson(c, gin.H{"code": 0, "total": v.Total, "data": v.Data})
	} else if v, ok := data.(dto.Pages); ok {
		toJson(c, gin.H{"code": 0, "total": v.Total, "data": v.Data})
	} else {
		toJson(c, gin.H{"code": 0, "data": data})
	}
	c.Abort()
}

//JSON字符反序列化为实例
func BindJSON(c *gin.Context, v interface{}) error {
	decoder := gojson.Json.NewDecoder(c.Request.Body)
	if e := decoder.Decode(v); e != nil {
		return e
	}
	return nil
}

var jsonContentType = []string{"application/json; charset=utf-8"}

//写入json对象
func toJson(c *gin.Context, data interface{}) {
	c.Status(200)
	writer := c.Writer
	header := writer.Header()
	if val := header["Content-Type"]; len(val) == 0 {
		header["Content-Type"] = jsonContentType
	}

	err := gojson.Json.NewEncoder(writer).Encode(data)
	if err != nil {
		glog.Error(err.Error())
		panic(err)
	}
}

func GetId(c *gin.Context) int64 {
	return GetInt64("id", c)
}

//获取分页参数
func GetPageParams(c *gin.Context) (int, int) {
	pageStr := c.Query("page")
	limitStr := c.Query("limit")
	var page, limit int
	if pageStr != "" && limitStr != "" {
		page = gconv.Int(pageStr)
		limit = gconv.Int(limitStr)
	}
	return page, limit
}

//获取时间区间参数
func GetTimeParams(c *gin.Context) (string, string) {
	beginTime := c.Query("begin_time")
	endTime := c.Query("end_time")
	return beginTime, endTime
}

/**
@guanzhognkai
获取日期区间参数yyyy-MM-dd
*/
func GetDateParams(c *gin.Context) (string, string) {
	beginDate := c.Query("begin_date")
	endDate := c.Query("end_date")
	return beginDate, endDate
}

func GetString(key string, c *gin.Context) string {
	str := c.Query(key)
	if strings.TrimSpace(str) == "" {
		errText := fmt.Sprintf("%s is empty", key)
		panic(errText)
	}
	return str
}

func GetInt64(key string, c *gin.Context) int64 {
	str := c.Query(key)
	if strings.TrimSpace(str) == "" {
		return 0
	}

	value, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		errText := fmt.Sprintf("%s is not a number", key)
		panic(errText)
	}

	return value
}

func Get(key string, c *gin.Context) string {
	str := c.Query(key)
	return str
}

func GetInt(key string, c *gin.Context) int {
	str := c.Query(key)
	if strings.TrimSpace(str) == "" {
		errText := fmt.Sprintf("%s is empty", key)
		panic(errText)
	}

	value, err := strconv.Atoi(str)
	if err != nil {
		errText := fmt.Sprintf("%s is not a number", key)
		panic(errText)
	}

	return value
}

func GetEmployeeClaims(c *gin.Context) (claims *jwt.EmployeeClaims) {
	claims = c.Keys["employeeClaims"].(*jwt.EmployeeClaims)
	return
}
