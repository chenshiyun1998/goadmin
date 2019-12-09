package common

import (
	"goprojects/internal/model/dto"
	"goprojects/pkg/util/gojson"

	"github.com/gin-gonic/gin"
)

type Response struct {
	ErrCode int         `json:"errcode"`
	ErrMsg  string      `json:"errmsg"`
	Data    interface{} `json:"data"`
}

var jsonContentType = []string{"application/json; charset=utf-8"}

func ResponseWith(c *gin.Context, code int, msg string) {
	toJson(c, gin.H{"code": code, "msg": msg})
}

func ResponseError(c *gin.Context, msg string) {
	toJson(c, gin.H{"code": 500, "msg": msg})
}

func ResponseOk(c *gin.Context, data interface{}) {
	if v, ok := data.(dto.Pages); ok {
		toJson(c, gin.H{"code": 0, "total": v.Total, "data": v.Data})
	} else {
		toJson(c, gin.H{"code": 0, "data": data})
	}
}

//写入json对象
func toJson(c *gin.Context, data interface{}) {
	c.Status(200)
	writer := c.Writer
	header := writer.Header()
	if val := header["Content-Type"]; len(val) == 0 {
		header["Content-Type"] = jsonContentType
	}
	e := gojson.Json.NewEncoder(writer).Encode(data)
	if e != nil {
		panic(e)
	}
}
