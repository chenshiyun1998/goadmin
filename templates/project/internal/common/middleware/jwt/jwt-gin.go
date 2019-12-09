/**
 * Created by Wangwei on 2019-06-06 12:04.
 */

package jwt

import (
	"goprojects/internal/common"
	"strings"

	"github.com/gin-gonic/gin"
)

var (
	jwt = &JWT{}
)

func jwtTokenAbort(c *gin.Context, msg string) {
	common.ResponseWith(c, 501, msg)
	c.Abort()
}

// 请求拦截器中间件，验证token，后台管理专用
func EmployeeJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if claims := getEmployeeClaims(c); claims != nil {
			c.Set("employeeClaims", claims)
			c.Next()
		}
	}
}

// 请求拦截器中间件，验证token，后台管理专用
func UserJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if claims := getUserClaims(c); claims != nil {
			c.Set("userClaims", claims)
			c.Next()
		}
	}
}

// 解析token中的信息
func getEmployeeClaims(c *gin.Context) *EmployeeClaims {
	clientId := c.Request.Header.Get("X-Client-Id")
	clientId = common.FormatClientId(clientId)
	if strings.TrimSpace(clientId) == "" {
		jwtTokenAbort(c, "client-id不能为空")
		return nil
	}

	authHeader := c.Request.Header.Get("X-Token")
	if authHeader == "" {
		jwtTokenAbort(c, "token不能为空")
		return nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		jwtTokenAbort(c, "token无效")
		return nil
	}

	claims, err := jwt.ParseEmployeeToken(parts[1])
	if err != nil {
		jwtTokenAbort(c, err.Error())
		return nil
	}

	return claims
}

// 解析token中的信息
func getUserClaims(c *gin.Context) *UserClaims {
	clientId := c.Request.Header.Get("X-Client-Id")
	clientId = common.FormatClientId(clientId)
	if strings.TrimSpace(clientId) == "" {
		jwtTokenAbort(c, "client-id不能为空")
		return nil
	}

	authHeader := c.Request.Header.Get("X-Token")
	if authHeader == "" {
		jwtTokenAbort(c, "token不能为空")
		return nil
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		jwtTokenAbort(c, "token无效")
		return nil
	}

	claims, err := jwt.ParseUserToken(parts[1])
	if err != nil {
		jwtTokenAbort(c, err.Error())
		return nil
	}

	return claims
}
