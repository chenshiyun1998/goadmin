/**
 * Created by Wangwei on 2019-06-06 10:48.
 */

package casbin

import (
	"goprojects/internal/common"
	"goprojects/internal/common/casbins"
	"goprojects/internal/common/middleware/jwt"
	"net/http"

	"github.com/gogf/gf/g/util/gconv"

	"github.com/gin-gonic/gin"
)

func jwtTokenAbort(c *gin.Context, code int, msg string) {
	common.ResponseWith(c, code, msg)
	c.Abort()
}

//权限检查中间件
func AuthCheckRole() gin.HandlerFunc {
	return func(c *gin.Context) {
		//根据上下文获取载荷claims 从claims获得role
		claims := c.MustGet("employeeClaims").(*jwt.EmployeeClaims)
		e := casbins.NewEnforcer()
		//检查权限
		res, err := e.EnforceSafe(gconv.String(claims.RoleId), c.Request.URL.Path, c.Request.Method)
		if err != nil {
			jwtTokenAbort(c, http.StatusInternalServerError, err.Error())
			return
		}

		if !res {
			jwtTokenAbort(c, 500, "很抱歉您没有此权限")
			return
		}

		c.Next()
	}
}
