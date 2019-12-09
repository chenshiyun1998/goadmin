/**
 * Created by Wangwei on 2019-06-05 11:26.
 */

package v1

import (
	"goprojects/internal/common/middleware/jwt"

	"github.com/gin-gonic/gin"
)

// 初始化router，app是提供给iOS、Android调用的接口
func InitRouter(r *gin.Engine) {
	router := r.Group("/v1/app/api")
	SetupNoneAuthorized(router)

	// jwt token认证，app主要针对商家员工的token认证
	router.Use(jwt.EmployeeJWTAuth())
	SetupAuthorized(router)
}

// 不需要token认证的接口,比如登录、身份认证、获取accessToken的接口
func SetupNoneAuthorized(router gin.IRouter) {

}

// 需要accessToken身份认证的接口
func SetupAuthorized(router gin.IRouter) {

}
