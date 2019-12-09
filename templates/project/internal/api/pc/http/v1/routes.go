/**
 * Created by Wangwei on 2019-06-05 11:26.
 */

package v1

import (
	"goprojects/internal/common/middleware/jwt"

	"github.com/gin-gonic/gin"
)

// 初始化router，pc是提供给客户端软件的接口，比如提供给windows桌面安装程序调用的接口
func InitRouter(r *gin.Engine) {
	router := r.Group("/v1/pc/api")
	SetupNoneAuthorized(router)

	// jwt token认证，pc主要针对商家员工的token认证
	router.Use(jwt.EmployeeJWTAuth())
	SetupAuthorized(router)
}

// 不需要token认证的接口,比如登录、身份认证、获取accessToken的接口
func SetupNoneAuthorized(router gin.IRouter) {

}

// 需要accessToken身份认证的接口
func SetupAuthorized(router gin.IRouter) {

}
