/**
 * Created by Wangwei on 2019-06-05 11:26.
 */

package v1

import (
	"goprojects/internal/common/middleware/casbin"
	"goprojects/internal/common/middleware/jwt"

	"github.com/gin-gonic/gin"
)

// 初始化router，admin是提供给后台管理web浏览器端调用的接口
func InitRouter(r *gin.Engine) {
	router := r.Group("/v1/admin/api")
	SetupNoneAuthorized(router)

	// jwt token认证，admin主要针对商家员工的token认证
	router.Use(jwt.EmployeeJWTAuth())
	router.Use(casbin.AuthCheckRole())
	SetupAuthorized(router)
}

// 不需要token认证的接口,比如登录、身份认证、获取accessToken的接口
func SetupNoneAuthorized(router gin.IRouter) {
	authController := AuthController{}
	router.POST("/login", authController.Login)
}

// 需要accessToken身份认证的接口
func SetupAuthorized(router gin.IRouter) {
	orgTypeController := OrgTypeController{router}
	orgTypeController.Setup()

	roleController := RoleController{router}
	roleController.Setup()

	roleMenuController := RoleMenuController{router}
	roleMenuController.Setup()

	sysMenuController := SysMenuController{router}
	sysMenuController.Setup()

	employeeController := EmployeeController{router}
	employeeController.Setup()
}
