/**
 * Created by Wangwei on 2019-06-05 11:26.
 */

package v1

import (
	"${project}/internal/common/middleware/casbin"
	"${project}/internal/common/middleware/jwt"

	"github.com/gin-gonic/gin"
)

func InitRouter(r *gin.Engine) {
	router := r.Group("/v1/admin_api")
	SetupNoneAuthorized(router)

	router.Use(jwt.JWTAuth())
	router.Use(casbin.AuthCheckRole())
	SetupAuthorized(router)
}

// 不需要token认证的接口
func SetupNoneAuthorized(router gin.IRouter) {
	authController := AuthController{}
	router.POST("/login", authController.Login)
}

// 需要token认证的接口
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

    // 本次新生成的代码
	${SetupController}
}
