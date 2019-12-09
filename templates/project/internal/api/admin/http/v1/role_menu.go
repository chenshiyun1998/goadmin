package v1

import (
	"goprojects/internal/model/sys"
	service "goprojects/internal/service/sys"

	"github.com/gin-gonic/gin"
)

var (
	roleMenuService = &service.RoleMenuService{}
)

type RoleMenuController struct {
	Router gin.IRouter
}

func (self *RoleMenuController) FindAll(c *gin.Context) {
	roleId := GetInt64("role_id", c)

	roleMenus, err := roleMenuService.FindMenusByRole(roleId)
	if err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, roleMenus)
}

func (self *RoleMenuController) FindRouteLinksByRole(c *gin.Context) {
	roleId := GetInt64("role_id", c)

	routeLinks, err := roleMenuService.FindRouteLinksByRole(roleId)
	if err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, routeLinks)
}

func (self *RoleMenuController) Save(c *gin.Context) {
	roleMenuReq := sys.RoleMenuReq{}
	if err := BindJSON(c, &roleMenuReq); err != nil {
		ResponseErrorf(c, "请求的数据不合法: %s", err)
		return
	}

	if err := roleMenuService.Save(&roleMenuReq); err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, "")
}

func (self *RoleMenuController) Setup() {
	self.Router.GET("/role_menu/query", self.FindAll)
	self.Router.GET("/role_menu/route_links", self.FindRouteLinksByRole)
	self.Router.POST("/role_menu/save", self.Save)
}
