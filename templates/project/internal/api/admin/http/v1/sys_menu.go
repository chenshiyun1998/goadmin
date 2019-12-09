package v1

import (
	"goprojects/internal/model/sys"
	service "goprojects/internal/service/sys"

	"github.com/gin-gonic/gin"
)

var (
	menuService = &service.SysMenuService{}
)

type SysMenuController struct {
	Router gin.IRouter
}

func (*SysMenuController) FindAll(c *gin.Context) {
	menus, err := menuService.FindAll()
	if err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, menus)
}

func (*SysMenuController) Save(c *gin.Context) {
	menu := new(sys.SysMenu)
	if err := BindJSON(c, menu); err != nil {
		ResponseErrorf(c, "请求的数据不合法: %s", err)
		return
	}

	if err := menuService.Save(menu); err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, "")
}

func (*SysMenuController) Delete(c *gin.Context) {
	menuId := GetInt64("menu_id", c)

	if err := roleMenuService.Delete(menuId); err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, "")
}

func (self *SysMenuController) Setup() {
	self.Router.GET("/sys_menu/query", self.FindAll)
	self.Router.POST("/sys_menu/save", self.Save)
	self.Router.GET("/sys_menu/delete", self.Delete)
}
