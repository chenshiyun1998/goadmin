/**
 * Created by Wangwei on 2019-06-12 17:13.
 */

package v1

import (
	"goprojects/internal/model/sys"
	service "goprojects/internal/service/sys"

	"github.com/gin-gonic/gin"
)

var (
	orgTypeService = &service.OrgTypeService{}
)

type OrgTypeController struct {
	Router gin.IRouter
}

// 查找树形结构的机构类型数据
func (*OrgTypeController) FindByTree(c *gin.Context) {
	claims := GetEmployeeClaims(c)
	orgTypes, err := orgTypeService.FindByTree(claims.RoleId)
	if err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, orgTypes)
}

// 查找可供下拉框选择的机构类型数据
func (*OrgTypeController) FindBySelect(c *gin.Context) {
	claims := GetEmployeeClaims(c)
	orgTypes, err := orgTypeService.FindBySelect(claims.RoleId)
	if err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, orgTypes)
}

func (*OrgTypeController) Save(c *gin.Context) {
	orgType := sys.OrgType{}
	if err := BindJSON(c, &orgType); err != nil {
		ResponseErrorf(c, "请求的数据不合法: %s", err)
		return
	}

	if err := orgTypeService.Save(&orgType); err != nil {
		ResponseError(c, err)
		return
	}

	ResponseOK(c, "")
}

func (self *OrgTypeController) Setup() {
	self.Router.GET("/org_type/query_by_tree", self.FindByTree)
	self.Router.GET("/org_type/query_by_select", self.FindBySelect)
	self.Router.POST("/org_type/save", self.Save)
}
