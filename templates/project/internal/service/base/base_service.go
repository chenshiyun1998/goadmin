/**
 * Created by Wangwei on 2019-06-05 14:39.
 */

package base

import (
	"goprojects/pkg/DB"

	service "goprojects/internal/service/sys"

	"github.com/xormplus/xorm"
)

var (
	roleService     = service.RoleService{}
	employeeService = service.EmployeeService{}
)

func NewSession() *xorm.Session {
	return DB.Engine.NewSession()
}

// 模糊化字符串，常用于sql查询
func LikeStr(str string) string {
	if str == "" {
		return str
	}
	return "%" + str + "%"
}

func GetOffset(page, limit int) int {
	if limit < 0 {
		return 0
	}
	if page < 1 {
		return 0
	}
	return (page - 1) * limit
}
