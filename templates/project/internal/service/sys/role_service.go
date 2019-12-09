package sys

import (
	"errors"
	"fmt"
	"goprojects/internal/model/dto"
	"goprojects/internal/model/sys"
	"goprojects/pkg/DB"
)

type RoleService struct{}

func (*RoleService) Find(roleId int64, page, limit int) (pages *dto.Pages, err error) {
	query := map[string]interface{}{
		"offset": GetOffset(page, limit),
		"limit":  limit,
	}

	if roleId > 1 {
		role := sys.Role{}
		if _, err = DB.FindById(roleId, &role); err != nil {
			return nil, err
		}

		query["org_type_id"] = role.OrgTypeId
	} else {
		query["is_admin"] = 1
	}

	var total int64
	roles := make([]*sys.Role, 0)
	err = DB.PageBySqlTemplateClient("select_role.stpl", &query, &roles, "select_role_total.stpl", &total)
	if err != nil {
		return nil, err
	}

	pages = &dto.Pages{total, roles}
	return
}

func (*RoleService) Get(id int64) (role *sys.Role, err error) {
	role = &sys.Role{}
	_, err = DB.FindById(id, role)
	return
}

func (*RoleService) GetAdminRoleByOrgId(orgId int64) (role *sys.Role, err error) {
	role = &sys.Role{}
	ok, err := DB.Where("org_type_id = ? and is_admin = 1", orgId).FindOne(role)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("org_type_id: %d is not exists!", orgId)
	}
	return
}

// 保存
func (*RoleService) Save(role *sys.Role) (err error) {
	if role.Id == 0 {
		_, err = DB.InsertOne(role)
	} else {
		_, err = DB.UpdateById(role.Id, role)
	}
	return
}

func (*RoleService) Delete(id int64) error {
	role := new(sys.Role)
	count, err := DB.Where("role_id = ?", id).Count(sys.Employee{})
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("请先删除该角色下的用户")
	}

	_, err = DB.DeleteById(id, role)
	return err
}
