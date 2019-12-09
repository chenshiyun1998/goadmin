/**
 * Created by Wangwei on 2019-06-12 17:41.
 */

package sys

import (
	"errors"
	"fmt"
	"goprojects/internal/model/sys"
	"goprojects/pkg/DB"
)

type OrgTypeService struct{}

// 查找树形结构的机构类型数据
func (self *OrgTypeService) FindByTree(roleId int64) (orgTypes []*sys.OrgType, err error) {
	orgTypes = make([]*sys.OrgType, 0)

	// 如果是超级管理员角色，查询所有机构和下级机构
	if roleId == 1 {
		if err = DB.Where("parent_id = 0").FindRows(&orgTypes); err != nil {
			return nil, err
		}
	} else {
		// 如果不是超级管理员角色，则只查询当前角色所属的机构类型
		role := sys.Role{}
		if _, err = DB.FindById(roleId, &role); err != nil {
			return nil, err
		}

		if err = DB.Where("id = ?", role.OrgTypeId).FindRows(&orgTypes); err != nil {
			return nil, err
		}
	}

	// 查找所有下级机构
	for _, orgType := range orgTypes {
		if err = self.findChildrenTree(orgType); err != nil {
			return nil, err
		}
	}

	return orgTypes, err
}

// 查找可供下拉框选择的机构类型数据
func (self *OrgTypeService) FindBySelect(roleId int64) (orgTypes []*sys.OrgType, err error) {
	orgTypes = make([]*sys.OrgType, 0)

	// 如果是超级管理员角色，查询所有机构和下级机构
	if roleId == 1 {
		err = DB.Where("1=1").FindRows(&orgTypes)
		return orgTypes, err
	} else {
		// 如果不是超级管理员角色，则只查询当前角色所属的机构类型和下级机构类型
		role := sys.Role{}
		if _, err = DB.FindById(roleId, &role); err != nil {
			return nil, err
		}

		var ok bool
		orgType := sys.OrgType{}
		if ok, err = DB.Where("id = ?", role.OrgTypeId).FindOne(&orgType); err != nil {
			return nil, err
		}

		if !ok {
			return nil, fmt.Errorf("orgTypeId is invalid: %d", role.OrgTypeId)
		}

		childs, err := self.findChildrenSlice(&orgType)
		return childs, err
	}

	return orgTypes, err
}

// 递归调用，查询下级机构, 返回嵌套层级的结构数据
func (self *OrgTypeService) findChildrenTree(orgType *sys.OrgType) (err error) {
	children := make([]*sys.OrgType, 0)
	if err = DB.Where("parent_id = ?", orgType.Id).FindRows(&children); err != nil {
		return err
	}

	orgType.Children = children
	for _, orgtype := range orgType.Children {
		if err = self.findChildrenTree(orgtype); err != nil {
			return err
		}
	}

	return err
}

// 递归调用，查询下级机构, 返回数组结构数据，无层级嵌套关系
func (self *OrgTypeService) findChildrenSlice(orgType *sys.OrgType) (orgTypes []*sys.OrgType, err error) {
	orgTypes = make([]*sys.OrgType, 0)
	if err = DB.Where("parent_id = ?", orgType.Id).FindRows(&orgTypes); err != nil {
		return nil, err
	}

	results := make([]*sys.OrgType, 0)
	for _, orgtype := range orgTypes {
		results = append(results, orgtype)

		children, err := self.findChildrenSlice(orgtype)
		if err != nil {
			return nil, err
		}

		for _, item := range children {
			results = append(results, item)
		}
	}

	return results, err
}

func (self *OrgTypeService) GetByRoleId(roleId int64) (orgType *sys.OrgType, err error) {
	role := sys.Role{}
	if _, err = DB.FindById(roleId, &role); err != nil {
		return nil, err
	}

	var ok bool
	orgType = &sys.OrgType{}
	ok, err = DB.Where("id = ?", role.OrgTypeId).FindOne(orgType)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("无效的orgTypeId: %d", role.OrgTypeId)
	}

	return
}

func (*OrgTypeService) Get(id int64) (orgType *sys.OrgType, err error) {
	orgType = &sys.OrgType{}
	_, err = DB.FindById(id, orgType)
	return
}

// 保存
func (*OrgTypeService) Save(orgType *sys.OrgType) (err error) {
	newOrgType := sys.OrgType{}
	has, err := DB.Where("name=?", orgType.Name).FindOne(&newOrgType)
	if err != nil {
		return err
	}
	if has && orgType.Id != newOrgType.Id {
		return errors.New("机构类型已存在")
	}

	if orgType.Id == 0 {
		_, err = DB.InsertOne(orgType)
	} else {
		_, err = DB.UpdateById(orgType.Id, orgType)
	}
	return
}
