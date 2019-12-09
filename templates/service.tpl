package base

import (
	"${project}/pkg/DB"
	"${project}/internal/model/base"
	"${project}/internal/model/dto"
	"${project}/internal/model/sys"

	"github.com/jinzhu/copier"
	${errors}
)

type ${modelName}Service struct{}

func (*${modelName}Service) Find(page, limit int, parentOrgId int64) (pages *dto.Pages, err error) {
	var total int64
	total, err = DB.Count(&base.${modelName}{})
	if err != nil {
		return nil, err
	}

	offset := GetOffset(page, limit)
	${lowerModelName}s := make([]*base.${modelName}, 0)
	if err = DB.Where("parent_org_id = ? ", parentOrgId).Limit(offset, limit).FindRows(&${lowerModelName}s); err != nil {
		return nil, err
	}

	pages = &dto.Pages{total, &${lowerModelName}s}
	return
}

func (*${modelName}Service) Get(id int64) (${lowerModelName} *base.${modelName}, err error) {
	${lowerModelName} = &base.${modelName}{}
	_, err = DB.FindById(id, ${lowerModelName})
	return
}

// 新增服务商
func (*${modelName}Service) Save(req *base.${modelName}Req) (err error) {
	${lowerModelName} := base.${modelName}{}
	copier.Copy(&${lowerModelName}, req)
	if req.Id > 0 {
		_, err = DB.UpdateById(${lowerModelName}.Id, &${lowerModelName})
		return
	}

	session := NewSession()
	defer session.Close()
	session.Begin()

	role, err := roleService.GetAdminRoleByOrgId(${lowerModelName}.OrgTypeId)
	if err != nil {
		return err
	}

	if _, err = DB.InsertOneTx(session, &${lowerModelName}); err != nil {
		return err
	}

	employee := sys.Employee{
		Name:      ${lowerModelName}.ContactName,
		Account:   req.Account,
		Password:  req.Password,
		RoleId:    role.Id,
		RoleName:  role.Name,
		OrgTypeId: role.OrgTypeId,
		OrgId:     ${lowerModelName}.Id,
		OrgName:   ${lowerModelName}.Name,
		Phone:     req.ServicePhone,
	}

	if err = employeeService.SaveTx(session, &employee); err != nil {
		session.Rollback()
		return err
	}

	session.Commit()
	return
}

func (*${modelName}Service) Delete(id int64) (err error) {

    ${deleteStatement}

	${lowerModelName} := new(base.${modelName})
	_, err = DB.DeleteById(id, ${lowerModelName})
	return
}