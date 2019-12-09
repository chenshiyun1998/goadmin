package sys

import (
	"errors"
	"fmt"
	"goprojects/internal/common/casbins"
	"goprojects/internal/model"
	"goprojects/internal/model/sys"
	"goprojects/pkg/DB"
	"strings"

	"github.com/gogf/gf/g/util/gconv"
)

var (
	SuperAdminRoutes = []string{"/sys/org_types", "/sys/roles", "/sys/menus", "/sys/role_menu", "/sys/employees", "/sys/employee_edit"}
)

type RoleMenuService struct{}

func (self *RoleMenuService) GetCountByPermsId(permsId string, roleId int64) (int, error) {
	var (
		count int
		err   error
	)

	sql := "select count(*) from role_menu rm inner join sys_menu m on rm.menu_id = m.id where m.perms_id = ? and rm.role_id=? and rm.checked=1 group by m.id"
	_, err = DB.SQL(sql, permsId, roleId).FindOne(&count)
	if err != nil {
		return count, err
	}

	return count, err
}

// 查询角色拥有的菜单路由地址，用于控制前端菜单显示或隐藏
func (self *RoleMenuService) FindRouteLinksByRole(roleId int64) (routeLinks []string, err error) {
	sysMenus3 := make([]*sys.SysMenu, 0)
	sql := "select sm.* from sys_menu sm where sm.id in (select m.parent_id from sys_menu m INNER JOIN role_menu rm on m.id = rm.menu_id where rm.role_id = ? and rm.checked = 1 and level='level3' group by m.parent_id)"
	if err = DB.Engine.SQL(sql, roleId).Find(&sysMenus3); err != nil {
		return routeLinks, err
	}

	sysMenus2 := make([]*sys.SysMenu, 0)
	sql = "select m.* from sys_menu m INNER JOIN role_menu rm on m.id = rm.menu_id where rm.role_id = ? and rm.checked = 1 and m.level='level2'"
	if err = DB.SQL(sql, roleId).FindRows(&sysMenus2); err != nil {
		return routeLinks, err
	}

	for _, item := range sysMenus3 {
		if strings.TrimSpace(item.RouteLink) != "" {
			routeLinks = append(routeLinks, item.RouteLink)
		}
	}

	for _, item := range sysMenus2 {
		if strings.TrimSpace(item.RouteLink) != "" {
			routeLinks = append(routeLinks, item.RouteLink)
		}
	}

	if roleId == 1 {
		newRouterLinks := make([]string, 0)
		newRouterLinks = append(newRouterLinks, SuperAdminRoutes...)
		for _, route := range routeLinks {
			isExists := false
			for _, item := range SuperAdminRoutes {
				if route == item {
					isExists = true
					break
				}
			}

			if !isExists {
				newRouterLinks = append(newRouterLinks, route)
			}
		}

		return newRouterLinks, err
	}

	return routeLinks, err
}

// 根据角色查询所在组织的菜单权限，拥有权限的则勾选，不拥有的取消勾选
func (self *RoleMenuService) FindMenusByRole(roleId int64) ([]*sys.SysMenu, error) {
	role := sys.Role{}
	ok, err := DB.FindById(roleId, &role)
	if !ok {
		return nil, errors.New("非法的角色ID")
	}

	if err != nil {
		return nil, err
	}

	level1Menus := make([]*sys.SysMenu, 0)
	sql := "SELECT * FROM `sys_menu` where deleted_at is null and level=? and instr(org_type_ids, ?) order by `index` asc"
	err = DB.SQL(sql, "level1", role.OrgTypeId).FindRows(&level1Menus)
	if err != nil {
		return nil, err
	}

	level2Menus := make([]*sys.SysMenu, 0)
	err = DB.SQL(sql, "level2", role.OrgTypeId).FindRows(&level2Menus)
	if err != nil {
		return nil, err
	}

	level3Menus := make([]*sys.SysMenu, 0)
	err = DB.SQL(sql, "level3", role.OrgTypeId).FindRows(&level3Menus)
	if err != nil {
		return nil, err
	}

	roleMenus := make([]*sys.RoleMenu, 0)
	err = DB.Where("role_id=? and checked=1", roleId).FindRows(&roleMenus)
	if err != nil {
		return nil, err
	}

	for _, level3Menu := range level3Menus {
		for _, roleMenu := range roleMenus {
			if roleMenu.MenuId == level3Menu.Id {
				level3Menu.Checked = roleMenu.Checked
				break
			}
		}
	}

	for _, level2Menu := range level2Menus {
		for _, roleMenu := range roleMenus {
			if roleMenu.MenuId == level2Menu.Id {
				level2Menu.Checked = roleMenu.Checked
				break
			}
		}
		level2Menu.Children = make([]*sys.SysMenu, 0)
		for _, level3Menu := range level3Menus {
			level3Menu.RoleId = roleId
			if level3Menu.ParentId == level2Menu.Id {
				level2Menu.Children = append(level2Menu.Children, level3Menu)
			}
		}
	}

	for _, level1Menu := range level1Menus {
		level1Menu.Children = make([]*sys.SysMenu, 0)
		for _, level2Menu := range level2Menus {
			if level2Menu.ParentId == level1Menu.Id {
				level1Menu.Children = append(level1Menu.Children, level2Menu)
			}
		}
	}

	return level1Menus, err
}

//保存
func (self *RoleMenuService) Save(roleMenuForm *sys.RoleMenuReq) error {
	var (
		err error
		ok  bool
	)

	session := NewSession()
	defer session.Close()
	session.Begin()

	// 因为有角色取消权限和新增权限
	// 先把角色的所有权限都设置为没有权限，然后重新分配权限
	sql := "update role_menu set checked=0 where role_id=?"
	if err = DB.ExecuteSqlTx(session, sql, roleMenuForm.RoleId); err != nil {
		return fmt.Errorf("修改role_menu checked状态报错: %s", err.Error())
	}

	roleMenus := make([]*sys.RoleMenu, 0)
	insertRoleMenus := make([]*sys.RoleMenu, 0)
	updateRoleMenus := make([]*sys.RoleMenu, 0)
	for _, menuId := range roleMenuForm.MenuIds {
		roleMenu := sys.RoleMenu{}
		if ok, err = DB.Where("menu_id=? and role_id=?", menuId, roleMenuForm.RoleId).FindOne(&roleMenu); err != nil {
			session.Rollback()
			return err
		}

		roleMenu.MenuId = menuId
		roleMenu.RoleId = roleMenuForm.RoleId
		roleMenu.Checked = 1

		if ok {
			updateRoleMenus = append(updateRoleMenus, &roleMenu)
		} else {
			insertRoleMenus = append(insertRoleMenus, &roleMenu)
		}

		roleMenus = append(roleMenus, &roleMenu)
	}

	// 新增角色权限
	if len(insertRoleMenus) > 0 {
		if _, err = DB.InsertOneTx(session, insertRoleMenus); err != nil {
			session.Rollback()
			return err
		}
	}

	// 修改角色权限
	if len(updateRoleMenus) > 0 {
		for _, m := range updateRoleMenus {
			if _, err = DB.UpdateByIdTx(session, m.Id, m); err != nil {
				session.Rollback()
				return err
			}
		}
	}

	var roleId int64
	apiUrls := make([]*sys.ApiUrl, 0)
	for _, roleMenu := range roleMenus {
		menu := sys.SysMenu{}
		ok, err := DB.FindById(roleMenu.MenuId, &menu)
		if !ok {
			session.Rollback()
			return fmt.Errorf("menu id: %d is not exists", roleMenu.MenuId)
		}

		if err != nil {
			session.Rollback()
			return err
		}

		if menu.NodeType != "permission" {
			continue
		}

		roleId = roleMenu.RoleId
		for _, apiUrl := range menu.ApiUrls {
			apiUrls = append(apiUrls, apiUrl)
		}
	}

	// 超级管理员初始权限
	if roleId == 1 {
		if err = model.UpdateSuperAdminPermsission(session, apiUrls); err != nil {
			session.Rollback()
			return err
		}

		session.Commit()
		return nil
	}

	// 非超级管理员角色，先删除角色所有权限，然后重新将角色权限持久化到casbin
	casbins.RemoveRolePolicy(gconv.String(roleId))
	for _, apiUrl := range apiUrls {
		casbin := casbins.CasbinModel{
			Ptype:  "p",
			Role:   gconv.String(roleId),
			Path:   apiUrl.ApiUrl,
			Method: "*",
		}

		if err = casbins.AddCasbin(&casbin); err != nil {
			session.Rollback()
			return err
		}
	}

	session.Commit()
	return nil
}
