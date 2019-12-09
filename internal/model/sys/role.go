package sys

import (
	"goadmin/internal/DB"
	"time"

	"github.com/golang/glog"
)

type Role struct {
	Id          int64
	Code        string    `xorm:"varchar(20) comment('角色编码')"`
	Name        string    `xorm:"varchar(40) comment('角色名称')"`
	OrgTypeId   int64     `xorm:"comment('机构类型id')"`
	OrgTypeName string    `xorm:"varchar(40) comment('组织类型名称')"`
	Buildin     int       `xorm:"int(1) comment('内建')"`
	IsAdmin     int       `xorm:"comment('是否管理员角色')"`
	CreateById  int64     `xorm:"comment('创建人employee ID')"`
	CreateBy    string    `xorm:"varchar(40) comment('创建人姓名')"`
	CreatedAt   time.Time `xorm:"created"` //创建时间
	UpdatedAt   time.Time `xorm:"updated"`
	DeletedAt   time.Time `xorm:"deleted"`
}

func (self *Role) Init() {
	count, err := DB.Where("id = 1").Count(&Role{})
	if err != nil {
		glog.Fatalf("init superadmin role err: %v\n", err)
		panic(err)
	}

	if count > 0 {
		return
	}

	role := &Role{Id: 1, Code: "1001", IsAdmin: 1, Name: "超级管理员", Buildin: 1}
	DB.Insert(role)
}
