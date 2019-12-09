package sys

import "time"

type SysMenu struct {
	Id         int64
	ParentId   int64     `xorm:"comment('上级节点id')"`
	Name       string    `xorm:"varchar(20) comment('节点名称')"`
	NodeType   string    `xorm:"varchar(10) comment('节点类型: menu, permission')"`
	RouteLink  string    `xorm:"varchar(200) comment('前端页面路由')"`
	ApiUrls    []*ApiUrl `xorm:"comment('api地址，可填写多个')"`
	OrgTypeIds []int64   `xorm:"comment('节点所属机构类型，可多选')"`
	Level      string    `xorm:"varchar(20) comment('节点级别')"`
	Index      int
	Children   []*SysMenu `xorm:"-"` //不创建表字段，仅填充使用
	RoleId     int64      `xorm:"-"` //不创建表字段，仅填充使用
	Checked    int        `xorm:"-"` //不创建表字段，仅填充使用
	CreatedAt  time.Time  `xorm:"created"`
	UpdatedAt  time.Time  `xorm:"updated"`
	DeletedAt  time.Time  `json:"-" xorm:"deleted"`
}

type ApiUrl struct {
	ApiUrl string
}
