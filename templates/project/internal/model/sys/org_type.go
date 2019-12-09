/**
 * Created by Wangwei on 2019-06-12 17:38.
 */

package sys

import (
	"time"
)

type OrgType struct {
	Id        int64
	ParentId  int64
	Code      string     `xorm:"varchar(20)"` //组织编号
	Name      string     `xorm:"varchar(40)"` //组织名称
	Buildin   int        `xorm:"int(1) "`     //是否内建
	Children  []*OrgType `xorm:"-"`           //下级机构，不保存到数据库，用于查询
	CreatedAt time.Time  `xorm:"created"`     //创建时间
	UpdatedAt time.Time  `xorm:"updated"`
	DeletedAt time.Time  `xorm:"deleted"`
}
