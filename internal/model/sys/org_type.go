/**
 * Created by Wangwei on 2019-06-12 17:38.
 */

package sys

import (
	"goadmin/internal/DB"
	"time"

	"github.com/golang/glog"
)

type OrgType struct {
	Id        int64
	ParentId  int64
	Code      string     `xorm:"varchar(20)"` //机构编号
	Name      string     `xorm:"varchar(40)"` //机构名称
	Buildin   int        `xorm:"int(1) "`     //是否内建
	Children  []*OrgType `xorm:"-"`           //下级机构，不保存到数据库，用于查询
	CreatedAt time.Time  `xorm:"created"`     //创建时间
	UpdatedAt time.Time  `xorm:"updated"`
	DeletedAt time.Time  `xorm:"deleted"`
}

func (*OrgType) Init() {
	count, err := DB.Where("id = 1").Count(&OrgType{})
	if err != nil {
		glog.Fatalf("init orgType err: %v\n", err)
		panic(err)
	}

	if count > 0 {
		return
	}

	orgType := &OrgType{Id: 1, Name: "平台", Buildin: 1}
	DB.Insert(orgType)
}
