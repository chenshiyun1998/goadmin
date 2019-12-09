package sys

import (
	"time"
)

type RoleMenu struct {
	Id        int64
	RoleId    int64
	MenuId    int64
	Checked   int
	CreatedAt time.Time `xorm:"created"`
	UpdatedAt time.Time `xorm:"updated"`
}

type RoleMenuReq struct {
	RoleId  int64
	MenuIds []int64
}
