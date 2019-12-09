/**
 * Created by Wangwei on 2019-06-06 10:33.
 */

package casbins

import (
	"fmt"
	"goprojects/internal/common/xormadapter"
	"goprojects/internal/conf"
	"goprojects/pkg/util/gopath"
	"time"

	"github.com/casbin/casbin"
)

//权限结构
type CasbinModel struct {
	Ptype  string
	Role   string
	Path   string
	Method string
}

var (
	confPath string
	enforcer *casbin.Enforcer
)

func init() {
	confPath = gopath.FindFilePath("configs/rbac_model.conf")
}

// 权限配置持久化
func NewEnforcer() *casbin.Enforcer {
	if enforcer == nil {
		dataSource := fmt.Sprintf("%s:%s@tcp(%s:%d)/", conf.CasbinConf.User, conf.CasbinConf.Pswd, conf.CasbinConf.Host, conf.CasbinConf.Port)
		a := xormadapter.NewAdapter("mysql", dataSource)

		enforcer = casbin.NewEnforcer(confPath, a)
		enforcer.LoadPolicy()
		WatcherPolicy()
	}

	return enforcer
}

//添加角色权限
func AddCasbin(cm *CasbinModel) (err error) {
	e := NewEnforcer()
	if err = e.LoadPolicy(); err != nil {
		return err
	}

	e.AddPolicy(cm.Role, cm.Path, cm.Method)
	return nil
}

// 删除角色的所有权限
func RemoveRolePolicy(role string) (err error) {
	e := NewEnforcer()
	if err = e.LoadPolicy(); err != nil {
		return err
	}

	filteredPolicy := e.GetFilteredPolicy(0, role)
	for _, rules := range filteredPolicy {
		for i := 0; i < len(rules)/3; i++ {
			subRules := rules[i*3 : i*3+3]
			e.RemovePolicy(subRules[0], subRules[1], subRules[2])
		}
	}

	return nil
}

// 每隔3分钟更新一次权限策略
func WatcherPolicy() {
	go func() {
		for {
			time.Sleep(time.Minute * 2)
			enforcer.LoadPolicy()
		}
	}()
}
