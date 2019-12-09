/**
 * Created by Wangwei on 2019-05-30 18:10.
 */

package conf

import (
	"flag"
	"fmt"
	"goadmin/pkg/util/gopath"

	"github.com/gogf/gf/g/os/glog"

	"github.com/BurntSushi/toml"
)

var (
	confPath   string
	AppConf    = AppConfig{}
	MySQLConf  = MySQLConfig{}
	CasbinConf = MySQLConfig{}
)

func init() {
	flag.StringVar(&confPath, "conf", "", "config path")
}

// Init conf.
func Init() {
	if confPath == "" {
		confPath = gopath.FindParentPath("configs", "mysql.toml")
	}

	mysqlPath := fmt.Sprintf("%s/mysql.toml", confPath)
	tomlDecodeFile(mysqlPath, &MySQLConf)

	casbinPath := fmt.Sprintf("%s/casbin.toml", confPath)
	tomlDecodeFile(casbinPath, &CasbinConf)
}

func tomlDecodeFile(fpath string, v interface{}) {
	_, err := toml.DecodeFile(fpath, v)
	if err != nil {
		glog.Fatalf("err: %v\n", err)
		panic(err)
	}
}
