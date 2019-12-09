/**
 * Created by Wangwei on 2019-07-04 15:18.
 */

package util

import (
	"fmt"
	"goadmin/internal/conf"
	"strings"

	"github.com/gogf/gf/g/util/gconv"
)

var (
	MySQLPath  = "../output/%s/configs/mysql.toml"
	CasbinPath = "../output/%s/configs/casbin.toml"
)

// 生成数据库配置文件
func genMySQLConfig() {
	if strings.TrimSpace(*NewProject) == "" {
		return
	}

	content := ReadTemplate("../templates/mysql.toml.tpl")

	port := gconv.String(conf.MySQLConf.Port)

	content = strings.Replace(content, "${host}", conf.MySQLConf.Host, -1)
	content = strings.Replace(content, "${port}", port, -1)
	content = strings.Replace(content, "${user}", conf.MySQLConf.User, -1)
	content = strings.Replace(content, "${pswd}", conf.MySQLConf.Pswd, -1)
	content = strings.Replace(content, "${dbname}", conf.MySQLConf.Dbname, -1)
	content = strings.Replace(content, "${charset}", conf.MySQLConf.Charset, -1)

	fileName := fmt.Sprintf(MySQLPath, getGoProjectName())
	GenCodeFile(fileName, content)
}

func genCasbinConfig() {
	if strings.TrimSpace(*NewProject) == "" {
		return
	}

	content := ReadTemplate("../templates/casbin.toml.tpl")

	port := gconv.String(conf.CasbinConf.Port)

	content = strings.Replace(content, "${host}", conf.CasbinConf.Host, -1)
	content = strings.Replace(content, "${port}", port, -1)
	content = strings.Replace(content, "${user}", conf.CasbinConf.User, -1)
	content = strings.Replace(content, "${pswd}", conf.CasbinConf.Pswd, -1)
	content = strings.Replace(content, "${charset}", conf.CasbinConf.Charset, -1)

	fileName := fmt.Sprintf(CasbinPath, getGoProjectName())
	GenCodeFile(fileName, content)
}
