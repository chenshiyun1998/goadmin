package DB

import (
	"fmt"
	"goprojects/pkg/util/gopath"

	_ "github.com/go-sql-driver/mysql"
	"github.com/xormplus/xorm"
)

var (
	dataSource string
	Engine     *xorm.Engine
)

func Init(mysqlConf *MySQLConfig) {
	dataSource = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s",
		mysqlConf.User,
		mysqlConf.Pswd,
		mysqlConf.Host,
		mysqlConf.Port,
		mysqlConf.Dbname,
		mysqlConf.Charset,
	)

	var err error
	if Engine, err = xorm.NewEngine("mysql", dataSource); err != nil {
		panic(err)
	}
	Engine.ShowSQL(true)

	filePath := gopath.FindFilePath("sqlmap")
	if err = Engine.RegisterSqlTemplate(xorm.Pongo2(filePath, ".stpl")); err != nil {
		panic(err)
	}
}
