package DB

import (
	"fmt"
	"goadmin/internal/conf"

	_ "github.com/go-sql-driver/mysql"
	"github.com/xormplus/xorm"
)

var (
	dataSource string
	Engine     *xorm.Engine
)

func Init() {
	dataSource = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=%s",
		conf.MySQLConf.User,
		conf.MySQLConf.Pswd,
		conf.MySQLConf.Host,
		conf.MySQLConf.Port,
		conf.MySQLConf.Dbname,
		conf.MySQLConf.Charset,
	)

	var err error
	if Engine, err = xorm.NewEngine("mysql", dataSource); err != nil {
		panic(err)
	}
	Engine.ShowSQL(true)
}
