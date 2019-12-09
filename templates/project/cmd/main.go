package main

import (
	"context"
	"flag"
	"goprojects/internal/conf"
	"goprojects/internal/model"
	"goprojects/internal/server/http"
	"goprojects/pkg/DB"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gogf/gf/g/os/glog"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	flag.Parse()

	// configs init
	conf.Init()
	// db start
	DB.Init(&conf.MySQLConf)
	// create tables
	model.Init()

	// start http server
	srv := http.New(gin.New())

	// 以下代码用于平滑重启，重启时，旧的请求不会中断，新的请求会被新启动的程序接管
	// 注意重启不要使用kill -9 pid,否则无法捕获到信号，请使用kill -2 pid
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-quit
	glog.Println("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		glog.Fatal("Server Shutdown: ", err)
	}
}
