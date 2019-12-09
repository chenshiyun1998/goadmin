/**
 * Created by Wangwei on 2019-07-02 11:55.
 */

package main

import (
	"flag"
	"fmt"
	"goadmin/internal/DB"
	"goadmin/internal/conf"
	"goadmin/internal/model"
	"goadmin/util"
	"strings"
)

func main() {
	flag.Parse()

	// 如果输入-newProject参数，则生成项目源码
	projectName := strings.TrimSpace(*util.NewProject)
	if projectName != "" {
		conf.Init()
		DB.Init()
		model.Init()

		util.RunProgressBar("开始项目创建:", 200)
		util.CreateGoProject()
		util.CreateVueProject()
		util.RunProgressBar("项目创建成功:", 10)
	}

	// 如果输入-NewModule,且输入-projectName参数，则生成新增模块源码
	if *util.NewModule {
		if strings.TrimSpace(*util.ProjectName) == "" {
			fmt.Println("-projectName参数缺失")
			return
		}

		util.GenModuleCodes()
		util.RunProgressBar("模块代码生成成功!", 10)
	}
}
