/**
 * Created by Wangwei on 2019-07-02 16:35.
 */

package util

import (
	"fmt"
	"goadmin/pkg/util/gojson"
	"io/ioutil"
	"os"
	"strings"
)

func ReadJSON(filename string, v interface{}) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("read json file err: %s\n", err)
		return
	}

	if err = gojson.Unmarshal(data, v); err != nil {
		fmt.Printf("Unmarshal json err: %s\n", err)
		return
	}
}

// 读取模板文件中内容
func ReadTemplate(filename string) (content string) {
	var err error
	text, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("readTemplate err: %s\n", err)
		return
	}

	return string(text)
}

// 生成文件代码
func GenCodeFile(fileName string, content string) {
	fileName = strings.Replace(fileName, "\\", "/", -1)

	paths := strings.Split(fileName, "/")
	paths = paths[0 : len(paths)-1]
	filepath := strings.Join(paths, "/")

	if err := os.MkdirAll(filepath, os.ModePerm); err != nil {
		fmt.Printf("MkdirAll filepath err: %s\n", err)
		return
	}

	f, err := os.Create(fileName)
	defer f.Close()

	if _, err = f.Write([]byte(content)); err != nil {
		fmt.Printf("write file err: %s, content: %s\n", err, content)
	}
}

func TypeConvert(goType string) string {
	switch goType {
	case "int64":
		return "bigint"
	case "int":
		return "int"
	case "string":
		return "varchar"
	}

	return "varchar"
}
