/**
 * Created by Wangwei on 2019-03-20 09:21.
 * 该json库为滴滴打车公司开源项目，这里做了工具封装
 * 官网：http://jsoniter.com/index.cn.html
 * 请务必所有json序列化和反序列化都使用此包gojson调用
 */

package gojson

import (
	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
)

// json格式使用json-iterator提高性能
var Json = jsoniter.Config{
	UseNumber:   true,
	SortMapKeys: true,
}.Froze()

func init() {
	// 此方法使用下划线的格式
	extra.SetNamingStrategy(extra.LowerCaseWithUnderscores)

	// 启动模糊模式: 可以容忍字符串和数字互转
	extra.RegisterFuzzyDecoders()
	extra.SupportPrivateFields()
}

// 把对象转化为json
func MarshalToString(obj interface{}) string {
	json, err := Json.MarshalToString(obj)
	if err != nil {
		panic(err)
	}
	return json
}

// 把json字符串转化为结构体或者map等等
func UnmarshalFromString(str string, obj interface{}) error {
	return Json.UnmarshalFromString(str, obj)
}

// 把bytes转化为结构体或者map等等
func Unmarshal(bytes []byte, obj interface{}) error {
	return Json.Unmarshal(bytes, obj)
}
