/**
 * Created by Wangwei on 2019-03-17 11:30.
 */

package gosecurity

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"openapi/pkg/mapstruct"
	"reflect"
	"sort"
	"strings"
)

// MD5加密签名
func Sign(m map[string]interface{}, appSecret string) string {
	str := GetKvString(m)

	appId := m["app_id"].(string)
	str = fmt.Sprintf("%s%s%s", str, appId, appSecret)

	/*hash := md5.New()
	io.WriteString(hash, str)
	md5str := fmt.Sprintf("%x", hash.Sum(nil))*/

	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))

	//return md5str
}

// 获取签名排序字符串
func GetKvString(m map[string]interface{}) string {
	var keys []string
	for key, _ := range m {
		if key == "sign" || key == "app_id" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var kvs []string
	for _, k := range keys {
		v := m[k]
		type_ := reflect.TypeOf(v).String()

		if type_ == "[]interface {}" {
			kvStrs := []string{}
			vv := v.([]interface{})
			for _, item := range vv {
				itemMap := item.(map[string]interface{})
				s := GetKvString(itemMap)
				kvStrs = append(kvStrs, s)
			}
			kvStr := strings.Join(kvStrs, "")
			kv := fmt.Sprintf("%s=%v", k, kvStr)
			kvs = append(kvs, kv)
		} else if type_ == "map[string]interface {}" {
			vv := v.(map[string]interface{})
			kvStr := GetKvString(vv)
			kv := fmt.Sprintf("%s=%v", k, kvStr)
			kvs = append(kvs, kv)
		} else {
			kv := fmt.Sprintf("%s=%v", k, v)
			kvs = append(kvs, kv)
		}
	}

	str := strings.Join(kvs, "&")
	return str
}

func StructSign(v interface{}, appSecret string) string {
	m := mapstruct.Struct2Map(v)
	return Sign(m, appSecret)
}
