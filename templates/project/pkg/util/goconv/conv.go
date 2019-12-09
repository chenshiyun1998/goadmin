/**
 * Created by Wangwei on 2019/11/6 10:40 上午.
 */

package goconv

import (
	"encoding/json"
	"strconv"
)

func ToFloat64(value interface{}) float64 {
	if v, ok := value.(json.Number); ok {
		f, err := v.Float64()
		if err != nil {
			panic(err)
		}
		return f
	}
	if v, ok := value.([]uint8); ok {
		f, err := strconv.ParseFloat(string(v), 64)
		if err != nil {
			panic(err)
		}
		return f
	}
	if v, ok := value.(string); ok {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			panic(err)
		}
		return f
	}
	return value.(float64)
}

func ToString(value interface{}) string {
	if value == nil {
		return ""
	}
	if v, ok := value.(json.Number); ok {
		return v.String()
	}
	if v, ok := value.(int64); ok {
		return strconv.FormatInt(v, 10)
	}
	if v, ok := value.(float64); ok {
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	if v, ok := value.(int); ok {
		return strconv.Itoa(v)
	}

	return value.(string)
}

func ToInt(value interface{}) int {
	if value == nil {
		return 0
	}
	if v, ok := value.(json.Number); ok {
		iv, err := strconv.Atoi(v.String())
		if err != nil {
			panic(err)
		}
		return iv
	}
	if v, ok := value.(int64); ok {
		return int(v)
	}
	if v, ok := value.(float64); ok {
		return int(v)
	}
	if v, ok := value.(int); ok {
		return v
	}
	if v, ok := value.(string); ok {
		vv, err := strconv.Atoi(v)
		if err != nil {
			panic(err)
		}
		return vv
	}
	if v, ok := value.(json.Number); ok {
		vv, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			panic(err)
		}
		return int(vv)
	}

	return value.(int)
}

func ToInt64(value interface{}) int64 {
	if value == nil {
		return 0
	}
	if v, ok := value.(json.Number); ok {
		iv, err := v.Int64()
		if err != nil {
			panic(err)
		}
		return iv
	}
	if v, ok := value.(int64); ok {
		return v
	}
	if v, ok := value.(float64); ok {
		return int64(v)
	}
	if v, ok := value.(int); ok {
		return int64(v)
	}
	if v, ok := value.(string); ok {
		iv, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			panic(err)
		}
		return iv
	}

	return value.(int64)
}
