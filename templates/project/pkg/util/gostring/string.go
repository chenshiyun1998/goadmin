// Copyright 2019 syncd Author. All Rights Reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package gostring

import (
	"encoding/base64"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/text/encoding/simplifiedchinese"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
	STR     = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func JoinStrings(multiString ...string) string {
	return strings.Join(multiString, "")
}

func JoinIntSlice2String(intSlice []int, sep string) string {
	return strings.Join(IntSlice2StrSlice(intSlice), sep)
}

func StrSplit2IntSlice(str, sep string) []int {
	return StrSlice2IntSlice(StrFilterSliceEmpty(strings.Split(str, sep)))
}

func Str2StrSlice(str, sep string) []string {
	return StrFilterSliceEmpty(strings.Split(str, sep))
}

func StrSlice2IntSlice(strSlice []string) []int {
	var intSlice []int
	for _, s := range strSlice {
		i, _ := strconv.Atoi(s)
		intSlice = append(intSlice, i)
	}
	return intSlice
}

func StrFilterSliceEmpty(strSlice []string) []string {
	var filterSlice []string
	for _, s := range strSlice {
		ss := strings.TrimSpace(s)
		if ss != "" {
			filterSlice = append(filterSlice, ss)
		}
	}
	return filterSlice
}

func IntSlice2StrSlice(intSlice []int) []string {
	var strSlice []string
	for _, i := range intSlice {
		s := strconv.Itoa(i)
		strSlice = append(strSlice, s)
	}
	return strSlice
}

func Str2Int(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func Int2Str(i int) string {
	return strconv.Itoa(i)
}

func RandomString(l int) string {
	bytes := []byte(STR)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}

	return string(result)
}

func PrefixRandomString(l int, prefix string) string {
	bytes := []byte(STR)
	result := []byte{}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}

	return prefix + string(result)
}

// 生成随机数，用户订单号，流水号等
func RandomNo(l int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := time.Now().Format("20060102150405") //16
	for i := len(code); i < l; i++ {
		code = code + strconv.Itoa(r.Intn(10))
	}

	return code
}

// 生成带前缀的随机数，用户订单号，流水号等
func PrefixRandomNo(l int, prefix string) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := prefix + time.Now().Format("20060102150405") //16
	for i := len(code); i < l; i++ {
		code = code + strconv.Itoa(r.Intn(10))
	}

	return code
}

func UUID() string {
	_uuid := uuid.NewV4().String()
	_uuid = strings.Replace(_uuid, "-", "", -1)
	no := Substr(_uuid, 0, 32)
	return no
}

func Substr(str string, start int, length int) string {
	rs := []rune(str)
	rl := len(rs)
	end := 0

	if start < 0 {
		start = rl - 1 + start
	}

	end = start + length

	if start > end {
		start, end = end, start
	}

	if start < 0 {
		start = 0
	}
	if start > rl {
		start = rl
	}
	if end < 0 {
		end = 0
	}
	if end > rl {
		end = rl
	}

	return string(rs[start:end])
}

//截取字符串 start 起点下标 end 终点下标(不包括)
func Substr2(str string, start int, end int) string {
	rs := []rune(str)
	length := len(rs)

	if start < 0 || start > length {
		panic("start is wrong")
	}

	if end < 0 || end > length {
		panic("end is wrong")
	}

	return string(rs[start:end])
}

func Base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Base64Decode(s string) ([]byte, error) {
	ds, err := base64.StdEncoding.DecodeString(s)
	return ds, err
}

func Base64UrlEncode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

func Base64UrlDecode(s string) ([]byte, error) {
	ds, err := base64.URLEncoding.DecodeString(s)
	return ds, err
}

func ConvertByte2String(byte []byte, charset Charset) string {
	var str string
	switch charset {
	case GB18030:
		var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}

	return str
}
