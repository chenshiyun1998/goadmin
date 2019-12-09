/**
 * Created by Wangwei on 2019-03-23 16:59.
 */

package gosecurity

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"goprojects/pkg/util/goconv"
	"goprojects/pkg/util/gostring"
	"goprojects/pkg/util/gostruct"
	"sort"
	"strings"
)

// Sign 微信公众号 url 签名.
func WxSign(token, timestamp, nonce string) (signature string) {
	strs := sort.StringSlice{token, timestamp, nonce}
	strs.Sort()

	buf := make([]byte, 0, len(token)+len(timestamp)+len(nonce))
	buf = append(buf, strs[0]...)
	buf = append(buf, strs[1]...)
	buf = append(buf, strs[2]...)

	hashsum := sha1.Sum(buf)
	return hex.EncodeToString(hashsum[:])
}

// MsgSign 微信公众号/企业号 消息体签名.
func WxMsgSign(token, timestamp, nonce, encryptedMsg string) (signature string) {
	strs := sort.StringSlice{token, timestamp, nonce, encryptedMsg}
	strs.Sort()

	h := sha1.New()

	bufw := bufio.NewWriterSize(h, 128) // sha1.BlockSize 的整数倍
	bufw.WriteString(strs[0])
	bufw.WriteString(strs[1])
	bufw.WriteString(strs[2])
	bufw.WriteString(strs[3])
	bufw.Flush()

	hashsum := h.Sum(nil)
	return hex.EncodeToString(hashsum)
}

/**
微信支付签名
string-->拼接字符串
string-->签名
*/
func WxSignV2(v interface{}, key string) (string, string) {
	_, buf := Getkv(v)

	buf.WriteString(`key=`)
	buf.WriteString(key)

	sum := md5.Sum(buf.Bytes())
	sign := hex.EncodeToString(sum[:])

	return string(buf.Bytes()), strings.ToUpper(sign)
}

func Getkv(v interface{}) (string, *bytes.Buffer) {
	m := gostruct.Struct2Map(v)
	var keys = make([]string, 0, len(m))
	for k, _ := range m {
		if k != "sign" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		if len(goconv.ToString(m[k])) > 0 {
			buf.WriteString(k)
			buf.WriteString(`=`)
			buf.WriteString(goconv.ToString(m[k]))
			buf.WriteString(`&`)
		}
	}

	kvs := string(buf.Bytes())
	kvs = gostring.Substr(kvs, 0, len(kvs)-1)
	return kvs, &buf
}
