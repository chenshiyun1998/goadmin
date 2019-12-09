/**
 * Created by Wangwei on 2019-03-22 11:38.
 */

package gosecurity

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
)

const md5Yan = "moka88ttttdadef&f88&(%*%*%%$*)(#$@$%"

func MD5Password(str string) string {
	h := md5.New()
	h.Write([]byte(str + md5Yan))
	return hex.EncodeToString(h.Sum(nil))
}

/*
给要加密的信息加把盐
*/
func MD5WithSalt(plantext string, salt string) string {
	hash := md5.New()
	io.WriteString(hash, plantext)
	io.WriteString(hash, salt)

	md5str := fmt.Sprintf("%x", hash.Sum(nil))
	return md5str
}
