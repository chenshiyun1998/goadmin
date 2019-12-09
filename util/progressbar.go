/**
 * Created by Wangwei on 2019-07-12 15:35.
 */

package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"

	pb "github.com/cheggaaa/pb/v3"
)

func RunProgressBar(title string, time int64) {
	var limit int64 = 1024 * 1024 * time

	tmpl := `{{ green "%s" }} {{ bar . "<" "-" (cycle . "↖" "↗" "↘" "↙" ) "." ">"}} {{ percent .}}`
	tmpl = fmt.Sprintf(tmpl, title)
	bar := pb.ProgressBarTemplate(tmpl).Start64(limit)

	reader := io.LimitReader(rand.Reader, limit)
	writer := ioutil.Discard

	barReader := bar.NewProxyReader(reader)
	io.Copy(writer, barReader)

	bar.Finish()
}
