/**
 * Created by Wangwei on 2019/11/6 8:18 下午.
 */

package gocopier

import "github.com/jinzhu/copier"

func Copy(target interface{}, source interface{}) {
	if err := copier.Copy(target, source); err != nil {
		panic(err)
	}
}
