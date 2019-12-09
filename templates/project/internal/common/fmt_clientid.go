/**
 * Created by Wangwei on 2019-05-31 14:31.
 */

package common

import "strings"

func FormatClientId(clientId string) string {
	if strings.HasPrefix(clientId, "webadmin") {
		return "webadmin"
	} else if strings.HasPrefix(clientId, "h5") {
		return "h5"
	} else if strings.HasPrefix(clientId, "mp") {
		return "mp"
	} else {
		return "web_admin"
	}
}
