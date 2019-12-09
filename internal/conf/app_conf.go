/**
 * Created by Wangwei on 2019-05-31 20:46.
 */

package conf

type AppConfig struct {
	JwtSecret    string `dsn:"jwt_secret"`
	PwdMd5Secret string `dsn:"pwd_md5_secret"`
}
