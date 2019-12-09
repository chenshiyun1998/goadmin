/**
 * Created by Wangwei on 2019-05-30 18:14.
 */

package DB

type MySQLConfig struct {
	Host    string `toml:"host"`
	Port    int    `toml:"port"`
	User    string `toml:"user"`
	Pswd    string `toml:"pswd"`
	Dbname  string `toml:"dbname"`
	Charset string `toml:"charset"`
}
