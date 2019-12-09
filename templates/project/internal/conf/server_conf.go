/**
 * Created by Wangwei on 2019-05-30 18:13.
 */

package conf

import "time"

type ServerConfig struct {
	Addr         string   `toml:"addr"`
	Timeout      duration `toml:"timeout"`
	ReadTimeout  duration `toml:"read_timeout"`
	WriteTimeout duration `toml:"write_timeout"`
}

type duration struct {
	time.Duration
}

func (d *duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}
