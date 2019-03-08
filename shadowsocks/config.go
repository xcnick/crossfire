package shadowsocks

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"
)

type Config struct {
	Server       string `json:"server"`
	ServerPort   int    `json:"server_port"`
	LocalPort    int    `json:"local_port"`
	LocalAddress string `json:"local_address"`
	Password     string `json:"password"`
	Method       string `json:"method"`
	Timeout      int    `json:"timeout"`
}

var readTimeout time.Duration

func ParseConfig(path string) (config *Config, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	config = &Config{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	readTimeout = time.Duration(config.Timeout) * time.Second
	return
}

func SetDebug(d DebugLog) {
	Debug = d
}
