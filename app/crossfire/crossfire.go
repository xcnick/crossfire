package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"crossfire/common"
	"crossfire/proxy"
	_ "crossfire/proxy/socks5"
	_ "crossfire/proxy/tls"
	_ "crossfire/proxy/trojan"
	_ "crossfire/proxy/vless"
)

var (
	// Version
	version  = "0.1.0"
	codename = "Crossfire, a simple implementation of V2Ray vless and trojan"

	// Flag
	f = flag.String("f", "client.json", "config file name")
)

const (
	// 路由模式
	whitelist = "whitelist"
	blacklist = "blacklist"
)

//
// Version
//

func printVersion() {
	fmt.Printf("Crossfire %v (%v), %v %v %v\n", version, codename, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

//
// Config
//

type Config struct {
	Local  string `json:"local"`
	Route  string `json:"route"`
	Remote string `json:"remote"`
}

func loadConfig(configFileName string) (*Config, error) {
	path := common.GetPath(configFileName)
	if len(path) > 0 {
		if cf, err := os.Open(path); err == nil {
			defer cf.Close()
			bytes, _ := ioutil.ReadAll(cf)
			config := &Config{}
			if err = json.Unmarshal(bytes, config); err != nil {
				return nil, fmt.Errorf("can not parse config file %v, %v", configFileName, err)
			}
			return config, nil
		}
	}
	return nil, fmt.Errorf("can not load config file %v", configFileName)
}

func main() {
	// 打印版本信息
	printVersion()

	// 解析命令行参数
	flag.Parse()

	// 读取配置文件，默认为客户端模式
	conf, err := loadConfig(*f)
	if err != nil {
		log.Printf("can not load config file: %v", err)
		os.Exit(-1)
	}

	// Proxy
	proxy, err := proxy.NewProxy(conf.Local, conf.Remote, conf.Route)
	if err != nil {
		log.Printf("can not create proxy: %v", err)
		os.Exit(-1)
	}
	if err = proxy.Execute(); err != nil {
		log.Printf("can not run proxy: %v", err)
		os.Exit(-1)
	}

	// 后台运行
	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
		<-osSignals
	}
}
