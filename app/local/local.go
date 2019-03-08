package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	ss "shadowsocks-lite/shadowsocks"
	"strconv"
)

var debug ss.DebugLog

var (
	errVer           = errors.New("socks version not supported")
	errCmd           = errors.New("socks command not supported")
	errAddrType      = errors.New("socks addr type not supported")
	errAuthExtraData = errors.New("sock authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	var n int
	// ss.SetReadTimeout(conn)
	// 读取前面两个字节，ver + idNmethod
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	if buf[idVer] != socksVer5 {
		return errVer
	}
	// 表示第三个字段method的长度
	nmethod := int(buf[idNmethod])
	// 消息总长度
	msgLen := nmethod + 2
	if n == msgLen {
		// 正常情况，实际读取的字节数与理论相同
	} else if n < msgLen {
		// 如果读取的字节数不够，则把剩余的读完
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else {
		// 读取数据出现错误
		return errAuthExtraData
	}

	// 回复浏览器，返回两个字节，1.协议版本号 2.无需认证标识0
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // 第4个字节是地址类型
		idIP0   = 4 // 如果地址是IP，则第5个字节起为IP内容
		idDmLen = 4 // 如果地址是域名，则第5个字节为域名长度
		idDm0   = 5 // 如果地址是域名，则第6个字节起为域名内容

		typeIPv4 = 1 // ATYP=1表示IPv4
		typeDm   = 3 // ATYP=3表示域名
		typeIPv6 = 4 // ATYP=4表示IPv6

		// 如果是IPv4，则整个请求数据长度为
		// 3(ver+cmd+rsv) + 1addrtype + ipv4 + 2port
		lenIPv4   = 3 + 1 + net.IPv4len + 2
		lenIPv6   = 3 + 1 + net.IPv6len + 2
		lenDmBase = 3 + 1 + 1 + 2
	)

	// 理论上协议最大长度+1
	buf := make([]byte, 263)
	var n int
	// ss.SetReadtimeout(conn)
	// 至少读取5个字节，即使时域名，也读取到了域名的长度
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// 检验协议头
	if buf[idVer] != socksCmdConnect {
		err = errVer
		return
	}
	// 仅处理客户端Connect请求类型
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	// 根据地址类型计算发来的请求数据的理论长度
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	// 判断理论应读取的字节数与实际读取的一致
	if n == reqLen {
		// 正常情况
	} else if n < reqLen {
		// 如果不够则继续读完
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		// 读取数据出错
		err = errReqExtraData
		return
	}

	// 获取地址信息
	// 如果是IPv4,则rawaddr包含的信息是1addrtype + ipv4 + 2port
	rawaddr = buf[idType:reqLen]

	// 如果开启debug模式，则将目标地址转换为字符串方便打印
	if debug {
		switch buf[idType] {
		case typeIPv4:
			host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		case typeIPv6:
			host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		case typeDm:
			host = string(buf[idDm0 : idDm0+buf[idDmLen]])
		}
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	return
}

func handleConnection(conn net.Conn) {
	if debug {
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	closed := false
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	var err error = nil
	// socks5协议握手过程
	if err = handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	// socks5协议握手成功后
	// 将浏览器要访问的真正地址解析出来
	// rawaddr表示字节表示的地址
	// addr表示转换成字符串的地址
	rawaddr, addr, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// 给浏览器的响应
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation:", err)
		return
	}

	// 传入要访问的真实地址，比如google.com
}

func run(listenAddr string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting local socks5 server at %v ...\n", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func main() {
	log.SetOutput(os.Stdout)

	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
	}
	if config.Method == "" {
		config.Method = "aes-128-gcm"
	}
	if err = ss.CheckCipherAeadMethod(config.Method); err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}

	if config.Password == "" || config.ServerPort == 0 {
		fmt.Fprintln(os.Stderr, "server_port and password must be specified")
		os.Exit(1)
	}

	// go run(port, password)
	// if udp {
	// 	go runUDP(port, password)
	// }

	// waitSignal()
	//run()
}
