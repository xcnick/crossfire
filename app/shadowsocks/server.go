package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	ss "crossfire/proxy/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip address start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4   = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6   = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase = 2               // 1addrLen + 2port, plus addrLen
	// lenHmacSha1 = 10
)

var debug ss.DebugLog
var udp bool

func getRequest(conn *ss.StreamConn) (host string, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 269)
	// 获取地址类型字段
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	switch addrType {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// 解析port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return
}

func handleConnection(conn *ss.StreamConn, port string) {
	var host string

	if debug {
		debug.Printf("new client %s->%s\n", conn.RemoteAddr(), conn.LocalAddr())
	}

	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s->%s\n", conn.RemoteAddr(), host)
		}
		if !closed {
			conn.Close()
		}
	}()

	host, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
		closed = true
		return
	}

	if strings.ContainsRune(host, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log to many open file
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	if debug {
		debug.Printf("piping %s<->%s", conn.RemoteAddr(), host)
	}
	go ss.PipeThenClose(conn, remote, nil)
	ss.PipeThenClose(remote, conn, nil)

	closed = true
	return
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	for sig := range sigChan {
		log.Printf("caught signal %v, exit", sig)
		os.Exit(0)
	}
}

func run(port, password string) {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}
	var cipher *ss.CipherAead
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			debug.Printf("accept error: %v\n", err)
			return
		}
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipherAead(config.Method, password)
			if err != nil {
				log.Printf("error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewStreamConn(conn, cipher.Copy()), port)
	}
}

var configFile string
var config *ss.Config

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
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-128-gcm")
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

	go run(strconv.Itoa(config.ServerPort), config.Password)
	if udp {
		// go runUDP(port, password)
	}

	waitSignal()
}
