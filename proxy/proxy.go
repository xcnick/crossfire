package proxy

import (
	"crossfire/common"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// whitelist route mode
	whitelist = "whitelist"
	// blacklist route mode
	blacklist = "blacklist"
)

// Client is used to create connection.
type Client interface {
	Name() string
	Addr() string
	Handshake(underlay net.Conn, target string) (StreamConn, error)
	Pack(underlay net.Conn) (PacketConn, error)
}

// ClientCreator is a function to create client.
type ClientCreator func(url *url.URL) (Client, error)

var (
	clientMap = make(map[string]ClientCreator)
)

// RegisterClient is used to register a client.
func RegisterClient(name string, c ClientCreator) {
	clientMap[name] = c
}

// ClientFromURL calls the registered creator to create client.
// dialer is the default upstream dialer so cannot be nil, we can use Default when calling this function.
func ClientFromURL(s string) (Client, error) {
	u, err := url.Parse(s)
	if err != nil {
		log.Printf("can not parse client url %s err: %s", s, err)
		return nil, err
	}

	c, ok := clientMap[strings.ToLower(u.Scheme)]
	if ok {
		return c(u)
	}

	return nil, errors.New("unknown client scheme '" + u.Scheme + "'")
}

// Server interface
type Server interface {
	Name() string
	Addr() string
	Handshake(underlay net.Conn) (StreamConn, *TargetAddr, error)
	Pack(underlay net.Conn) (PacketConn, error)
}

// ServerCreator is a function to create proxy server
type ServerCreator func(url *url.URL) (Server, error)

var (
	serverMap = make(map[string]ServerCreator)
)

// RegisterServer is used to register a proxy server
func RegisterServer(name string, c ServerCreator) {
	serverMap[name] = c
}

// ServerFromURL calls the registered creator to create proxy servers
// dialer is the default upstream dialer so cannot be nil, we can use Default when calling this function
func ServerFromURL(s string) (Server, error) {
	u, err := url.Parse(s)
	if err != nil {
		log.Printf("can not parse server url %s err: %s", s, err)
		return nil, err
	}

	c, ok := serverMap[strings.ToLower(u.Scheme)]
	if ok {
		return c(u)
	}

	return nil, errors.New("unknown server scheme '" + u.Scheme + "'")
}

// An Addr represents a address that you want to access by proxy. Either Name or IP is used exclusively.
type TargetAddr struct {
	Name string // fully-qualified domain name
	IP   net.IP
	Port int
}

// Return host:port string
func (a *TargetAddr) String() string {
	port := strconv.Itoa(a.Port)
	if a.IP == nil {
		return net.JoinHostPort(a.Name, port)
	}
	return net.JoinHostPort(a.IP.String(), port)
}

// Returned host string
func (a *TargetAddr) Host() string {
	if a.IP == nil {
		return a.Name
	}
	return a.IP.String()
}

func NewTargetAddr(addr string) (*TargetAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	port, err := strconv.Atoi(portStr)

	target := &TargetAddr{Port: port}
	if ip := net.ParseIP(host); ip != nil {
		target.IP = ip
	} else {
		target.Name = host
	}
	return target, nil
}

// for tcp relay
type StreamConn interface {
	io.Reader
	io.Writer
	io.Closer
}

// for udp relay
type PacketConn interface {
	net.PacketConn
	ReadWithTargetAddress([]byte) (int, net.Addr, *TargetAddr, error)
}

// Proxy
type Proxy struct {
	localServer                Server
	remoteClient, directClient Client
	route                      string
	matcher                    *common.Matcher
}

func (p *Proxy) Execute() error {
	listener, err := net.Listen("tcp", p.localServer.Addr())
	if err != nil {
		return fmt.Errorf("can not listen tcp on %v: %v", p.localServer.Addr(), err)
	}
	log.Printf("listening tcp on %v", p.localServer.Addr())
	go p.tcpLoop(listener)
	// if p.localServer.Name() == "socks5" {
	// 	udpAddr, err := net.ResolveUDPAddr("udp", p.localServer.Addr())
	// 	if err != nil {
	// 		return fmt.Errorf("can not resolve udp address %s: %v", p.localServer.Addr(), err)
	// 	}
	// 	udpConn, err := net.ListenUDP("udp", udpAddr)
	// 	if err != nil {
	// 		return fmt.Errorf("can not listen udp on %v: %v", p.localServer.Addr(), err)
	// 	}
	// 	log.Printf("listening udp on %v", p.localServer.Addr())
	// 	go p.udpLoop(udpConn)
	// }
	return nil
}

func (p *Proxy) tcpLoop(listener net.Listener) {
	for {
		lc, err := listener.Accept()
		if err != nil {
			select {
			default:
				//
			}

			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			log.Printf("failed to accepted connection: %v", err)
			if strings.Contains(errStr, "too many") {
				time.Sleep(time.Millisecond * 500)
			}
			continue
		}
		go func() {
			// Handshake with raw net.Conn from client and return a connection with protocol support
			wlc, targetAddr, err := p.localServer.Handshake(lc)
			if err != nil {
				lc.Close()
				log.Printf("failed in handshake from %v: %v", p.localServer.Addr(), err)
				return
			}
			defer wlc.Close()

			// Routing logic
			client := p.pickClient(targetAddr)
			dialAddr := p.remoteClient.Addr()
			if client.Name() == "direct" {
				dialAddr = targetAddr.String()
			}
			rc, err := net.Dial("tcp", dialAddr)
			if err != nil {
				log.Printf("failed to dail to %v: %v", dialAddr, err)
				return
			}

			// Handshake with raw net.Conn of remote server and return a connection with protocal support
			wrc, err := client.Handshake(rc, targetAddr.String())
			if err != nil {
				rc.Close()
				log.Printf("failed in handshake to %v: %v", dialAddr, err)
				return
			}
			defer wrc.Close()

			// Traffic forward
			go io.Copy(wrc, wlc)
			io.Copy(wlc, wrc)
		}()
	}
}

func (p *Proxy) pickClient(targetAddr *TargetAddr) Client {
	var client Client
	if p.route == whitelist {
		if p.matcher.Check(targetAddr.Host()) {
			client = p.directClient
		} else {
			client = p.remoteClient
		}
	} else if p.route == blacklist {
		if p.matcher.Check(targetAddr.Host()) {
			client = p.remoteClient
		} else {
			client = p.directClient
		}
	} else {
		client = p.remoteClient
	}
	log.Printf("%v to %v", client.Name(), targetAddr)
	return client
}

func (p *Proxy) udpLoop(lc *net.UDPConn) {
	defer lc.Close()
	var nm sync.Map
	packetBuf := make([]byte, common.UDPBufSize)

	for {
		// Parse incoming packet and return a packet with protocol support
		wlc, err := p.localServer.Pack(lc)
		if err != nil {
			log.Printf("failed in pack: %v", err)
			continue
		}
		n, remoteAddr, targetAddr, err := wlc.ReadWithTargetAddress(packetBuf) // Read from local client
		if err != nil {
			log.Printf("failed in read udp: %v", err)
			continue
		}

		var wrc PacketConn
		v, ok := nm.Load(remoteAddr.String()) // Reuse connection
		if !ok && v == nil {
			// Routing logic
			client := p.pickClient(targetAddr)
			dialAddr := p.remoteClient.Addr()
			var rc net.Conn
			if client.Name() == "direct" { // UDP directly
				dialAddr = targetAddr.String()
				udpDialAddr, err := net.ResolveUDPAddr("udp", dialAddr)
				if err != nil {
					log.Printf("failed to resolve dail address %v: %v", dialAddr, err)
					continue
				}
				zeroAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
				rc, err = net.DialUDP("udp", zeroAddr, udpDialAddr)
			} else { // UDP over TCP
				rc, err = net.Dial("tcp", dialAddr)
			}
			if err != nil {
				log.Printf("failed to dail to %v: %v", dialAddr, err)
				continue
			}

			// Parse outgoing packet and return a packet with protocol support
			wrc, err := client.Pack(rc)
			if err != nil {
				log.Printf("failed to pack: %v", err)
				continue
			}
			nm.Store(remoteAddr.String(), wrc)

			// Traffic forwarding
			go func() {
				b := common.GetBuffer(common.UDPBufSize)
				defer common.PutBuffer(b)

				for {
					wrc.SetReadDeadline(time.Now().Add(2 * time.Minute))
					n, _, err := wrc.ReadFrom(b) // Read from remove server
					if err != nil {
						return
					}
					_, err = wlc.WriteTo(b[:n], remoteAddr) // Write to local client
					if err != nil {
						return
					}
				}

				wrc.Close()
				nm.Delete(remoteAddr.String())
			}()
		} else {
			wrc = v.(PacketConn)
		}

		_, err = wrc.WriteTo(packetBuf[:n], remoteAddr) // Write to remote server
		if err != nil {
			log.Printf("failed in write udp to remote: %v", err)
			continue
		}
	}
}

func NewProxy(local, remote, route string) (*Proxy, error) {
	proxy := &Proxy{}

	var err error
	proxy.localServer, err = ServerFromURL(local)
	if err != nil {
		return nil, fmt.Errorf("can not create local server: %v", err)
	}
	proxy.remoteClient, err = ClientFromURL(remote)
	if err != nil {
		return nil, fmt.Errorf("can not create remote client: %v", err)
	}
	proxy.directClient, _ = ClientFromURL("direct://")
	proxy.route = route
	proxy.matcher = common.NewMather(route)

	return proxy, nil
}
