package socks5

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"time"

	"crossfire/common"
	"crossfire/proxy"
)

func init() {
	proxy.RegisterServer(Name, NewSocks5Server)
}

func NewSocks5Server(url *url.URL) (proxy.Server, error) {
	addr := url.Host

	// TODO: Support Auth
	user := url.User.Username()
	password, _ := url.User.Password()

	s := &Server{
		addr:     addr,
		user:     user,
		password: password,
	}
	return s, nil
}

type Server struct {
	addr     string
	user     string
	password string
}

func (s *Server) Name() string { return Name }

func (s *Server) Addr() string { return s.addr }

func (s *Server) Handshake(underlay net.Conn) (proxy.StreamConn, *proxy.TargetAddr, error) {
	// Set handshake timeout 4 seconds
	if err := underlay.SetReadDeadline(time.Now().Add(time.Second * 4)); err != nil {
		return nil, nil, err
	}
	defer underlay.SetReadDeadline(time.Time{})

	// https://www.ietf.org/rfc/rfc1928.txt
	reqOneByte := common.GetBuffer(1)
	defer common.PutBuffer(reqOneByte)

	if _, err := io.ReadFull(underlay, reqOneByte); err != nil {
		return nil, nil, fmt.Errorf("failed to read socks version:%v", err)
	}
	if reqOneByte[0] != Version5 {
		return nil, nil, fmt.Errorf("invalid socks version:%v", reqOneByte[0])
	}

	if _, err := io.ReadFull(underlay, reqOneByte); err != nil {
		return nil, nil, fmt.Errorf("failed to read NMETHODS")
	}
	if _, err := io.CopyN(ioutil.Discard, underlay, int64(reqOneByte[0])); err != nil {
		return nil, nil, fmt.Errorf("failed to read methods:%v", err)
	}

	if _, err := underlay.Write([]byte{Version5, AuthNone}); err != nil {
		return nil, nil, fmt.Errorf("failed to write auth:%v", err)
	}

	// Read command message
	reqCmd := common.GetBuffer(3)
	defer common.PutBuffer(reqCmd)

	if _, err := io.ReadFull(underlay, reqCmd); err != nil {
		return nil, nil, fmt.Errorf("failed to read command:%v", err)
	}
	cmd := reqCmd[1]

	addr, _, err := ReadTargetAddr(underlay)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read address:%v", err)
	}

	if cmd != CmdConnect {
		return nil, nil, fmt.Errorf("unsuppoted command %v", cmd)
	}

	switch cmd {
	case CmdConnect:
		_, err = underlay.Write([]byte{Version5, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case CmdUDPAssociate:
		listenAddr := ParseAddr(underlay.LocalAddr().String())
		_, err = underlay.Write(append([]byte{Version5, 0, 0}, listenAddr...))
		// Keep the connection util timeout then the socket will be free
		buf := common.GetBuffer(16)
		defer common.PutBuffer(buf)
		underlay.Read(buf)
	default:
		return nil, nil, fmt.Errorf("unsuppoted command %v", cmd)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to write command response: %w", err)
	}

	return underlay, addr, err
}

func (s *Server) Pack(underlay net.Conn) (proxy.PacketConn, error) {
	return nil, errors.New("implement me")
}
