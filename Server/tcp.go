package Server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/valyala/bytebufferpool"
)

const (
	FlagGzip FrameFlags = 1 << iota
	FlagTLS  FrameFlags = 1 << iota
)

func NewServer(settings Settings) (*Server, error) {
	s := &Server{
		settings: settings,
		cons:     make(map[string]*Connection),
	}

	listener, err := net.Listen("TCP", settings.Addr.String())
	if err != nil {
		return nil, err
	}

	if settings.UseTLS {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{settings.Cert},
			MinVersion:   tls.VersionTLS12,
		}

		s.tlsCfg = tlsConfig
	}

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.listener = listener

	s.bufferPool = bytebufferpool.Pool{}

	return s, nil
}

func (s *Server) Accept() (string, error) {
	conn, err := s.listener.Accept()
	if err != nil {
		return "", err
	}

	id, err := s.SetConnection(conn)
	if err != nil {
		return "", err
	}

	if s.onConnectFunc != nil {
		s.onConnectFunc(id)
	}

	go s.handleConnection(id)
	return id, nil
}

func (s *Server) Send(id string, payload []byte) error {
	var flags FrameFlags
	if len(payload) > int(s.settings.ZipThreshold) {
		flags |= FlagGzip

		gzipPayload, err := gzipFrame(payload, s.settings.MaxFrameBytes)
		if err != nil {
			return err
		}

		if len(gzipPayload) > len(payload) {
			if err := s.sendFrame(id, flags, payload); err != nil {
				return err
			}
		} else {
			if err := s.sendFrame(id, flags, gzipPayload); err != nil {
				return err
			}
		}

		return nil
	}

	if err := s.sendFrame(id, flags, payload); err != nil {
		return err
	}

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cancel()
	return s.listener.Close()
}

func (s *Server) GetConnection(id string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, ok := s.cons[id]
	if !ok {
		return nil, fmt.Errorf("Connection not found for ID: %s", id)
	}

	return conn.con, nil
}

func (s *Server) SetConnection(conn net.Conn) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, _ := newUID()
	for _, ok := s.cons[id]; ok; {
		id, _ = newUID()
	}

	s.cons[id] = &Connection{
		con: conn,
	}
	return id, nil
}

func (s *Server) RemoveConnection(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, ok := s.cons[id]
	if !ok {
		return fmt.Errorf("Connection not found for ID: %s", id)
	}

	conn.con.Close()
	delete(s.cons, id)
	return nil
}

func (s *Server) SetOnData(f func(id string, payload []byte)) {
	s.onDataFunc = f
}

func (s *Server) SetOnError(f func(id string, err error)) {
	s.onErrorFunc = f
}

func (s *Server) SetOnConnect(f func(id string)) {
	s.onConnectFunc = f
}

func (s *Server) SetOnDisconnect(f func(id string)) {
	s.onDisconnectFunc = f
}
