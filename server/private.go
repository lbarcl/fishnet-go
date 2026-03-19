package server

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/lbarcl/fishnet-go/repo"
	"github.com/valyala/bytebufferpool"
)

func (s *Server) handleFrame(id string, flags repo.FrameFlags, payload *bytebufferpool.ByteBuffer) {
	defer s.bufferPool.Put(payload)

	conn, err := s.getConnectionWrapper(id)
	if err != nil {
		s.onErrorFunc(id, err)
		return
	}

	if !conn.established {
		if s.settings.UseTLS {
			if repo.HasFlag(flags, repo.FlagRequestTLS) {
				conn.con = tls.Server(conn.con, s.tlsCfg)
			} else {
				s.onErrorFunc(id, fmt.Errorf("security policy violation: TLS required"))
				s.RemoveConnection(id)
				return
			}
		} else {
			if repo.HasFlag(flags, repo.FlagRequestTLS) {
				s.onErrorFunc(id, fmt.Errorf("client requested TLS but server is plaintext-only"))
				s.RemoveConnection(id)
				return
			}
		}

		s.setEstablished(id)
	}

	outData := payload.Bytes()
	if repo.HasFlag(flags, repo.FlagGzip) {
		decompressedPayload, err := repo.GunzipFrame(payload, s.settings.MaxDecompressedBytes, &s.bufferPool)
		if err != nil {
			s.onErrorFunc(id, fmt.Errorf("error gunzipping frame: %v", err))
			return
		}

		outData = decompressedPayload.Bytes()
		defer s.bufferPool.Put(decompressedPayload)
	}

	if s.onDataFunc != nil {
		temp := make([]byte, len(outData))
		copy(temp, outData)
		s.onDataFunc(id, temp)
	}
}

// [4 Bytes payload size][1 Byte flags][N Bytes payload]
func (s *Server) handleConnection(id string) {
	connWrap, err := s.getConnectionWrapper(id)
	if err != nil {
		s.onErrorFunc(id, err)
		return
	}
	conn := connWrap.con

	// Centralized cleanup
	defer func() {
		s.RemoveConnection(id)
		if s.onDisconnectFunc != nil {
			s.onDisconnectFunc(id)
		}
	}()

	setDeadline := func() {
		if s.settings.Timeout != 0 && conn != nil {
			_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.settings.Timeout) * time.Second))
		}
	}

	headerBuf := make([]byte, 5) // Allocated once outside the loop
	for {
		setDeadline()

		if _, err := io.ReadFull(conn, headerBuf); err != nil {
			if s.ctx.Err() == nil {
				s.onErrorFunc(id, err)
			}
			return
		}

		payloadSize := binary.BigEndian.Uint32(headerBuf[:4])
		if payloadSize > s.settings.MaxFrameBytes {
			s.onErrorFunc(id, fmt.Errorf("payload size %d exceeds max", payloadSize))
			return
		}

		flags := repo.FrameFlags(headerBuf[4])
		payload := s.bufferPool.Get() // Consider sync.Pool for large payloads
		if _, err := io.CopyN(payload, conn, int64(payloadSize)); err != nil {
			if s.ctx.Err() == nil {
				s.onErrorFunc(id, err)
			}
			return
		}

		s.handleFrame(id, flags, payload)
	}
}

func (s *Server) sendFrame(id string, flags repo.FrameFlags, payload []byte) error {
	connWrapp, err := s.getConnectionWrapper(id)
	if err != nil {
		return err
	}

	if repo.HasFlag(flags, repo.FlagStartTLS) {
		if !connWrapp.established {
			<-connWrapp.ready
		}

		if s.settings.UseTLS {
			<-connWrapp.tlsHandShakeDone
		}
	}
	if len(payload) > int(s.settings.MaxFrameBytes) {
		return fmt.Errorf("payload size exceeds maximum allowed: %d", len(payload))
	}

	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	frame[4] = byte(flags)

	copy(frame[5:], payload)
	s.sendLockTheID(id)
	defer s.sendUnlockTheID(id)

	if _, err := connWrapp.con.Write(frame); err != nil {
		return err
	}

	return nil
}

func (s *Server) sendLockTheID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if conn, ok := s.cons[id]; ok {
		conn.wmu.Lock()
	}
}

func (s *Server) sendUnlockTheID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if conn, ok := s.cons[id]; ok {
		conn.wmu.Unlock()
	}
}

func (s *Server) getConnectionWrapper(id string) (*Connection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, ok := s.cons[id]
	if !ok {
		return nil, fmt.Errorf("connection not found for ID: %s", id)
	}

	return conn, nil
}

func (s *Server) setEstablished(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, ok := s.cons[id]
	if !ok || conn.established {
		return
	}

	// 1. If TLS was wrapped in handleFrame, we must ensure the handshake completes
	if s.settings.UseTLS {

		var flags repo.FrameFlags
		flags |= repo.FlagStartTLS

		s.sendFrame(id, flags, make([]byte, 0))

		if tc, ok := conn.con.(*tls.Conn); ok {
			if err := tc.Handshake(); err != nil {
				s.onErrorFunc(id, fmt.Errorf("TLS handshake failed: %v", err))
				s.RemoveConnection(id)
				return
			}
			close(conn.tlsHandShakeDone)
		}
	} else {
		// If not using TLS, immediately unblock senders
		close(conn.tlsHandShakeDone)
	}

	conn.established = true
	close(conn.ready) // Unblock the 'ready' gate
}
