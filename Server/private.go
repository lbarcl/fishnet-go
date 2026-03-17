package Server

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/valyala/bytebufferpool"
)

func (s *Server) handleFrame(id string, flags FrameFlags, payload *bytebufferpool.ByteBuffer) {
	defer s.bufferPool.Put(payload)

	conn, err := s.getConnectionWrapper(id)
	if err != nil {
		s.onErrorFunc(id, err)
		return
	}

	if !conn.established {
		if hasFlag(flags, FlagTLS) && s.settings.UseTLS {
			conn.con = tls.Server(conn.con, s.tlsCfg)
		} else if hasFlag(flags, FlagTLS) {
			s.onErrorFunc(id, fmt.Errorf("TLS is not enabled on server side. Closing the connection"))
			s.RemoveConnection(id)
			return
		}

		s.setEstablished(id)
	}

	outData := payload.Bytes()
	if hasFlag(flags, FlagGzip) {
		decompressedPayload, err := gunzipFrame(payload, s.settings.MaxDecompressedBytes, &s.bufferPool)
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
	conn, err := s.GetConnection(id)
	if err != nil {
		s.onErrorFunc(id, err)
		return
	}

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

		flags := FrameFlags(headerBuf[4])
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

func (s *Server) sendFrame(id string, flags FrameFlags, payload []byte) error {
	conn, err := s.GetConnection(id)
	if err != nil {
		return err
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

	if _, err := conn.Write(frame); err != nil {
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

	if conn, ok := s.cons[id]; ok {
		conn.established = true
	}
}
