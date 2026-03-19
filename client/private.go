package client

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/lbarcl/fishnet-go/repo"
	"github.com/valyala/bytebufferpool"
)

func (c *Client) handleFrame(flags repo.FrameFlags, payload *bytebufferpool.ByteBuffer) {
	defer c.bufferPool.Put(payload)

	if c.settings.UseTLS && repo.HasFlag(flags, repo.FlagStartTLS) {

		config := &tls.Config{
			InsecureSkipVerify: c.settings.TrustUnverifiedCerts,
		}

		c.conn = tls.Client(c.conn, config)
		err := c.conn.(*tls.Conn).Handshake()
		if err != nil {
			if c.onErrorFunc != nil {
				c.onErrorFunc(err)
			}
			return
		}

		if c.onConnectFunc != nil {
			c.onConnectFunc()
		}
		close(c.ready)
		return
	}

	outData := payload.Bytes()

	if repo.HasFlag(flags, repo.FlagPing) {
		temp := make([]byte, len(outData))
		copy(temp, outData)
		var flag repo.FrameFlags
		flag |= repo.FlagPong
		c.sendFrame(flag, temp)

		sentTimeUnix := int64(binary.BigEndian.Uint64(temp[:8]))
		sentTime := time.Unix(sentTimeUnix, 0)
		duration := time.Since(sentTime)
		c.Ping = int(duration)
		return
	}

	if repo.HasFlag(flags, repo.FlagGzip) {
		decompressedPayload, err := repo.GunzipFrame(payload, c.settings.MaxDecompressedBytes, &c.bufferPool)
		if err != nil {
			if c.onErrorFunc != nil {
				c.onErrorFunc(fmt.Errorf("error gunzipping frame: %v", err))
			}
			return
		}

		outData = decompressedPayload.Bytes()
		defer c.bufferPool.Put(decompressedPayload)
	}

	if c.onDataFunc != nil {
		temp := make([]byte, len(outData))
		copy(temp, outData)
		c.onDataFunc(temp)
	}
}

func (c *Client) sendFrame(flags repo.FrameFlags, payload []byte) error {
	if len(payload) > int(c.settings.MaxFrameBytes) {
		return fmt.Errorf("payload size exceeds maximum allowed: %d", len(payload))
	}

	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	frame[4] = byte(flags)

	copy(frame[5:], payload)

	if _, err := c.conn.Write(frame); err != nil {
		return err
	}

	return nil
}

func (c *Client) listen() {
	headerBuf := make([]byte, 5)
	if c.onDisconnectFunc != nil {
		defer c.onDisconnectFunc()
	}

	for {
		if _, err := io.ReadFull(c.conn, headerBuf); err != nil {
			if c.ctx.Err() == nil {
				if c.onErrorFunc != nil {
					c.onErrorFunc(err)
				}
			}
			return
		}

		payloadSize := binary.BigEndian.Uint32(headerBuf[:4])
		if payloadSize > c.settings.MaxFrameBytes {
			if c.onErrorFunc != nil {
				c.onErrorFunc(fmt.Errorf("payload size %d exceeds max", payloadSize))
			}
			return
		}

		flags := repo.FrameFlags(headerBuf[4])
		payload := c.bufferPool.Get()
		if _, err := io.CopyN(payload, c.conn, int64(payloadSize)); err != nil {
			if c.ctx.Err() == nil {
				if c.onErrorFunc != nil {
					c.onErrorFunc(err)
				}
			}
			return
		}

		c.handleFrame(flags, payload)
	}
}
