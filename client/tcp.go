package client

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/lbarcl/fishnet-go/repo"
	"github.com/valyala/bytebufferpool"
)

func NewClient(settings Settings) (*Client, error) {
	client := &Client{
		settings: settings,
	}

	client.ctx, client.cancel = context.WithCancel(context.Background())
	client.bufferPool = bytebufferpool.Pool{}

	return client, nil
}

func (c *Client) Connect() error {
	conn, err := net.DialTCP("tcp", nil, &c.settings.Addr)
	if err != nil {
		return err
	}

	c.conn = conn

	_ = c.conn.SetDeadline(time.Now().Add(time.Duration(c.settings.Timeout) * time.Second))

	if c.settings.UseTLS {
		_ = c.Send(make([]byte, 0))

		conf := &tls.Config{
			InsecureSkipVerify: c.settings.TrustUnverifiedCerts,
		}

		tlsConn := tls.Client(conn, conf)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}

		c.conn = tlsConn
	}

	c.onConnectFunc()

	go c.listen()
	return nil
}

func (c *Client) Send(payload []byte) error {
	var flags repo.FrameFlags

	if c.settings.UseTLS {
		flags |= repo.FlagTLS
	}

	if len(payload) > int(c.settings.ZipThreshold) {
		flags |= repo.FlagGzip

		gzipPayload, err := repo.GzipFrame(payload, c.settings.MaxFrameBytes)
		if err != nil {
			return err
		}

		if len(gzipPayload) > len(payload) {
			if err := c.sendFrame(flags, payload); err != nil {
				return err
			}
		} else {
			if err := c.sendFrame(flags, gzipPayload); err != nil {
				return err
			}
		}

		return nil
	}

	if err := c.sendFrame(flags, payload); err != nil {
		return err
	}

	return nil
}

func (c *Client) SetOnData(f func(payload []byte)) {
	c.onDataFunc = f
}

func (c *Client) SetOnError(f func(err error)) {
	c.onErrorFunc = f
}

func (c *Client) SetOnConnect(f func()) {
	c.onConnectFunc = f
}

func (c *Client) SetOnDisconnect(f func()) {
	c.onDisconnectFunc = f
}

func (c *Client) Close() {
	c.cancel()
	_ = c.conn.Close()
}
