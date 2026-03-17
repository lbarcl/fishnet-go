package client

import (
	"context"
	"net"

	"github.com/valyala/bytebufferpool"
)

type Settings struct {
	Addr                 net.TCPAddr
	UseTLS               bool
	TrustUnverifiedCerts bool
	Timeout              uint32
	MaxFrameBytes        uint32
	MaxDecompressedBytes uint32
	ZipThreshold         uint32
}

type Client struct {
	settings   Settings
	conn       net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	bufferPool bytebufferpool.Pool

	onDataFunc       func(payload []byte)
	onErrorFunc      func(err error)
	onConnectFunc    func()
	onDisconnectFunc func()
}
