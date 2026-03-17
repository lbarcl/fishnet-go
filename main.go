package main

import (
	"fmt"
	tcp "github.com/lbarcl/fishnet-go/Server"
	"net"
)

func main() {
	serverSettings := tcp.Settings{
		Addr:                 net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		UseTLS:               false,
		Timeout:              1000,
		MaxDecompressedBytes: 1024 * 1024,
		MaxFrameBytes:        1024 * 512,
	}

	tcpServer, err := tcp.NewServer(serverSettings)
	if err != nil {
		fmt.Println("Error creating server:", err)
		return
	}

	for {
		id, err := tcpServer.Accept()

		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		fmt.Println("Accepted connection:", id)
	}
}
