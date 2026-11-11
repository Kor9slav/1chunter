package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	TransportGreeting = []byte{0x53, 0xf5, 0xc6, 0x1a, 0x7b}
	MessageEnd        = []byte{0x66, 0x53, 0xb2, 0xa6}
	TransportPing     = []byte{0x21, 0x47, 0x54, 0xb3}
)

type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

type Transport struct {
	Dial DialContext
}

type ProbeResult struct {
	Endpoint       string
	ServerGreeting string
	Latency        time.Duration
}

func (transport Transport) Probe(ctx context.Context, endpoint string, timeout time.Duration) (ProbeResult, error) {
	started := time.Now()
	dial := transport.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}
	connection, err := dial(ctx, "tcp", endpoint)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("подключение к %s: %w", endpoint, err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))

	greeting := make([]byte, len(TransportGreeting))
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return ProbeResult{}, fmt.Errorf("чтение приветствия ragent: %w", err)
	}
	if string(greeting) != string(TransportGreeting) {
		return ProbeResult{}, fmt.Errorf("неожиданная сигнатура ragent: %s", hex.EncodeToString(greeting))
	}
	return ProbeResult{
		Endpoint:       endpoint,
		ServerGreeting: hex.EncodeToString(greeting),
		Latency:        time.Since(started),
	}, nil
}
