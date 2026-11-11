package agent

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeExchangesGreeting(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write(TransportGreeting)
	}()

	transport := Transport{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return client, nil
	}}
	result, err := transport.Probe(context.Background(), "pipe", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ServerGreeting != "53f5c61a7b" {
		t.Fatalf("unexpected greeting: %s", result.ServerGreeting)
	}
}

func TestProbeRejectsUnexpectedGreeting(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{1, 2, 3, 4, 5})
	}()
	transport := Transport{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return client, nil
	}}
	if _, err := transport.Probe(context.Background(), "pipe", time.Second); err == nil {
		t.Fatal("expected unexpected greeting error")
	}
}
