package agent

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggingWriterPreservesDataAndWritesDump(t *testing.T) {
	var destination bytes.Buffer
	var dump bytes.Buffer
	writer := loggingWriter{destination: &destination, dump: &dump, direction: "client>agent"}
	payload := []byte{0x53, 0xf5, 0xc6, 0x1a, 0x7b}

	written, err := writer.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), written)
	}
	if !bytes.Equal(destination.Bytes(), payload) {
		t.Fatalf("payload changed: %x", destination.Bytes())
	}
	if !strings.Contains(dump.String(), "53 f5 c6 1a 7b") {
		t.Fatalf("hex payload not found in dump: %s", dump.String())
	}
}

func TestLoggingWriterRewritesAdvertisedAddress(t *testing.T) {
	var destination bytes.Buffer
	var dump bytes.Buffer
	writer := loggingWriter{
		destination: &destination,
		dump:        &dump,
		direction:   "agent>client",
		rewriteFrom: []byte("DESKTOP-DHPEU34:"),
		rewriteTo:   []byte("192.168.153.132:"),
	}
	payload := []byte("prefix DESKTOP-DHPEU34:1561 suffix")

	written, err := writer.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), written)
	}
	expected := "prefix 192.168.153.132:1561 suffix"
	if destination.String() != expected {
		t.Fatalf("unexpected rewritten payload: %q", destination.String())
	}
	if !strings.Contains(dump.String(), expected) {
		t.Fatalf("rewritten payload not found in dump: %s", dump.String())
	}
}

func TestRelayIPAllowed(t *testing.T) {
	allowed := "192.168.153.132, 192.168.153.137"
	if !relayIPAllowed(allowed, "192.168.153.132") || !relayIPAllowed(allowed, "192.168.153.137") {
		t.Fatal("allowed IP rejected")
	}
	if relayIPAllowed(allowed, "192.168.153.138") {
		t.Fatal("unexpected IP allowed")
	}
}

func TestPrintable(t *testing.T) {
	if result := printable([]byte{'A', 0, 'B'}); result != "A.B" {
		t.Fatalf("unexpected printable representation: %s", result)
	}
}
