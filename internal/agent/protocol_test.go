package agent

import (
	"bufio"
	"bytes"
	"testing"
)

func TestDecodeBase64Block(t *testing.T) {
	value, err := decodeBase64Block([]byte("prefix{#base64:TlRMTVNTUA==}suffix"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "NTLMSSP" {
		t.Fatalf("unexpected decoded value: %q", value)
	}
}

func TestDecodeRawNTLMBlock(t *testing.T) {
	value, err := decodeBase64Block([]byte("{TlRMTVNTUA==}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "NTLMSSP" {
		t.Fatalf("unexpected decoded value: %q", value)
	}
}

func TestDetectServerVersion(t *testing.T) {
	frame := []byte("Различаются версии клиента и сервера (8.3.26.0 - 8.3.27.1859), {00000000},\"8.3.27.1859\"}")
	if version := detectServerVersion(frame); version != "8.3.27.1859" {
		t.Fatalf("unexpected server version: %s", version)
	}
}

func TestFrameReaderPreservesFollowingFrame(t *testing.T) {
	first := append([]byte{1, 2, 3}, MessageEnd...)
	second := append([]byte{4, 5, 6}, MessageEnd...)
	reader := newFrameReader(bufio.NewReader(bytes.NewReader(append(first, second...))))

	actualFirst, err := reader.readFrame(1024)
	if err != nil {
		t.Fatal(err)
	}
	actualSecond, err := reader.readFrame(1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualFirst, first) || !bytes.Equal(actualSecond, second) {
		t.Fatalf("frames changed: %x %x", actualFirst, actualSecond)
	}
}
