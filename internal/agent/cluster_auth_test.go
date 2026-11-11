package agent

import (
	"bytes"
	"testing"
)

func TestBuildClusterCredentialRequest(t *testing.T) {
	clusterID := []byte{0xc6, 0xa2, 0xb9, 0x88, 0xb9, 0x25, 0xc9, 0x4e, 0x8e, 0xca, 0xf7, 0xe8, 0x5f, 0xa8, 0x97, 0xdd}
	request, err := buildClusterCredentialRequest("2ca99659-d297-4681-a276-9c51d411cc44", clusterID, "Admin", "secret", 0x95)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range [][]byte{
		{0x9a, 0x05, 'A', 'd', 'm', 'i', 'n'},
		{0x9a, 0x06, 's', 'e', 'c', 'r', 'e', 't'},
		clusterID,
	} {
		if !bytes.Contains(request, expected) {
			t.Fatalf("missing %x in request", expected)
		}
	}
	if bytes.Contains(request, []byte("0123456789abcdef")) {
		t.Fatal("template password was not replaced")
	}
	if request[19] != 0x95 || request[20] != 0x1d {
		t.Fatalf("unexpected request metadata: %x %x", request[19], request[20])
	}
}
