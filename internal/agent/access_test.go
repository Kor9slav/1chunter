package agent

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestFirstTextRunFindsRussianText(t *testing.T) {
	text := []rune("Локальный кластер")
	data := make([]byte, 0, len(text)*2+6)
	data = append(data, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	for _, value := range text {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		data = append(data, encoded[:]...)
	}
	if actual := firstTextRun(data); actual != "Локальный кластер" {
		t.Fatalf("unexpected text: %q", actual)
	}
}

func TestAccessFailureDetection(t *testing.T) {
	for _, value := range []string{
		"Администратор центрального сервера не аутентифицирован",
		"Недостаточно прав пользователя на управление кластером",
		"Сеанс работы завершен администратором.",
	} {
		if !isAccessFailure(value) {
			t.Fatalf("expected access failure: %s", value)
		}
	}
	if isAccessFailure("Локальный кластер") {
		t.Fatal("cluster name must not be treated as access failure")
	}
}

func TestClusterBoundaryDetection(t *testing.T) {
	encoded := "43 95 d8 f3 1d ba ad ea 3b 47 b5 45 33 6d 3d ee 25 e8 c0 55 d8 f3 1d ba ad ea 3b 47 b5 45 33 6d 3d ee 25 e8 97 43 1d 04 35 04 34 04 3e 04 41 04 42 04 30 04 42 04 3e 04 47 04 3d 04 3e 04 20 00 3f 04 40 04 30 04 32 04 20 00 3f 04 3e 04 3b 04 4c 04 37 04 3e 04 32 04 30 04 42 04 35 04 3b 04 4f 04 20 00 3d 04 30 04 20 00 43 04 3f 04 40 04 30 04 32 04 3b 04 35 04 3d 04 38 04 35 04 20 00 3a 04 3b 04 30 04 41 04 42 04 35 04 40 04 3e 04 3c 04 20 00 1a 04 3b 04 30 04 41 04 42 04 35 04 40 04 1d 04 3e 04 32 04 4b 04 39 04 c1 bb 47 02 63 6f 72 65 38 33 2e 64 6c 6c 3a 30 78 30 30 30 30 30 30 30 30 30 30 30 38 35 39 32 38 20 72 73 65 72 76 65 72 2e 64 6c 6c 3a 30 78 30 30 30 30 30 30 30 30 30 30 30 32 31 35 39 32 46 20 72 73 65 72 76 65 72 2e 64 6c 6c 3a 30 78 30 30 30 30 30 30 30 30 30 30 30"
	data := make([]byte, 0, len(encoded))
	for _, value := range strings.Fields(encoded) {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, decoded...)
	}
	detail := firstTextRun(data)
	if !isAccessFailure(detail) {
		t.Fatalf("cluster boundary was not detected: %q", detail)
	}
}

func TestInfoBaseFields(t *testing.T) {
	encoded := "42 8f 86 df 6e 1e 82 cb 23 95 ab 4a 65 59 d2 c9 e0 49 ab 3b 32 f2 a3 59 5c 5b c2 d5 63 d9 fe d1 0b de cc 4b 95 fe ab 21 1b 7e ec ff 9a 08 5a 55 50 5f 74 65 73 74 9a 03 31 32 33 20 20 a2 81 81 a3 66 53 b2 a6"
	data := make([]byte, 0, len(encoded))
	for _, value := range strings.Fields(encoded) {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, decoded...)
	}
	name, description := infoBaseFields(data)
	if name != "ZUP_test" || description != "123" {
		t.Fatalf("unexpected infobase fields: %q %q", name, description)
	}
}

func TestInfoBaseFieldsEmpty(t *testing.T) {
	encoded := "42 8f 05 c4 ed a3 82 cb 23 95 ab 4a 65 59 d2 c9 e0 49 ab 3b 32 f2 a3 59 5c 5b c1 20 a2 81 81 a3 66 53 b2 a6"
	data := make([]byte, 0, len(encoded))
	for _, value := range strings.Fields(encoded) {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, decoded...)
	}
	name, description := infoBaseFields(data)
	if name != "" || description != "" {
		t.Fatalf("expected empty infobase, got %q %q", name, description)
	}
}

func TestClusterAdminStatus(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected ClusterAdminStatus
	}{
		{name: "authentication required", response: utf16Response("Администратор кластера не аутентифицирован"), expected: ClusterAdminPresent},
		{name: "other access failure", response: utf16Response("Недостаточно прав пользователя на управление кластером"), expected: ClusterAdminUnknown},
		{name: "empty infobase list", response: nil, expected: ClusterAdminAbsent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := clusterAdminStatus(test.response); actual != test.expected {
				t.Fatalf("unexpected status: %q", actual)
			}
		})
	}
}

func utf16Response(text string) []byte {
	data := make([]byte, 0, len(text)*2)
	for _, value := range text {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(value))
		data = append(data, encoded[:]...)
	}
	return data
}

func TestClusterEntriesIncludePort(t *testing.T) {
	data := make([]byte, 16)
	data = append(data, 0x0b)
	data = append(data, []byte("testcluster")...)
	data = append(data, 0xc2, 0xda, 0x0f)
	data = append(data, []byte("SERVER")...)
	data = append(data, 0x8d, 0x05, 0x06)

	clusters := clusterEntries(data)
	if len(clusters) != 1 {
		t.Fatalf("expected one cluster, got %d", len(clusters))
	}
	if clusters[0].Port != 1541 {
		t.Fatalf("unexpected cluster port: %d", clusters[0].Port)
	}
}
