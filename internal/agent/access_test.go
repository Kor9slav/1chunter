package agent

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"
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

func TestAdminRequestParameters(t *testing.T) {
	tests := []struct {
		name            string
		platformVersion string
		flagOverride    byte
		expectedID      byte
		expectedFlag    byte
	}{
		{name: "default", platformVersion: "8.3.22", expectedID: 0x11, expectedFlag: 0x06},
		{name: "8.3.23", platformVersion: "8.3.23.1782", expectedID: 0x11, expectedFlag: 0x4c},
		{name: "8.3.27", platformVersion: "8.3.27.1936", expectedID: 0xa1, expectedFlag: 0x53},
		{name: "override", platformVersion: "8.3.27.1936", flagOverride: 0x1d, expectedID: 0xa1, expectedFlag: 0x1d},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, flag := adminRequestParameters(test.platformVersion, test.flagOverride)
			if id != test.expectedID || flag != test.expectedFlag {
				t.Fatalf("unexpected parameters: id=%#x flag=%#x", id, flag)
			}
		})
	}
}

func TestClusterEntriesLengthPrefixedName(t *testing.T) {
	encoded := "42 8f aa 87 45 4b 82 cb 23 95 9c 4e 34 41 8a 16 10 4c 8d f4 0a 37 00 db d8 15 c2 d5 49 37 87 14 f0 50 08 40 9b 21 34 39 2a 13 f8 c4 9a 09 43 6c 75 73 74 65 72 31 43 c2 da 05 31 43 2d 30 35 8d 05 06 20 a1 8b 3c 81 81 82 81 81 82 81 81 82 9a 09 30 20 32 20 2a 20 2a 20 2a 20 20 a1 81 a4 91 00 40 e9 fe b6 01 00 00 66 53 b2 a6"
	data, err := hex.DecodeString(strings.ReplaceAll(encoded, " ", ""))
	if err != nil {
		t.Fatal(err)
	}

	clusters := clusterEntries(data)
	if len(clusters) != 1 {
		t.Fatalf("expected one cluster, got %d", len(clusters))
	}
	if clusters[0].Name != "Cluster1C" || clusters[0].Port != 1541 {
		t.Fatalf("unexpected cluster: %+v", clusters[0])
	}
	if actual := hex.EncodeToString(clusters[0].ID); actual != "49378714f05008409b2134392a13f8c4" {
		t.Fatalf("unexpected cluster ID: %s", actual)
	}
}

func TestCheckAdminAccessRejectsUnrecognizedClusterResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	deadline := time.Now().Add(time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	go func() {
		defer server.Close()
		reader := newFrameReader(bufio.NewReader(server))
		if _, err := reader.readFrame(maxProtocolFrame); err != nil {
			return
		}
		_, _ = server.Write(MessageEnd)
		if _, err := reader.readFrame(maxProtocolFrame); err != nil {
			return
		}
		_, _ = server.Write(MessageEnd)
	}()

	authenticationFrame := []byte("3ace6d91-51bb-4344-9388-c8105ad4ad11 d775ecad-e471-41a1-9031-9b4c60a13dbf")
	reader := newFrameReader(bufio.NewReader(client))
	_, _, _, err := checkAdminAccessWithFlag(client, reader, authenticationFrame, "8.3.27.1936", 0)
	if err == nil || !strings.Contains(err.Error(), "не удалось разобрать ответ со списком кластеров") {
		t.Fatalf("unexpected error: %v", err)
	}
}
