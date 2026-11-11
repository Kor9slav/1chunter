package agent

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildAgentCreateInfoBaseRequest(t *testing.T) {
	clusterID := []byte{0x5a, 0x9a, 0xb9, 0xb9, 0x94, 0xe3, 0xbc, 0x41, 0xb0, 0x19, 0xb5, 0x59, 0xd4, 0xad, 0x7b, 0xad}
	request := buildAgentCreateInfoBaseRequest("301e76dd-983b-47b1-9f17-4603d62f0ee6", clusterID, "Hunter_go_test")
	if !bytes.Contains(request, []byte{0x9a, 14}) || !bytes.Contains(request, []byte("Hunter_go_test")) {
		t.Fatalf("infobase name not encoded: %x", request)
	}
	if bytes.Contains(request, []byte("Hunter_relay_test")) {
		t.Fatal("template infobase name was not replaced")
	}
	encodedClusterID := append([]byte{0xc2, 0x95}, clusterID...)
	encodedClusterID = append(encodedClusterID, 0x20)
	if !bytes.Contains(request, encodedClusterID) {
		t.Fatal("cluster ID or its protocol marker not encoded")
	}
	if request[20] != 0x34 {
		t.Fatalf("unexpected create request flag: %x", request[20])
	}
}

func TestBuildWorkerCreateInfoBaseRequest(t *testing.T) {
	config := CreateInfoBaseConfig{
		ClusterPort: 1542,
		Name:        "Hunter_go_test",
		Description: `test "description"`,
		DBMS:        "PostgreSQL",
		DBServer:    "192.168.153.131",
		DBName:      "hunter_go",
		DBUser:      "postgres",
		DBPassword:  "secret",
	}
	request, err := buildWorkerCreateInfoBaseRequest("d37e82d3-fdf9-45f7-a0b8-8138ee6a6e3b", "192.168.153.131:1540", config)
	if err != nil {
		t.Fatal(err)
	}
	text := string(request)
	for _, expected := range []string{
		`Srvr="192.168.153.131:1542"`, `Ref="Hunter_go_test"`, `Descr="test ""description"""`,
		`DBMS="PostgreSQL"`, `DB="hunter_go"`, `DBUID="postgres"`, `DBPwd="secret"`,
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("missing %q in request", expected)
		}
	}
	if !bytes.HasSuffix(request, workerCreateSuffix) {
		t.Fatal("fixed AdminProcess UUID was changed")
	}
}

func TestWorkerEndpoint(t *testing.T) {
	endpoint, err := workerEndpoint("192.168.153.131:1540", []byte("prefix DESKTOP-DHPEU34:1561 suffix"))
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "192.168.153.131:1561" {
		t.Fatalf("unexpected worker endpoint: %s", endpoint)
	}
}

func TestValidateCreateInfoBaseConfig(t *testing.T) {
	config := CreateInfoBaseConfig{
		ClusterName: "КластерНовый",
		Name:        "Hunter_go_test",
		DBMS:        "postgres",
		DBServer:    "192.168.153.131",
		DBName:      "hunter_go",
		DBUser:      "postgres",
	}
	if err := validateCreateInfoBaseConfig(&config); err != nil {
		t.Fatal(err)
	}
	if config.ClusterPort != 0 || config.DBMS != "PostgreSQL" {
		t.Fatalf("unexpected normalized config: %+v", config)
	}
}
