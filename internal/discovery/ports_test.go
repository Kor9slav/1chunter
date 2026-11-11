package discovery

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("1545,1540-1542,1560,1541")
	if err != nil {
		t.Fatal(err)
	}
	expected := []int{1540, 1541, 1542, 1545, 1560}
	if !reflect.DeepEqual(ports, expected) {
		t.Fatalf("expected %v, got %v", expected, ports)
	}
}

func TestParsePortsRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{"", "0", "65536", "abc", "1540-", "1545-1540", "1540,,1541", "1-10001"} {
		t.Run(value, func(t *testing.T) {
			if _, err := ParsePorts(value); err == nil {
				t.Fatalf("expected error for %q", value)
			}
		})
	}
}
