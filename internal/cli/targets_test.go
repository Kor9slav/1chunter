package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveTargetsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "# Тестовые серверы\n192.168.153.138\n\n  192.168.153.131  \r\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := resolveTargets("", path)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"192.168.153.138", "192.168.153.131"}
	if !reflect.DeepEqual(targets, expected) {
		t.Fatalf("unexpected targets: %v", targets)
	}
}

func TestResolveTargetsRejectsInvalidInput(t *testing.T) {
	if _, err := resolveTargets("192.168.153.131", "targets.txt"); err == nil {
		t.Fatal("expected mutually exclusive flags error")
	}
	if _, err := resolveTargets("", ""); err == nil {
		t.Fatal("expected missing target error")
	}

	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("192.168.153.131\nnot-an-ip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTargets("", path); err == nil {
		t.Fatal("expected invalid IP error")
	}
}

func TestResolveTargetsRejectsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("\n# Нет адресов\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTargets("", path); err == nil {
		t.Fatal("expected empty target list error")
	}
}
