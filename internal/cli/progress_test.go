package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressReporterRendersSingleLine(t *testing.T) {
	var output bytes.Buffer
	progress := &progressReporter{writer: &output, total: 10, terminal: true}
	progress.Start()
	progress.Update(3, "Admin")
	progress.Finish()
	text := output.String()
	if !strings.Contains(text, "3/10") || !strings.Contains(text, "30%") || !strings.Contains(text, "Admin") {
		t.Fatalf("unexpected progress output: %q", text)
	}
	if strings.Count(text, "\r") != 2 || strings.Count(text, "\n") != 1 {
		t.Fatalf("progress does not update a single line: %q", text)
	}
}

func TestProgressReporterSilentWithoutTerminal(t *testing.T) {
	var output bytes.Buffer
	progress := &progressReporter{writer: &output, total: 10}
	progress.Start()
	progress.Update(3, "Admin")
	progress.Finish()
	if output.Len() != 0 {
		t.Fatalf("unexpected non-terminal output: %q", output.String())
	}
}
