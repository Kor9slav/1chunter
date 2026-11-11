package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type progressReporter struct {
	writer   io.Writer
	total    int
	terminal bool
}

func newProgressReporter(writer io.Writer, total int) *progressReporter {
	terminal := false
	if file, ok := writer.(*os.File); ok {
		if info, err := file.Stat(); err == nil {
			terminal = info.Mode()&os.ModeCharDevice != 0
		}
	}
	return &progressReporter{writer: writer, total: total, terminal: terminal}
}

func (progress *progressReporter) Start() {
	if progress.terminal {
		progress.render(0, "")
	}
}

func (progress *progressReporter) Update(attempt int, username string) {
	if progress.terminal {
		progress.render(attempt, username)
	}
}

func (progress *progressReporter) Finish() {
	if progress.terminal {
		fmt.Fprintln(progress.writer)
	}
}

func (progress *progressReporter) render(attempt int, username string) {
	if progress.total < 1 {
		return
	}
	percent := attempt * 100 / progress.total
	if percent > 100 {
		percent = 100
	}
	filled := percent / 5
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", 20-filled)
	runes := []rune(username)
	if len(runes) > 32 {
		username = string(runes[:32])
	}
	fmt.Fprintf(progress.writer, "\r\033[K[%s] %d/%d (%3d%%) | %s", bar, attempt, progress.total, percent, username)
}
