package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func readCredentialFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	defer file.Close()

	var values []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		value := strings.TrimSuffix(scanner.Text(), "\r")
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("файл %s пуст", path)
	}
	return values, nil
}
