package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func resolveTargets(target, targetList string) ([]string, error) {
	target = strings.TrimSpace(target)
	targetList = strings.TrimSpace(targetList)
	if target != "" && targetList != "" {
		return nil, fmt.Errorf("параметры --target и --target-list нельзя использовать одновременно")
	}
	if target != "" {
		return []string{target}, nil
	}
	if targetList == "" {
		return nil, fmt.Errorf("укажите --target или --target-list")
	}

	file, err := os.Open(targetList)
	if err != nil {
		return nil, fmt.Errorf("чтение списка целей: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		address := strings.TrimSpace(scanner.Text())
		if address == "" || strings.HasPrefix(address, "#") {
			continue
		}
		if net.ParseIP(address) == nil {
			return nil, fmt.Errorf("%s:%d: некорректный IP-адрес %q", targetList, lineNumber, address)
		}
		targets = append(targets, address)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("чтение списка целей: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("список целей %s пуст", targetList)
	}
	return targets, nil
}
