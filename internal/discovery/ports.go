package discovery

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const maxPorts = 10000

func ParsePorts(specification string) ([]int, error) {
	if strings.TrimSpace(specification) == "" {
		return nil, fmt.Errorf("список портов не может быть пустым")
	}

	unique := make(map[int]struct{})
	for _, rawPart := range strings.Split(specification, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			return nil, fmt.Errorf("пустой элемент в списке портов")
		}
		if strings.Contains(part, "-") {
			if err := parseRange(part, unique); err != nil {
				return nil, err
			}
			continue
		}
		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		unique[port] = struct{}{}
	}

	if len(unique) > maxPorts {
		return nil, fmt.Errorf("за один запуск можно проверить не более %d портов", maxPorts)
	}
	ports := make([]int, 0, len(unique))
	for port := range unique {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

func parseRange(part string, ports map[int]struct{}) error {
	bounds := strings.Split(part, "-")
	if len(bounds) != 2 {
		return fmt.Errorf("некорректный диапазон портов: %s", part)
	}
	first, err := parsePort(strings.TrimSpace(bounds[0]))
	if err != nil {
		return err
	}
	last, err := parsePort(strings.TrimSpace(bounds[1]))
	if err != nil {
		return err
	}
	if first > last {
		return fmt.Errorf("начало диапазона больше конца: %s", part)
	}
	if last-first+1 > maxPorts {
		return fmt.Errorf("слишком большой диапазон портов: %s", part)
	}
	for port := first; port <= last; port++ {
		ports[port] = struct{}{}
	}
	return nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("некорректный порт: %s", value)
	}
	return port, nil
}
