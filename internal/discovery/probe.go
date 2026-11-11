package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusOpen     Status = "OPEN"
	StatusClosed   Status = "CLOSED"
	StatusFiltered Status = "FILTERED"
	StatusError    Status = "ERROR"
)

type Endpoint struct {
	Port    int
	Service string
	Status  Status
	Latency time.Duration
	Detail  string
}

type Probe struct {
	Workers int
}

func (probe Probe) Scan(ctx context.Context, host string, ports []int, timeout time.Duration) []Endpoint {
	workers := probe.Workers
	if workers <= 0 {
		workers = 32
	}
	if workers > len(ports) {
		workers = len(ports)
	}

	jobs := make(chan int)
	results := make(chan Endpoint, len(ports))
	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for index := 0; index < workers; index++ {
		go func() {
			defer waitGroup.Done()
			for port := range jobs {
				results <- probePort(ctx, host, port, timeout)
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case jobs <- port:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		waitGroup.Wait()
		close(results)
	}()

	endpoints := make([]Endpoint, 0, len(ports))
	for endpoint := range results {
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(first, second int) bool {
		return endpoints[first].Port < endpoints[second].Port
	})
	return endpoints
}

func (probe Probe) Print(writer io.Writer, host string, endpoints []Endpoint, showClosed bool) {
	fmt.Fprintf(writer, "Обнаружение сервисов 1С: %s\n", host)
	fmt.Fprintln(writer, "Открытый TCP-порт не подтверждает тип сервиса.")
	fmt.Fprintln(writer)
	fmt.Fprintf(writer, "%-8s %-12s %-12s %-12s %s\n", "ПОРТ", "СЕРВИС", "СТАТУС", "ВРЕМЯ", "ПОДРОБНОСТИ")
	open, filtered, errors := 0, 0, 0
	for _, endpoint := range endpoints {
		switch endpoint.Status {
		case StatusOpen:
			open++
		case StatusFiltered:
			filtered++
		case StatusError:
			errors++
		}
		if !showClosed && endpoint.Status != StatusOpen {
			continue
		}
		fmt.Fprintf(writer, "%-8d %-12s %-12s %-12s %s\n",
			endpoint.Port, endpoint.Service, endpoint.Status,
			strconv.FormatInt(endpoint.Latency.Milliseconds(), 10)+" мс", endpoint.Detail)
	}
	fmt.Fprintf(writer, "\nИтого: %d портов, открыто: %d, фильтруется: %d, ошибок: %d\n",
		len(endpoints), open, filtered, errors)
}

func probePort(ctx context.Context, host string, port int, timeout time.Duration) Endpoint {
	started := time.Now()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	connection, err := net.DialTimeout("tcp", address, timeout)
	result := Endpoint{Port: port, Service: ServiceName(port), Latency: time.Since(started)}
	if err == nil {
		_ = connection.Close()
		result.Status = StatusOpen
		result.Detail = "TCP connect"
		return result
	}

	result.Detail = err.Error()
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no route to host") {
		result.Status = StatusClosed
	} else if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		result.Status = StatusFiltered
	} else {
		result.Status = StatusError
	}
	return result
}

func ServiceName(port int) string {
	switch {
	case port == 1540:
		return "ragent"
	case port == 1541:
		return "rmngr"
	case port == 1545:
		return "RAS"
	case port >= 1560 && port <= 1591:
		return "rphost?"
	default:
		return "unknown"
	}
}
