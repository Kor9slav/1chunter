package agent

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RelayConfig struct {
	ListenHost     string
	ListenPort     int
	TargetHost     string
	TargetPort     int
	AllowIP        string
	DumpPath       string
	RewriteFrom    string
	RewriteTo      string
	MaxConnections int
	Timeout        time.Duration
}

func RunRelay(config RelayConfig, output io.Writer) error {
	if config.ListenPort < 1 || config.ListenPort > 65535 || config.TargetPort < 1 || config.TargetPort > 65535 {
		return fmt.Errorf("некорректный порт relay")
	}
	if config.TargetHost == "" {
		return fmt.Errorf("не указан адрес ragent")
	}
	if (config.RewriteFrom == "") != (config.RewriteTo == "") {
		return fmt.Errorf("для подмены адреса укажите --rewrite-from и --rewrite-to")
	}
	if len(config.RewriteFrom) != len(config.RewriteTo) {
		return fmt.Errorf("адреса --rewrite-from и --rewrite-to должны иметь одинаковую длину")
	}
	if config.MaxConnections < 0 {
		return fmt.Errorf("некорректное число подключений")
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}

	listenAddress := net.JoinHostPort(config.ListenHost, strconv.Itoa(config.ListenPort))
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("запуск relay на %s: %w", listenAddress, err)
	}
	defer listener.Close()
	dump, err := os.OpenFile(config.DumpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("создание файла дампа %s: %w", config.DumpPath, err)
	}
	defer dump.Close()
	dumpMutex := &sync.Mutex{}

	targetAddress := net.JoinHostPort(config.TargetHost, strconv.Itoa(config.TargetPort))
	fmt.Fprintf(dump, "# 1CHunter relay %s target=%s\n", time.Now().Format(time.RFC3339Nano), targetAddress)
	if config.MaxConnections == 0 {
		fmt.Fprintf(output, "Relay принимает подключения без ограничений: %s -> %s\n", listenAddress, targetAddress)
	} else {
		fmt.Fprintf(output, "Relay ожидает подключения (%d): %s -> %s\n", config.MaxConnections, listenAddress, targetAddress)
	}

	var sessions sync.WaitGroup
	accepted := 0
	for {
		connection, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("приём подключения: %w", err)
		}
		remoteIP, _, err := net.SplitHostPort(connection.RemoteAddr().String())
		if err != nil {
			_ = connection.Close()
			continue
		}
		if !relayIPAllowed(config.AllowIP, remoteIP) {
			fmt.Fprintf(output, "Подключение отклонено для %s: разрешены только %s\n", remoteIP, config.AllowIP)
			_ = connection.Close()
			continue
		}
		accepted++
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			if err := proxyRelayConnection(connection, config, targetAddress, dump, dumpMutex, output); err != nil {
				fmt.Fprintf(output, "Ошибка соединения: %v\n", err)
			}
		}()
		if config.MaxConnections > 0 && accepted >= config.MaxConnections {
			break
		}
	}
	sessions.Wait()
	fmt.Fprintln(output, "Все соединения завершены, relay остановлен.")
	return nil
}

func proxyRelayConnection(connection net.Conn, config RelayConfig, targetAddress string, dump *os.File, dumpMutex *sync.Mutex, output io.Writer) error {
	defer connection.Close()
	target, err := net.DialTimeout("tcp", targetAddress, config.Timeout)
	if err != nil {
		return fmt.Errorf("подключение relay к %s: %w", targetAddress, err)
	}
	defer target.Close()

	fmt.Fprintf(output, "Клиент: %s, дамп: %s\n", connection.RemoteAddr(), config.DumpPath)
	dumpMutex.Lock()
	fmt.Fprintf(dump, "\n# client=%s connected=%s\n", connection.RemoteAddr(), time.Now().Format(time.RFC3339Nano))
	dumpMutex.Unlock()

	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(&loggingWriter{destination: target, dump: dump, dumpMutex: dumpMutex, direction: "client>agent"}, connection)
		_ = target.Close()
	}()
	go func() {
		defer waitGroup.Done()
		_, _ = io.Copy(&loggingWriter{
			destination: connection,
			dump:        dump,
			dumpMutex:   dumpMutex,
			direction:   "agent>client",
			rewriteFrom: []byte(config.RewriteFrom + ":"),
			rewriteTo:   []byte(config.RewriteTo + ":"),
		}, target)
		_ = connection.Close()
	}()
	waitGroup.Wait()
	fmt.Fprintf(output, "Соединение %s завершено.\n", connection.RemoteAddr())
	return nil
}

func relayIPAllowed(allowed, remoteIP string) bool {
	if allowed == "" {
		return true
	}
	for _, address := range strings.Split(allowed, ",") {
		if strings.TrimSpace(address) == remoteIP {
			return true
		}
	}
	return false
}

type loggingWriter struct {
	destination io.Writer
	dump        io.Writer
	dumpMutex   *sync.Mutex
	direction   string
	rewriteFrom []byte
	rewriteTo   []byte
}

func (writer *loggingWriter) Write(data []byte) (int, error) {
	if len(writer.rewriteFrom) > 1 {
		data = bytes.ReplaceAll(data, writer.rewriteFrom, writer.rewriteTo)
	}
	written, err := writer.destination.Write(data)
	if written > 0 {
		chunk := data[:written]
		if writer.dumpMutex != nil {
			writer.dumpMutex.Lock()
			defer writer.dumpMutex.Unlock()
		}
		fmt.Fprintf(writer.dump, "\n%s %s bytes=%d\n%s\n%s\n",
			time.Now().Format(time.RFC3339Nano), writer.direction, written,
			hexDump(chunk), printable(chunk))
	}
	return written, err
}

func hexDump(data []byte) string {
	const digits = "0123456789abcdef"
	var builder strings.Builder
	for index, value := range data {
		if index > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteByte(digits[value>>4])
		builder.WriteByte(digits[value&0x0f])
	}
	return builder.String()
}

func printable(data []byte) string {
	var builder strings.Builder
	for _, value := range data {
		if value >= 32 && value < 127 {
			builder.WriteByte(value)
		} else {
			builder.WriteByte('.')
		}
	}
	return builder.String()
}
