package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Kor9slav/1chunter/internal/agent"
	"github.com/Kor9slav/1chunter/internal/discovery"
)

const version = "0.1.0"

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stdout)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		printRootUsage(stdout)
		return 0
	case "version", "-V", "--version":
		fmt.Fprintf(stdout, "1CHunter %s\n", version)
		return 0
	case "discover":
		return runDiscover(args[1:], stdout, stderr)
	case "agent":
		return runAgent(args[1:], stdout, stderr)
	case "infobase":
		return runInfoBase(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Неизвестная команда: %s\n", args[0])
		printRootUsage(stderr)
		return 2
	}
}

func runDiscover(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("discover", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "Адрес сервера 1С")
	ports := flags.String("ports", "1540,1541,1545,1560-1591", "Порты и диапазоны")
	timeout := flags.Duration("timeout", 3*time.Second, "Таймаут подключения")
	showClosed := flags.Bool("show-closed", false, "Показывать закрытые порты")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *timeout <= 0 {
		fmt.Fprintln(stderr, "Укажите --target и положительный --timeout")
		return 2
	}
	parsedPorts, err := discovery.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 2
	}

	endpoints := (discovery.Probe{Workers: 32}).Scan(context.Background(), *target, parsedPorts, *timeout)
	(discovery.Probe{}).Print(stdout, *target, endpoints, *showClosed)
	for _, endpoint := range endpoints {
		if endpoint.Status == discovery.StatusError {
			return 1
		}
	}
	return 0
}

func runAgent(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printAgentUsage(stderr)
		return 2
	}
	switch args[0] {
	case "probe":
		return runAgentProbe(args[1:], stdout, stderr)
	case "auth", "inspect":
		return runAgentAuth(args[1:], stdout, stderr)
	case "brute":
		return runAgentBrute(args[1:], stdout, stderr)
	case "relay":
		return runAgentRelay(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Неизвестная команда agent: %s\n", args[0])
		printAgentUsage(stderr)
		return 2
	}
}

func runAgentProbe(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("agent probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "Адрес ragent")
	agentPort := flags.Int("agent-port", 1540, "Порт ragent")
	timeout := flags.Duration("timeout", 3*time.Second, "Таймаут handshake")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *agentPort < 1 || *agentPort > 65535 || *timeout <= 0 {
		fmt.Fprintln(stderr, "Укажите корректные --target, --agent-port и --timeout")
		return 2
	}

	endpoint := net.JoinHostPort(*target, strconv.Itoa(*agentPort))
	result, err := (agent.Transport{}).Probe(context.Background(), endpoint, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "ragent: %s\n", result.Endpoint)
	fmt.Fprintf(stdout, "Транспорт 1С подтверждён по сигнатуре: %s\n", result.ServerGreeting)
	fmt.Fprintf(stdout, "Время handshake: %d мс\n", result.Latency.Milliseconds())
	fmt.Fprintln(stdout, "TCP-транспорт проверен; административная аутентификация и кластеры не запрашивались.")
	return 0
}

func runAgentAuth(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("agent auth", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "Адрес ragent")
	targetList := flags.String("target-list", "", "Файл с IP-адресами ragent, по одному на строку")
	agentPort := flags.Int("agent-port", 1540, "Порт ragent")
	username := flags.String("agent-user", "", "Имя пользователя NTLM; по умолчанию генерируется")
	workstation := flags.String("workstation", "", "Имя рабочей станции; по умолчанию генерируется")
	platformVersion := flags.String("platform-version", "", "Версия платформы 1С; по умолчанию определяется автоматически")
	locale := flags.String("locale", "1ru_RU", "Локаль протокола")
	timeout := flags.Duration("timeout", 5*time.Second, "Таймаут аутентификации")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *agentPort < 1 || *agentPort > 65535 || *timeout <= 0 {
		fmt.Fprintln(stderr, "Укажите корректные --agent-port и --timeout")
		return 2
	}
	targets, err := resolveTargets(*target, *targetList)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 2
	}
	if *username == "" {
		*username = "1chunter"
	}
	if *workstation == "" {
		*workstation = "1CHUNTER"
	}

	client := agent.Client{PlatformVersion: *platformVersion, Locale: *locale}
	failed := false
	for index, currentTarget := range targets {
		if index > 0 {
			fmt.Fprintln(stdout)
		}
		succeeded, err := inspectTarget(stdout, currentTarget, *agentPort, client, *username, os.Getenv("ONECHUNTER_AGENT_PASSWORD"), *workstation, *timeout)
		if err != nil {
			fmt.Fprintf(stderr, "Ошибка (%s): %v\n", currentTarget, err)
		}
		if !succeeded {
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

func inspectTarget(stdout io.Writer, target string, agentPort int, client agent.Client, username, password, workstation string, timeout time.Duration) (bool, error) {
	endpoint := net.JoinHostPort(target, strconv.Itoa(agentPort))
	result, err := client.Authenticate(context.Background(), endpoint, username, password, workstation, timeout)
	if err != nil {
		return false, err
	}
	fmt.Fprintf(stdout, "ragent: %s\n", endpoint)
	if result.PlatformVersion != "" {
		fmt.Fprintf(stdout, "Версия платформы: %s\n", result.PlatformVersion)
	} else {
		fmt.Fprintln(stdout, "Версия платформы: не определена")
	}
	fmt.Fprintf(stdout, "Пользователь NTLM: %s\n", username)
	fmt.Fprintf(stdout, "NTLM: %s\n", result.Detail)
	if len(result.Clusters) > 0 {
		for _, cluster := range result.Clusters {
			fmt.Fprintf(stdout, "Кластер: %s\n", cluster.Name)
			fmt.Fprintf(stdout, "  Администратор кластера: %s\n", cluster.AdminStatus)
			if cluster.Port > 0 {
				fmt.Fprintf(stdout, "  Порт кластера: %d\n", cluster.Port)
			}
			for _, infoBase := range cluster.InfoBases {
				fmt.Fprintf(stdout, "  Информационная база: %s\n", infoBase.Name)
				fmt.Fprintf(stdout, "  Описание ИБ: %s\n", infoBase.Description)
			}
		}
		if hasInfoBases(result) {
			fmt.Fprintln(stdout, "Чтение ИБ без пароля администратора кластера: выполнено")
		}
	} else {
		if result.ClusterName != "" {
			fmt.Fprintf(stdout, "Кластер: %s\n", result.ClusterName)
		}
		if result.InfoBaseName != "" {
			fmt.Fprintf(stdout, "Информационная база: %s\n", result.InfoBaseName)
			fmt.Fprintf(stdout, "Описание ИБ: %s\n", result.InfoBaseDescription)
			fmt.Fprintln(stdout, "Чтение ИБ без пароля администратора кластера: выполнено")
		}
	}
	fmt.Fprintf(stdout, "Операция управления кластером: %s\n", result.AdminStatus)
	if result.AdminDetail != "" {
		fmt.Fprintf(stdout, "Подробности: %s\n", result.AdminDetail)
	}
	if !result.Accepted {
		return false, nil
	}
	if hasInfoBases(result) {
		return true, nil
	}
	if result.AdminStatus == agent.AdminDenied {
		return false, nil
	}
	return true, nil
}

func hasInfoBases(result agent.AuthResult) bool {
	for _, cluster := range result.Clusters {
		if len(cluster.InfoBases) > 0 {
			return true
		}
	}
	return result.InfoBaseName != ""
}

func runAgentRelay(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("agent relay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "Адрес ragent")
	agentPort := flags.Int("agent-port", 1540, "Порт ragent")
	listenHost := flags.String("listen-host", "127.0.0.1", "Адрес прослушивания relay")
	listenPort := flags.Int("listen-port", 15400, "Порт прослушивания relay")
	allowIP := flags.String("allow", "", "IP единственного разрешённого клиента")
	dumpPath := flags.String("dump", "agent-relay.log", "Новый файл дампа; /dev/null — без записи")
	rewriteFrom := flags.String("rewrite-from", "", "Исходное имя хоста в ответах сервера")
	rewriteTo := flags.String("rewrite-to", "", "Новое имя хоста той же длины")
	maxConnections := flags.Int("max-connections", 1, "Число подключений; 0 — без ограничений")
	timeout := flags.Duration("timeout", 5*time.Second, "Таймаут подключения к ragent")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *dumpPath == "" || *agentPort < 1 || *agentPort > 65535 || *listenPort < 1 || *listenPort > 65535 || *maxConnections < 0 {
		fmt.Fprintln(stderr, "Укажите корректные --target, --agent-port, --listen-port, --max-connections и --dump")
		return 2
	}
	if *listenHost != "127.0.0.1" && *listenHost != "localhost" && *listenHost != "::1" && *allowIP == "" {
		fmt.Fprintln(stderr, "Для relay на внешнем адресе обязателен --allow с IP Windows-клиента")
		return 2
	}
	if *allowIP != "" {
		for _, address := range strings.Split(*allowIP, ",") {
			if net.ParseIP(strings.TrimSpace(address)) == nil {
				fmt.Fprintln(stderr, "Некорректный IP в --allow")
				return 2
			}
		}
	}

	err := agent.RunRelay(agent.RelayConfig{
		ListenHost:     *listenHost,
		ListenPort:     *listenPort,
		TargetHost:     *target,
		TargetPort:     *agentPort,
		AllowIP:        *allowIP,
		DumpPath:       *dumpPath,
		RewriteFrom:    *rewriteFrom,
		RewriteTo:      *rewriteTo,
		MaxConnections: *maxConnections,
		Timeout:        *timeout,
	}, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 1
	}
	return 0
}

func printRootUsage(writer io.Writer) {
	fmt.Fprintln(writer, "1CHunter — проверка безопасности 1С через прямой ragent:1540")
	fmt.Fprintln(writer, "Использование:")
	fmt.Fprintln(writer, "  1chunter discover --target <HOST> [--ports 1540,1541,1560-1591]")
	fmt.Fprintln(writer, "  1chunter agent probe --target <HOST> [--agent-port 1540]")
	fmt.Fprintln(writer, "  1chunter agent inspect (--target <HOST> | --target-list <FILE>) [--agent-user USER]")
	fmt.Fprintln(writer, "  1chunter agent brute --target <HOST> --cluster <NAME> --users <FILE> --passwords <FILE>")
	fmt.Fprintln(writer, "  1chunter agent relay --target <HOST> [--listen-host 127.0.0.1 --listen-port 15400]")
	fmt.Fprintln(writer, "  1chunter infobase --create --target <HOST> --cluster <NAME> --name <IB_NAME> [параметры СУБД]")
	fmt.Fprintln(writer, "  1chunter infobase exec --target <HOST> --cluster <NAME> --infobase <IB> --command <CMD>")
	fmt.Fprintln(writer, "  1chunter version")
}

func printAgentUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Использование:")
	fmt.Fprintln(writer, "  1chunter agent probe --target <HOST> [--agent-port 1540]")
	fmt.Fprintln(writer, "  1chunter agent inspect (--target <HOST> | --target-list <FILE>) [--agent-user USER]")
	fmt.Fprintln(writer, "  1chunter agent brute --target <HOST> --cluster <NAME> --users <FILE> --passwords <FILE>")
	fmt.Fprintln(writer, "  1chunter agent relay --target <HOST> [--listen-port 15400] [--allow <IP>]")
}
