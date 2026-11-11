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

func runInfoBaseExec(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("infobase exec", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "Адрес ragent")
	agentPort := flags.Int("agent-port", 1540, "Порт ragent")
	clusterName := flags.String("cluster", "", "Имя кластера")
	clusterPort := flags.Int("cluster-port", 0, "Порт кластера; по умолчанию определяется автоматически")
	infoBase := flags.String("infobase", "", "Имя информационной базы")
	command := flags.String("command", "", "Команда для выполнения на сервере 1С")
	_ = flags.Bool("confirm-exec", false, "Больше не требуется; оставлен для совместимости")
	username := flags.String("agent-user", "Administrator@SRV-1C-DEV", "Имя пользователя NTLM")
	workstation := flags.String("workstation", "SRV-1C-DEV", "Имя рабочей станции")
	locale := flags.String("locale", "1ru_RU", "Локаль протокола")
	timeout := flags.Duration("timeout", 60*time.Second, "Таймаут операции")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *target == "" || *clusterName == "" || *infoBase == "" || *command == "" ||
		*agentPort < 1 || *agentPort > 65535 || *clusterPort < 0 || *clusterPort > 65535 || *timeout <= 0 {
		fmt.Fprintln(stderr, "Укажите --target, --cluster, --infobase, --command и корректные параметры подключения")
		return 2
	}

	client := agent.Client{Locale: *locale}
	result, err := client.ExecuteCommand(context.Background(), net.JoinHostPort(*target, strconv.Itoa(*agentPort)),
		*username, os.Getenv("ONECHUNTER_AGENT_PASSWORD"), *workstation, agent.ExecuteCommandConfig{
			ClusterName: *clusterName,
			ClusterPort: *clusterPort,
			InfoBase:    *infoBase,
			Command:     *command,
		}, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Команда выполнена на сервере: %s\n", result.WorkerEndpoint)
	fmt.Fprintln(stdout, result.Output)
	return 0
}
