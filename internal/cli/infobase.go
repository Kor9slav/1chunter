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

	"github.com/Kor9slav/1chunter/internal/agent"
)

func runInfoBase(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "exec" {
		return runInfoBaseExec(args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("infobase", flag.ContinueOnError)
	flags.SetOutput(stderr)
	create := flags.Bool("create", false, "Создать информационную базу")
	confirmCreate := flags.Bool("confirm-create", false, "Подтвердить создание ИБ и базы данных")
	target := flags.String("target", "", "Адрес ragent")
	agentPort := flags.Int("agent-port", 1540, "Порт ragent")
	clusterName := flags.String("cluster", "", "Имя кластера без администратора")
	clusterPort := flags.Int("cluster-port", 0, "Порт кластера; по умолчанию определяется автоматически")
	name := flags.String("name", "", "Имя создаваемой информационной базы")
	description := flags.String("description", "", "Описание информационной базы")
	dbms := flags.String("dbms", "postgres", "Тип СУБД: postgres или mssql")
	dbHost := flags.String("db-host", "", "Адрес сервера СУБД")
	dbName := flags.String("db-name", "", "Имя создаваемой базы данных")
	dbUser := flags.String("db-user", "", "Пользователь СУБД")
	dbPassword := flags.String("db-password", "", "Пароль СУБД; безопаснее ONECHUNTER_DB_PASSWORD")
	username := flags.String("agent-user", "1chunter", "Имя пользователя NTLM")
	workstation := flags.String("workstation", "1CHUNTER", "Имя рабочей станции")
	locale := flags.String("locale", "1ru_RU", "Локаль протокола")
	timeout := flags.Duration("timeout", 30*time.Second, "Таймаут операции")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !*create {
		fmt.Fprintln(stderr, "Укажите --create для создания информационной базы")
		return 2
	}
	if !*confirmCreate {
		fmt.Fprintln(stderr, "Операция создаёт ИБ и базу данных. Для подтверждения укажите --confirm-create")
		return 2
	}
	if *target == "" || *agentPort < 1 || *agentPort > 65535 || *timeout <= 0 {
		fmt.Fprintln(stderr, "Укажите корректные --target, --agent-port и --timeout")
		return 2
	}
	if *dbPassword == "" {
		*dbPassword = os.Getenv("ONECHUNTER_DB_PASSWORD")
	}

	client := agent.Client{Locale: *locale}
	result, err := client.CreateInfoBase(context.Background(), net.JoinHostPort(*target, strconv.Itoa(*agentPort)),
		*username, os.Getenv("ONECHUNTER_AGENT_PASSWORD"), *workstation, agent.CreateInfoBaseConfig{
			ClusterName: *clusterName,
			ClusterPort: *clusterPort,
			Name:        *name,
			Description: *description,
			DBMS:        *dbms,
			DBServer:    *dbHost,
			DBName:      *dbName,
			DBUser:      *dbUser,
			DBPassword:  *dbPassword,
		}, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "Ошибка: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Кластер: %s\n", result.ClusterName)
	fmt.Fprintf(stdout, "Порт кластера: %d\n", result.ClusterPort)
	fmt.Fprintf(stdout, "Информационная база создана: %s\n", result.InfoBaseName)
	fmt.Fprintf(stdout, "Рабочий процесс: %s\n", result.WorkerEndpoint)
	return 0
}

func printInfoBaseUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Использование:")
	fmt.Fprintln(writer, "  1chunter infobase --create --target <HOST> --cluster <NAME> --name <IB_NAME> \\")
	fmt.Fprintln(writer, "    --dbms postgres --db-host <HOST> --db-name <DB_NAME> --db-user <USER> --confirm-create")
	fmt.Fprintln(writer, "  Пароль СУБД можно передать через ONECHUNTER_DB_PASSWORD")
}
