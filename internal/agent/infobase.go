package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CreateInfoBaseConfig struct {
	ClusterName string
	ClusterPort int
	Name        string
	Description string
	DBMS        string
	DBServer    string
	DBName      string
	DBUser      string
	DBPassword  string
}

type CreateInfoBaseResult struct {
	ClusterName    string
	ClusterPort    int
	InfoBaseName   string
	WorkerEndpoint string
}

var (
	agentCreateInfoBaseTemplate = []byte{
		0x41, 0x95, 0x35, 0x89, 0x12, 0x8c, 0x4f, 0xb3, 0x31, 0x40, 0x9b, 0x40, 0x30, 0xd7, 0xec, 0xd3, 0x91, 0xb9,
		0x8d, 0xa2, 0x06, 0x81, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43, 0xb7, 0x38, 0x58, 0xc7,
		0x72, 0xe3, 0xa0, 0xbf, 0x8b, 0x4c, 0x82, 0x84, 0x81, 0xcb, 0x23, 0x95, 0x32, 0x59, 0x13, 0xae, 0x94, 0x4f,
		0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15, 0xa9, 0x28, 0x48, 0xc2, 0x95, 0x5a, 0x9a, 0xb9, 0xb9, 0x94, 0xe3,
		0xbc, 0x41, 0xb0, 0x19, 0xb5, 0x59, 0xd4, 0xad, 0x7b, 0xad, 0x20, 0xa1, 0xcb, 0x53, 0x9a, 0x11,
		0x48, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x79, 0x5f, 0x74, 0x65, 0x73, 0x74,
		0xa1, 0xcb, 0x23, 0x95, 0x32, 0x59, 0x13, 0xae, 0x94, 0x4f, 0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15,
		0xa9, 0x28, 0x48, 0xc2, 0x95, 0xc2, 0x86, 0x18, 0x46, 0xfb, 0xb8, 0x63, 0x4e, 0xa2, 0x5f, 0xf8, 0x6d,
		0xbc, 0xda, 0x5d, 0x4a, 0x20, 0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
	}
	workerPrepareTemplate = []byte{
		0x41, 0x95, 0xd3, 0x82, 0x7e, 0xd3, 0xf9, 0xfd, 0xf7, 0x45, 0xa0, 0xb8, 0x81, 0x38, 0xee, 0x6a, 0x6e, 0x3b,
		0x8d, 0xf8, 0x34, 0x85, 0x95, 0x1f, 0xaa, 0x07, 0x76, 0x7e, 0xf8, 0xa2, 0x47, 0x8a, 0x6b, 0x70, 0x1c, 0x71,
		0x05, 0xca, 0x63, 0x8b, 0x0b, 0x84, 0x83, 0x81, 0xcb, 0x53, 0x81, 0xa1, 0xcb, 0x53, 0x81, 0x20, 0x20,
		0x66, 0x53, 0xb2, 0xa6,
	}
	workerCreatePrefix = []byte{
		0x41, 0x95, 0xd3, 0x82, 0x7e, 0xd3, 0xf9, 0xfd, 0xf7, 0x45, 0xa0, 0xb8, 0x81, 0x38, 0xee, 0x6a, 0x6e, 0x3b,
		0x8d, 0xf9, 0x34, 0x81, 0x85, 0x95, 0x1f, 0xaa, 0x07, 0x76, 0x7e, 0xf8, 0xa2, 0x47, 0x8a, 0x6b, 0x70, 0x1c, 0x71,
		0x05, 0xca, 0x63, 0x89, 0x82, 0x83, 0x81, 0xcb, 0x53,
	}
	workerCreateSuffix = []byte{
		0xa1, 0xcb, 0x23, 0x95, 0x33, 0xdc, 0x5e, 0xba, 0x36, 0x89, 0x12, 0x42, 0x9e, 0xd2, 0x48, 0x5e, 0x75, 0x92,
		0x03, 0xaa, 0x82, 0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
	}
	workerPortPattern = regexp.MustCompile(`:(\d{1,5})`)
)

func (client Client) CreateInfoBase(ctx context.Context, endpoint, username, password, workstation string, config CreateInfoBaseConfig, timeout time.Duration) (CreateInfoBaseResult, error) {
	var result CreateInfoBaseResult
	if err := validateCreateInfoBaseConfig(&config); err != nil {
		return result, err
	}
	inspection, err := client.Authenticate(ctx, endpoint, username, password, workstation, timeout)
	if err != nil {
		return result, err
	}
	if !inspection.Accepted {
		return result, fmt.Errorf("аутентификация ragent не выполнена")
	}

	var cluster *ClusterInfo
	for index := range inspection.Clusters {
		if inspection.Clusters[index].Name == config.ClusterName {
			cluster = &inspection.Clusters[index]
			break
		}
	}
	if cluster == nil {
		return result, fmt.Errorf("кластер %q не найден", config.ClusterName)
	}
	if cluster.AdminStatus != ClusterAdminAbsent {
		return result, fmt.Errorf("создание разрешено только при отсутствии администратора кластера; текущий статус: %s", cluster.AdminStatus)
	}
	if config.ClusterPort == 0 {
		if cluster.Port == 0 {
			return result, fmt.Errorf("порт кластера %q не определён; укажите --cluster-port", config.ClusterName)
		}
		config.ClusterPort = cluster.Port
	}
	client.PlatformVersion = inspection.PlatformVersion

	agentSession, authResult, err := client.openSession(ctx, endpoint, username, password, workstation, timeout)
	if err != nil {
		return result, err
	}
	if agentSession == nil {
		return result, fmt.Errorf("аутентификация ragent не выполнена: %s", authResult.Detail)
	}
	defer agentSession.connection.Close()
	if _, _, _, err := checkAdminAccessWithFlag(agentSession.connection, agentSession.reader, agentSession.authenticationFrame, client.PlatformVersion, 0x34); err != nil {
		return result, fmt.Errorf("подготовка кластера к созданию ИБ: %w", err)
	}

	agentRequest := buildAgentCreateInfoBaseRequest(agentSession.id, cluster.ID, config.Name)
	if _, err := agentSession.connection.Write(agentRequest); err != nil {
		return result, fmt.Errorf("запрос создания ИБ в кластере: %w", err)
	}
	agentResponse, err := agentSession.reader.readFrame(maxProtocolFrame)
	if err != nil {
		return result, fmt.Errorf("ответ кластера на создание ИБ: %w", err)
	}
	workerEndpoint, err := workerEndpoint(endpoint, agentResponse)
	if err != nil {
		return result, err
	}

	workerSession, authResult, err := client.openSessionWithProfile(ctx, workerEndpoint, username, password, workstation, timeout, workerSessionProfile)
	if err != nil {
		return result, fmt.Errorf("подключение к рабочему процессу %s: %w", workerEndpoint, err)
	}
	if workerSession == nil {
		return result, fmt.Errorf("аутентификация рабочего процесса не выполнена: %s", authResult.Detail)
	}
	defer workerSession.connection.Close()
	if err := bindAdminSession(workerSession, "7607aa1f-f87e-47a2-8a6b-701c7105ca63"); err != nil {
		return result, err
	}
	if _, err := workerSession.connection.Write(withSessionID(workerPrepareTemplate, workerSession.id)); err != nil {
		return result, fmt.Errorf("подготовка рабочего процесса: %w", err)
	}
	prepareResponse, err := workerSession.reader.readFrame(maxProtocolFrame)
	if err != nil {
		return result, fmt.Errorf("ответ подготовки рабочего процесса: %w", err)
	}
	if detail := responseDetail(prepareResponse); detail != "" {
		return result, fmt.Errorf("подготовка рабочего процесса отклонена: %s", detail)
	}

	workerRequest, err := buildWorkerCreateInfoBaseRequest(workerSession.id, endpoint, config)
	if err != nil {
		return result, err
	}
	if _, err := workerSession.connection.Write(workerRequest); err != nil {
		return result, fmt.Errorf("передача параметров ИБ: %w", err)
	}
	workerResponse, err := workerSession.reader.readFrame(maxProtocolFrame)
	if err != nil {
		return result, fmt.Errorf("ответ рабочего процесса на создание ИБ: %w", err)
	}
	if detail := responseDetail(workerResponse); detail != "" {
		return result, fmt.Errorf("создание ИБ отклонено: %s", detail)
	}

	result = CreateInfoBaseResult{ClusterName: cluster.Name, ClusterPort: config.ClusterPort, InfoBaseName: config.Name, WorkerEndpoint: workerEndpoint}
	return result, nil
}

func validateCreateInfoBaseConfig(config *CreateInfoBaseConfig) error {
	if config.ClusterPort < 0 || config.ClusterPort > 65535 {
		return fmt.Errorf("некорректный порт кластера")
	}
	for name, value := range map[string]string{
		"кластер": config.ClusterName, "имя ИБ": config.Name, "сервер СУБД": config.DBServer,
		"имя БД": config.DBName, "пользователь СУБД": config.DBUser,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("не указано: %s", name)
		}
	}
	if len(config.Name) > 255 {
		return fmt.Errorf("имя ИБ слишком длинное")
	}
	switch strings.ToLower(config.DBMS) {
	case "postgres", "postgresql":
		config.DBMS = "PostgreSQL"
	case "mssql", "sqlserver":
		config.DBMS = "MSSQL"
	default:
		return fmt.Errorf("поддерживаются только СУБД postgres и mssql")
	}
	return nil
}

func bindAdminSession(session *adminSession, interfaceID string) error {
	packet := append([]byte{}, utf8BOM...)
	packet = append(packet, []byte(fmt.Sprintf("{0,%s,13559,1,%s}", session.id, interfaceID))...)
	packet = append(packet, MessageEnd...)
	if _, err := session.connection.Write(packet); err != nil {
		return fmt.Errorf("привязка AdminProcess: %w", err)
	}
	response, err := session.reader.readFrame(maxProtocolFrame)
	if err != nil {
		return fmt.Errorf("ответ привязки AdminProcess: %w", err)
	}
	if bytes.Contains(response, []byte("Сеанс работы завершен")) {
		return fmt.Errorf("привязка AdminProcess отклонена: сеанс работы завершен")
	}
	if detail := responseDetail(response); detail != "" {
		return fmt.Errorf("привязка AdminProcess отклонена: %s", detail)
	}
	return nil
}

func buildAgentCreateInfoBaseRequest(sessionID string, clusterID []byte, name string) []byte {
	request := withSessionID(agentCreateInfoBaseTemplate, sessionID)
	if len(clusterID) == 16 {
		copy(request[66:82], clusterID)
	}
	request[19] = 0xf3
	request[20] = 0x34
	oldName := append([]byte{0x9a, 0x11}, []byte("Hunter_relay_test")...)
	newName := append([]byte{0x9a, byte(len(name))}, []byte(name)...)
	request = bytes.Replace(request, oldName, newName, 1)
	randomizeRequestSuffix(request)
	return request
}

func buildWorkerCreateInfoBaseRequest(sessionID, agentEndpoint string, config CreateInfoBaseConfig) ([]byte, error) {
	host, _, err := net.SplitHostPort(agentEndpoint)
	if err != nil {
		return nil, fmt.Errorf("разбор адреса ragent: %w", err)
	}
	quote := func(value string) string {
		return strings.ReplaceAll(value, `"`, `""`)
	}
	connectionString := fmt.Sprintf(
		`Srvr="%s";Ref="%s";SLev=0;Descr="%s";DBSrvr="%s";DBMS="%s";DB="%s";DBUID="%s";DBPwd="%s";Locale="ru_RU";SQLYOffs=0;LicDstr=Y`,
		quote(net.JoinHostPort(host, strconv.Itoa(config.ClusterPort))), quote(config.Name), quote(config.Description),
		quote(config.DBServer), quote(config.DBMS), quote(config.DBName), quote(config.DBUser), quote(config.DBPassword),
	)
	if len(connectionString) > 255 {
		return nil, fmt.Errorf("строка параметров ИБ слишком длинная: %d байт", len(connectionString))
	}
	request := withSessionID(workerCreatePrefix, sessionID)
	request[19] = 0xf9
	request = append(request, 0x9a, byte(len(connectionString)))
	request = append(request, []byte(connectionString)...)
	request = append(request, workerCreateSuffix...)
	return request, nil
}

func randomizeRequestSuffix(request []byte) {
	if len(request) < 23 {
		return
	}
	_, _ = rand.Read(request[len(request)-23 : len(request)-7])
	request[len(request)-16] = request[len(request)-16]&0x0f | 0x40
	request[len(request)-15] = request[len(request)-15]&0x3f | 0x80
}

func responseDetail(data []byte) string {
	var details []string
	for _, run := range textRuns(data) {
		if run == "" || strings.Contains(run, ".dll:") {
			continue
		}
		details = append(details, run)
		if len(details) == 2 {
			break
		}
	}
	return strings.Join(details, "; ")
}

func workerEndpoint(agentEndpoint string, response []byte) (string, error) {
	if detail := firstTextRun(response); isAccessFailure(detail) {
		return "", fmt.Errorf("создание ИБ в кластере отклонено: %s", detail)
	}
	matches := workerPortPattern.FindAllStringSubmatch(string(response), -1)
	if len(matches) == 0 {
		if detail := responseDetail(response); detail != "" {
			return "", fmt.Errorf("создание ИБ в кластере отклонено: %s", detail)
		}
		return "", fmt.Errorf("сервер не вернул адрес рабочего процесса")
	}
	port, err := strconv.Atoi(matches[0][1])
	if err != nil || port < 1 || port > 65535 {
		if detail := responseDetail(response); detail != "" {
			return "", fmt.Errorf("создание ИБ в кластере отклонено: %s", detail)
		}
		return "", fmt.Errorf("некорректный порт рабочего процесса")
	}
	host, _, err := net.SplitHostPort(agentEndpoint)
	if err != nil {
		return "", fmt.Errorf("разбор адреса ragent: %w", err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
