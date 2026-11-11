package agent

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

const maxProtocolFrame = 4 * 1024 * 1024

type Client struct {
	Dial            DialContext
	PlatformVersion string
	Locale          string
}

type InfoBaseInfo struct {
	Name        string
	Description string
}

type ClusterAdminStatus string

const (
	ClusterAdminUnknown ClusterAdminStatus = "НЕ ОПРЕДЕЛЁН"
	ClusterAdminPresent ClusterAdminStatus = "УСТАНОВЛЕН"
	ClusterAdminAbsent  ClusterAdminStatus = "ОТСУТСТВУЕТ"
)

type ClusterInfo struct {
	ID          []byte
	Name        string
	Port        int
	AdminStatus ClusterAdminStatus
	InfoBases   []InfoBaseInfo
}

type AuthResult struct {
	Accepted            bool
	Detail              string
	PlatformVersion     string
	ClusterName         string
	InfoBaseName        string
	InfoBaseDescription string
	Clusters            []ClusterInfo
	AdminStatus         AdminStatus
	AdminDetail         string
}

func (client Client) Authenticate(ctx context.Context, endpoint, username, password, workstation string, timeout time.Duration) (AuthResult, error) {
	requestedVersion := client.PlatformVersion
	result, err := client.authenticateOnce(ctx, endpoint, username, password, workstation, timeout)
	if err != nil || result.Accepted || requestedVersion != "" || result.PlatformVersion == "" {
		return result, err
	}
	client.PlatformVersion = result.PlatformVersion
	return client.authenticateOnce(ctx, endpoint, username, password, workstation, timeout)
}

type adminSession struct {
	connection          net.Conn
	reader              *frameReader
	authenticationFrame []byte
	id                  string
}

type sessionProfile struct {
	objectID string
	sequence int
}

var (
	agentSessionProfile  = sessionProfile{objectID: "bc9113bc-5b88-4c9f-9fc0-ff7ade5450f0", sequence: 16683}
	workerSessionProfile = sessionProfile{objectID: "a2c6af52-7d8b-46ef-9a69-cb1fa650e4f5", sequence: 13556}
)

func (client Client) authenticateOnce(ctx context.Context, endpoint, username, password, workstation string, timeout time.Duration) (AuthResult, error) {
	session, result, err := client.openSession(ctx, endpoint, username, password, workstation, timeout)
	if session == nil {
		return result, err
	}
	defer session.connection.Close()

	result.Detail = "сервер принял NTLM-аутентификацию"
	clusters, adminStatus, adminDetail, err := checkAdminAccess(session.connection, session.reader, session.authenticationFrame, client.PlatformVersion)
	result.Clusters = clusters
	if len(clusters) > 0 {
		result.ClusterName = clusters[0].Name
		if len(clusters[0].InfoBases) > 0 {
			result.InfoBaseName = clusters[0].InfoBases[0].Name
			result.InfoBaseDescription = clusters[0].InfoBases[0].Description
		}
	}
	result.AdminStatus = adminStatus
	result.AdminDetail = adminDetail
	if err != nil {
		return result, err
	}
	return result, nil
}

func (client Client) openSession(ctx context.Context, endpoint, username, password, workstation string, timeout time.Duration) (*adminSession, AuthResult, error) {
	return client.openSessionWithProfile(ctx, endpoint, username, password, workstation, timeout, agentSessionProfile)
}

func (client Client) openSessionWithProfile(ctx context.Context, endpoint, username, password, workstation string, timeout time.Duration, profile sessionProfile) (*adminSession, AuthResult, error) {
	if client.Locale == "" {
		client.Locale = "1ru_RU"
	}
	connection, err := client.connect(ctx, endpoint, timeout)
	if err != nil {
		return nil, AuthResult{}, err
	}
	keepConnection := false
	defer func() {
		if !keepConnection {
			_ = connection.Close()
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(timeout))

	if err := exchangeGreeting(connection); err != nil {
		return nil, AuthResult{}, err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, AuthResult{}, fmt.Errorf("генерация RSA-ключа: %w", err)
	}
	modulus := make([]byte, 128)
	privateKey.PublicKey.N.FillBytes(modulus)
	sessionID := creatorID

	reader := newFrameReader(bufio.NewReader(connection))
	initial := buildInitialRequest(modulus, sessionID, workstation, username, client.PlatformVersion, client.Locale, profile.objectID, profile.sequence)
	if _, err := connection.Write(initial); err != nil {
		return nil, AuthResult{}, fmt.Errorf("отправка RSA-профиля: %w", err)
	}
	response, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, AuthResult{}, fmt.Errorf("чтение ответа RSA: %w", err)
	}
	if err := decryptServerProfile(privateKey, response); err != nil {
		return nil, AuthResult{}, err
	}

	negotiate := append([]byte(nil), windowsNegotiate...)
	if password != "" {
		negotiate[15] &^= 0x40
	}
	if _, err := connection.Write(buildAuthenticationRequest(negotiate, sessionID, workstation, client.PlatformVersion, client.Locale, profile.objectID, profile.sequence+1)); err != nil {
		return nil, AuthResult{}, fmt.Errorf("отправка NTLM Negotiate: %w", err)
	}
	challengeFrame, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, AuthResult{}, fmt.Errorf("чтение NTLM Challenge: %w", err)
	}
	challenge, err := decodeBase64Block(challengeFrame)
	if err != nil {
		return nil, AuthResult{}, fmt.Errorf("разбор NTLM Challenge: %w (кадр %d байт, префикс %x)", err, len(challengeFrame), challengeFrame[:min(16, len(challengeFrame))])
	}
	authenticate := anonymousAuthenticate
	if password != "" {
		authenticate, err = ntlmssp.ProcessChallenge(challenge, username, password, false)
		if err != nil {
			return nil, AuthResult{}, fmt.Errorf("формирование NTLM Authenticate: %w", err)
		}
	}
	if _, err := connection.Write(buildAuthenticationRequest(authenticate, sessionID, workstation, client.PlatformVersion, client.Locale, profile.objectID, profile.sequence+2)); err != nil {
		return nil, AuthResult{}, fmt.Errorf("отправка NTLM Authenticate: %w", err)
	}
	resultFrame, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, AuthResult{}, fmt.Errorf("чтение результата NTLM: %w", err)
	}

	accepted := strings.Contains(string(resultFrame), "{\"B\",1}")
	detail := "сервер отклонил NTLM-аутентификацию"
	result := AuthResult{Accepted: accepted, Detail: detail, PlatformVersion: client.PlatformVersion, AdminStatus: AdminUnknown}
	if !accepted && result.PlatformVersion == "" {
		result.PlatformVersion = detectServerVersion(resultFrame)
	}
	if !accepted {
		return nil, result, nil
	}
	ids := uuidPattern.FindAllString(string(resultFrame), -1)
	adminSessionID := ""
	for index, id := range ids {
		if id == "3ace6d91-51bb-4344-9388-c8105ad4ad11" && index+1 < len(ids) {
			adminSessionID = ids[index+1]
			break
		}
	}
	if adminSessionID == "" {
		return nil, result, fmt.Errorf("сервер не вернул идентификатор сеанса AdminProcess")
	}
	keepConnection = true
	return &adminSession{connection: connection, reader: reader, authenticationFrame: resultFrame, id: adminSessionID}, result, nil
}

func detectServerVersion(frame []byte) string {
	matches := regexp.MustCompile(`\b\d+\.\d+\.\d+\.\d+\b`).FindAllString(string(frame), -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

func (client Client) connect(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	dial := client.Dial
	if dial == nil {
		dialer := &net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}
	connection, err := dial(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("подключение к %s: %w", endpoint, err)
	}
	return connection, nil
}

func exchangeGreeting(connection net.Conn) error {
	greeting := make([]byte, len(TransportGreeting))
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return fmt.Errorf("чтение приветствия ragent: %w", err)
	}
	if string(greeting) != string(TransportGreeting) {
		return fmt.Errorf("неожиданная сигнатура ragent: %x", greeting)
	}
	return nil
}

func decryptServerProfile(privateKey *rsa.PrivateKey, response []byte) error {
	plain, err := decryptServerProfileData(privateKey, response)
	if err != nil {
		return err
	}
	if !strings.Contains(string(plain), "RHostRoot") {
		return fmt.Errorf("не удалось проверить расшифрованный профиль сервера")
	}
	return nil
}

func decryptServerProfileData(privateKey *rsa.PrivateKey, response []byte) ([]byte, error) {
	encrypted, err := decodeBase64Block(response)
	if err != nil {
		return nil, fmt.Errorf("разбор RSA-профиля: %w", err)
	}
	profile, err := rsa.DecryptPKCS1v15(nil, privateKey, encrypted)
	if err != nil {
		return nil, fmt.Errorf("расшифровка RSA-профиля: %w", err)
	}
	parts := base64Pattern.FindAllSubmatch(profile, -1)
	if len(parts) < 2 {
		return nil, fmt.Errorf("неполный профиль 3DES")
	}
	key, err := decodeBase64Value(parts[0][1])
	if err != nil {
		return nil, fmt.Errorf("разбор ключа 3DES: %w", err)
	}
	iv, err := decodeBase64Value(parts[1][1])
	if err != nil {
		return nil, fmt.Errorf("разбор IV 3DES: %w", err)
	}
	if len(key) != 24 || len(iv) != des.BlockSize {
		return nil, fmt.Errorf("неожиданные размеры ключа и IV 3DES: %d и %d", len(key), len(iv))
	}
	match := base64Pattern.FindIndex(response)
	encryptedProfile := response[match[1] : len(response)-len(MessageEnd)]
	if len(encryptedProfile)%des.BlockSize != 0 {
		return nil, fmt.Errorf("некорректный размер зашифрованного профиля: %d", len(encryptedProfile))
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("инициализация 3DES: %w", err)
	}
	plain := make([]byte, len(encryptedProfile))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encryptedProfile)
	return plain, nil
}

func decodeBase64Value(value []byte) ([]byte, error) {
	return decodeBase64Block(append([]byte("{#base64:"), append(value, '}')...))
}
