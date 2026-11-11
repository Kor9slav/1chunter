package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type thickSession struct {
	connection net.Conn
	reader     *frameReader
	id         string
	token      string
}

type thickProfile struct {
	service       string
	objectID      string
	finalObjectID string
	sequence      int
}

var thickClientTransportPrefix = []byte{
	0x22, 0x48, 0x55, 0xb5, 0x83, 0xb7, 0xa2, 0xcb, 0x15, 0xe1,
	0x55, 0x4e, 0xbd, 0x12, 0x19, 0xa4, 0x0c, 0xa9, 0xd4, 0x13,
}

func connectThickCluster(ctx context.Context, endpoint, infoBase, platformVersion, workstation string, timeout time.Duration) (string, error) {
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return "", fmt.Errorf("подключение к менеджеру кластера: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := exchangeGreeting(connection); err != nil {
		return "", err
	}
	if _, err := connection.Write(thickClientTransportPrefix); err != nil {
		return "", err
	}
	reader := newFrameReader(bufio.NewReader(connection))
	profile := thickProfile{
		service: "RegMngrCntxt:RegMngrCntxt", objectID: "4ecea39c-b4c9-453e-aed0-ce8a24cc71c2",
		finalObjectID: "00000000-0000-0000-0000-000000000000", sequence: 21185,
	}
	profileData, err := exchangeThickRSA(connection, reader, profile, workstation, "", platformVersion)
	if err != nil {
		return "", err
	}
	ids := uuidPattern.FindAllString(string(profileData), -1)
	sessionID := ""
	for index, id := range ids {
		if id == "3ace6d91-51bb-4344-9388-c8105ad4ad11" && index+1 < len(ids) {
			sessionID = ids[index+1]
			break
		}
	}
	if sessionID == "" {
		return "", fmt.Errorf("идентификатор сеанса менеджера не найден")
	}
	if err := writeThickText(connection, fmt.Sprintf("{0,%s,%d,1,73b7d3a3-fe0b-4fdf-ba70-b74b3589ffc3}", sessionID, profile.sequence+1)); err != nil {
		return "", err
	}
	bindResponse, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return "", err
	}
	if strings.Contains(string(bindResponse), "Сеанс работы завершен") {
		return "", fmt.Errorf("привязка менеджера кластера отклонена: %s", bindResponse)
	}
	request := fmt.Sprintf("{0,%s,%d,4,73b7d3a3-fe0b-4fdf-ba70-b74b3589ffc3,0,3,9,0,\r\n"+
		"{\"S\",\"\"},0,\r\n{\"S\",\"\"},0,\r\n{\"S\",\"%s\"},0,\r\n{\"S\",\"1CV8C\"},0,\r\n"+
		"{\"#\",ae135932-4f94-44df-92c1-c91f15a92848,\r\n{1,9046c003-9d0b-4436-94d4-5f7f9def4cad}\r\n},0,\r\n"+
		"{\"S\",\"\"},0,\r\n{\"S\",\"\"},1,1}", sessionID, profile.sequence+2, infoBase)
	if err := writeThickText(connection, request); err != nil {
		return "", err
	}
	response, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return "", err
	}
	worker, err := workerEndpoint(endpoint, response)
	if err != nil {
		return "", fmt.Errorf("%w (ответ %x)", err, response)
	}
	_ = writeThickText(connection, fmt.Sprintf("{0,%s,%d,0}", sessionID, profile.sequence+3))
	_, _ = reader.readFrame(maxProtocolFrame)
	return worker, nil
}

func openThickWorker(ctx context.Context, endpoint, infoBase, username, password, workstation, platformVersion string, timeout time.Duration) (*thickSession, error) {
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("подключение к рабочему процессу: %w", err)
	}
	keepConnection := false
	defer func() {
		if !keepConnection {
			_ = connection.Close()
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := exchangeGreeting(connection); err != nil {
		return nil, err
	}
	if _, err := connection.Write(thickClientTransportPrefix); err != nil {
		return nil, err
	}
	reader := newFrameReader(bufio.NewReader(connection))
	finalObjectID, err := newProtocolUUID()
	if err != nil {
		return nil, err
	}
	profile := thickProfile{
		service: infoBase + ":" + infoBase, objectID: "1e01900d-82fd-413a-bfe5-571a4c30a685",
		finalObjectID: finalObjectID, sequence: 21189,
	}
	_, err = exchangeThickRSA(connection, reader, profile, workstation, username, platformVersion)
	if err != nil {
		return nil, err
	}

	negotiate := append([]byte(nil), windowsNegotiate...)
	negotiate[15] &^= 0x40
	if err := writeThickText(connection, buildThickAuthenticationRequest(negotiate, profile, workstation, username, platformVersion, profile.sequence+1)); err != nil {
		return nil, err
	}
	challengeFrame, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, err
	}
	challenge, err := decodeBase64Block(challengeFrame)
	if err != nil {
		return nil, err
	}
	authenticate := buildNTLMAnonymousAuthenticate(negotiate, challenge)
	if password != "" {
		authenticate, err = buildNTLMKeyExchangeAuthenticate(negotiate, challenge, username, password, workstation)
		if err != nil {
			return nil, err
		}
	}
	if err := writeThickText(connection, buildThickAuthenticationRequest(authenticate, profile, workstation, username, platformVersion, profile.sequence+2)); err != nil {
		return nil, err
	}
	resultFrame, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(resultFrame), "{\"B\",1}") {
		return nil, fmt.Errorf("сервер отклонил NTLM-аутентификацию")
	}
	ids := uuidPattern.FindAllString(string(resultFrame), -1)
	sessionID := ""
	for index, id := range ids {
		if id == "3ace6d91-51bb-4344-9388-c8105ad4ad11" && index+1 < len(ids) {
			sessionID = ids[index+1]
			break
		}
	}

	if sessionID == "" {
		return nil, fmt.Errorf("рабочий процесс не вернул идентификатор сеанса")
	}
	if err := writeThickText(connection, fmt.Sprintf("{0,%s,%d,1,bc15bd01-10bf-413c-a856-ddc907fcd123}", sessionID, profile.sequence+3)); err != nil {
		return nil, err
	}
	if _, err := reader.readFrame(maxProtocolFrame); err != nil {
		return nil, err
	}
	keepConnection = true
	return &thickSession{connection: connection, reader: reader, id: sessionID}, nil
}

func exchangeThickRSA(connection net.Conn, reader *frameReader, profile thickProfile, workstation, username, platformVersion string) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	modulus := make([]byte, 128)
	privateKey.PublicKey.N.FillBytes(modulus)
	if _, err := connection.Write(buildThickInitialRequest(modulus, profile, workstation, username, platformVersion)); err != nil {
		return nil, err
	}
	response, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, err
	}
	return decryptServerProfileData(privateKey, response)
}

func buildThickInitialRequest(modulus []byte, profile thickProfile, workstation, username, platformVersion string) []byte {
	authentication := "{}"
	if username != "" {
		authentication = fmt.Sprintf("{%s}", encodeBase64(buildIntroTicket(username)))
	}
	body := fmt.Sprintf("\"n\",\r\n{#base64:%s},\r\n{#base64:AQAB}", encodeBase64(modulus))
	request := fmt.Sprintf("{0,%s,%d,4,%s,0,1,11,0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,%s}\r\n},0,\r\n"+
		"{\"S\",\"1CV8C\"},0,\r\n"+
		"{\"S\",\"%s\"},2,\r\n"+
		"{\"#\",%s,\r\n%s\r\n},1,0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"S\",\"1ru_RU\"},0,\r\n"+
		"{\"S\",\"1ru_RU\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,%s}\r\n},1}",
		creatorID, profile.sequence, adminProcessInterface, profile.service, adminProcessClass, profile.objectID,
		workstation, authenticationClass, authentication, platformVersion, adminProcessClass, profile.finalObjectID)
	packet := []byte{0xd6, 0x00}
	packet = append(packet, utf8BOM...)
	packet = append(packet, []byte(body)...)
	packet = append(packet, utf8BOM...)
	packet = append(packet, []byte(request)...)
	packet = append(packet, MessageEnd...)
	return packet
}

func buildThickAuthenticationRequest(token []byte, profile thickProfile, workstation, username, platformVersion string, sequence int) string {
	return fmt.Sprintf("{0,%s,%d,4,%s,0,1,11,0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,%s}\r\n},0,\r\n"+
		"{\"S\",\"1CV8C\"},0,\r\n"+
		"{\"S\",\"%s\"},2,\r\n"+
		"{\"#\",%s,\r\n{%s}\r\n},1,0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"S\",\"1ru_RU\"},0,\r\n"+
		"{\"S\",\"1ru_RU\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,%s}\r\n},1}",
		creatorID, sequence, adminProcessInterface, profile.service, adminProcessClass, profile.objectID,
		workstation, authenticationClass, encodeBase64(token), platformVersion, adminProcessClass, profile.finalObjectID)
}

func writeThickText(connection net.Conn, request string) error {
	packet := append([]byte{}, utf8BOM...)
	packet = append(packet, []byte(request)...)
	packet = append(packet, MessageEnd...)
	_, err := connection.Write(packet)
	return err
}

func newProtocolUUID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	data[6] = data[6]&0x0f | 0x40
	data[8] = data[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", data[0:4], data[4:6], data[6:8], data[8:10], data[10:16]), nil
}

func thickWorkerPort(endpoint string, port int) string {
	host, _, _ := net.SplitHostPort(endpoint)
	return net.JoinHostPort(host, strconv.Itoa(port))
}
