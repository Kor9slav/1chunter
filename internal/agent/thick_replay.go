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
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

//go:embed thick_frames.json
var thickFramesJSON []byte

//go:embed thick_frames_v23.json
var thickFramesV23JSON []byte

var (
	vrsSessionPattern     = regexp.MustCompile(`vrs-session: [A-Za-z0-9+/=]+`)
	contentLengthPattern  = regexp.MustCompile(`Content-Length: \d+`)
	textContentPattern    = regexp.MustCompile(`(?s)<textContent>(.*?)</textContent>`)
	descriptionPattern    = regexp.MustCompile(`(?s)<descr[^>]*>(.*?)</descr>`)
	remoteKeyPattern      = regexp.MustCompile(`(?i)<remotekey>([0-9a-f-]{36})`)
	formVersionPattern    = regexp.MustCompile(`(?i)v.{0,3}=.{0,3}"`)
	moduleVersionPattern  = regexp.MustCompile(`(?i)version.{0,10}=.{0,10}'`)
	vrsStatPattern        = regexp.MustCompile(`vrs-stat: [^\r\n]+\r\n`)
	sessionErrorIDPattern = regexp.MustCompile(`ID=([0-9a-fA-F-]{36})`)
)

type thickCodec interface {
	Decode(data []byte) ([]byte, error)
	Encode(data []byte) ([]byte, error)
}

type zstdCodec struct {
	decoder *zstd.Decoder
	encoder *zstd.Encoder
}

func (codec zstdCodec) Decode(data []byte) ([]byte, error) {
	return codec.decoder.DecodeAll(data, nil)
}

func (codec zstdCodec) Encode(data []byte) ([]byte, error) {
	return codec.encoder.EncodeAll(data, nil), nil
}

type lz4Codec struct{}

func (lz4Codec) Decode(data []byte) ([]byte, error) {
	return io.ReadAll(lz4.NewReader(bytes.NewReader(data)))
}

func (lz4Codec) Encode(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := lz4.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func newThickCodec(platformVersion string) (thickCodec, error) {
	if strings.HasPrefix(platformVersion, "8.3.23.") {
		return lz4Codec{}, nil
	}
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		decoder.Close()
		return nil, err
	}
	return zstdCodec{decoder: decoder, encoder: encoder}, nil
}

type ExecuteCommandConfig struct {
	ClusterName string
	ClusterPort int
	WorkerPort  int
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

	var workerEndpoints []string
	if config.WorkerPort > 0 {
		workerEndpoints = []string{thickWorkerPort(endpoint, config.WorkerPort)}
	} else {
		clusterEndpoint := thickWorkerPort(endpoint, config.ClusterPort)
		workerEndpoint, connectErr := connectThickCluster(ctx, clusterEndpoint, config.InfoBase, inspection.PlatformVersion, workstation, timeout)
		if connectErr == nil {
			workerEndpoints = []string{workerEndpoint}
		} else {
			workerEndpoints = availableThickWorkerEndpoints(ctx, endpoint, config.ClusterPort, timeout)
			if len(workerEndpoints) == 0 {
				ports := thickWorkerPorts(config.ClusterPort)
				return result, fmt.Errorf("рабочий процесс не найден в диапазоне %d–%d", ports[0], ports[len(ports)-1])
			}
		}
	}

	var lastErr error
	for _, workerEndpoint := range workerEndpoints {
		openTimeout := timeout
		if len(workerEndpoints) > 1 {
			openTimeout = min(timeout, 10*time.Second)
		}
		session, openErr := openThickWorker(ctx, workerEndpoint, config.InfoBase, username, password, workstation, inspection.PlatformVersion, openTimeout)
		if openErr != nil {
			lastErr = openErr
			continue
		}
		output, replayErr := replayThickSession(session, config.Command, workerEndpoint, config.InfoBase, inspection.PlatformVersion)
		_ = session.connection.Close()
		if replayErr == nil {
			result.WorkerEndpoint = workerEndpoint
			result.Output = output
			return result, nil
		}
		if !strings.Contains(strings.ToLower(replayErr.Error()), "информационная база") || !strings.Contains(strings.ToLower(replayErr.Error()), "не обнаружена") {
			return result, replayErr
		}
		lastErr = replayErr
	}
	return result, fmt.Errorf("не удалось подключиться к ИБ %q через найденные рабочие процессы: %w", config.InfoBase, lastErr)
}

func replayThickSession(session *thickSession, command, workerEndpoint, infoBase, platformVersion string) (string, error) {
	targetHost, _, err := net.SplitHostPort(workerEndpoint)
	if err != nil {
		return "", err
	}
	if len(targetHost) != len("192.168.153.132") {
		return "", fmt.Errorf("подмена адреса relay в кадрах не поддерживается")
	}
	framesJSON := thickFramesJSON
	if strings.HasPrefix(platformVersion, "8.3.23.") {
		framesJSON = thickFramesV23JSON
	}
	encodedFrames := make([]string, 0, 32)
	if err := json.Unmarshal(framesJSON, &encodedFrames); err != nil {
		return "", err
	}
	decoder, err := newThickCodec(platformVersion)
	if err != nil {
		return "", err
	}
	encoder := decoder
	if codec, ok := decoder.(zstdCodec); ok {
		defer codec.decoder.Close()
		defer codec.encoder.Close()
	}

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
		frame = vrsStatPattern.ReplaceAll(frame, nil)
		frame = bytes.ReplaceAll(frame, []byte("192.168.153.132"), []byte(targetHost))
		frame = bytes.ReplaceAll(frame, []byte("infosec"), []byte(infoBase))
		frame = bytes.ReplaceAll(frame, []byte("8.3.27.1786"), []byte(platformVersion))
		compressedCall := isCommandFrame(frame)
		if !compressedCall {
			frame = bytes.ReplaceAll(frame, []byte("4d9ff3b8edfe324481f5cd7e62f880d2"), []byte(formVersion))
			frame = bytes.ReplaceAll(frame, []byte("71cd0942ce7bda4fa0ed0492276effa2"), []byte(formVersion))
			frame = bytes.ReplaceAll(frame, []byte("66ef1366bf7d1f4f85ae9ddfe24f65d5"), []byte(moduleVersion))
			frame = bytes.ReplaceAll(frame, []byte("b582d9504dbd964182177c8945f55156"), []byte(moduleVersion))
			frame = bytes.ReplaceAll(frame, []byte("03FB8707-3A8E-4C4C-AD75-8B18BA7F7D47"), []byte(strings.ToUpper(remoteKey)))
			frame = bytes.ReplaceAll(frame, []byte("03fb8707-3a8e-4c4c-ad75-8b18ba7f7d47"), []byte(strings.ToLower(remoteKey)))
			frame = bytes.ReplaceAll(frame, []byte("F2BFDD48-85C7-475D-9045-DAB9BC86839A"), []byte(strings.ToUpper(remoteKey)))
			frame = bytes.ReplaceAll(frame, []byte("f2bfdd48-85c7-475d-9045-dab9bc86839a"), []byte(strings.ToLower(remoteKey)))
		}
		if session.token != "" {
			frame = vrsSessionPattern.ReplaceAll(frame, []byte("vrs-session: "+session.token))
		}
		frame = updateThickFrameLength(frame)
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
				if version := compressedHexVersion(response, formVersionPattern); version != "" {
					formVersion = version
				}
				if version := compressedHexVersion(response, moduleVersionPattern); version != "" {
					moduleVersion = version
				}
			}
		}
		if session.token == "" {
			if match := vrsSessionPattern.Find(response); match != nil {
				session.token = strings.TrimPrefix(string(match), "vrs-session: ")
			}
			if session.token == "" {
				if bytes.Contains(response, []byte("Информационная база не обнаружена")) {
					return "", fmt.Errorf("информационная база %q не обнаружена на рабочем процессе", infoBase)
				}
				return "", fmt.Errorf("сервер не вернул vrs-session: %s", extractCommandError(response, decoder))
			}
		}
		if commandFrame {
			lastOutput = extractCommandOutput(response, decoder)
			if lastOutput == "" {
				if match := sessionErrorIDPattern.FindSubmatch(response); match != nil {
					remoteKey = string(match[1])
				}
			}
			if lastOutput != "" {
				return lastOutput, nil
			}
			if commandResponses > 1 {
				return "", fmt.Errorf("команда отклонена сервером: %s (rKey %s, version %s)", extractCommandError(response, decoder), remoteKey, formVersion)
			}
		}
	}
	if commandResponses != 2 {
		return "", fmt.Errorf("не удалось сформировать вызов команды: командных кадров %d", commandResponses)
	}
	return lastOutput, nil
}

func compressedHexVersion(data []byte, marker *regexp.Regexp) string {
	location := marker.FindIndex(data)
	if location == nil {
		return ""
	}
	version := make([]byte, 0, 32)
	for index := location[1]; index < len(data) && len(version) < 32; {
		value := data[index]
		if value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F' {
			version = append(version, value)
			index++
			continue
		}
		if index+1 < len(data) && data[index+1] == 0x01 {
			index += 2
			continue
		}
		if index+1 < len(data) && data[index+1] == 0x39 {
			literalLength := 0
			for next := index + 2; next < len(data); next++ {
				if next+1 < len(data) && data[next+1] == 0x01 {
					next++
					continue
				}
				value := data[next]
				if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F') {
					break
				}
				literalLength++
			}
			zeroCount := 32 - len(version) - literalLength
			if zeroCount < 1 || zeroCount > 32 {
				return ""
			}
			version = append(version, []byte(strings.Repeat("0", zeroCount))...)
			index += 2
			continue
		}
		return ""
	}
	if len(version) != 32 {
		return ""
	}
	return string(version)
}

func updateThickFrameLength(frame []byte) []byte {
	headerStart := bytes.Index(frame, []byte("POST /e1cib"))
	if headerStart < 0 {
		headerStart = bytes.Index(frame, []byte("GET /e1cib"))
	}
	if headerStart >= 2 && len(frame) >= headerStart+34 {
		binary.LittleEndian.PutUint16(frame[headerStart-2:headerStart], uint16(len(frame)-headerStart-34))
	}
	return frame
}

func isCommandFrame(frame []byte) bool {
	return bytes.Contains(frame, []byte("POST /e1cib/logForm?cmd=call")) &&
		(bytes.Contains(frame, []byte("Content-Encoding: zstd")) || bytes.Contains(frame, []byte("Content-Encoding: lz4")))
}

func replaceThickCommand(frame []byte, command, remoteKey, formVersion string, decoder thickCodec, encoder thickCodec) ([]byte, bool, error) {
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
	body, err := decoder.Decode(frame[bodyStart : bodyStart+length])
	if err != nil {
		return nil, false, err
	}
	if !bytes.Contains(body, []byte("ВыполнитьКомандуСкриптаНаСервере")) {
		return frame, false, nil
	}
	body = bytes.ReplaceAll(body, []byte("4d9ff3b8edfe324481f5cd7e62f880d2"), []byte(formVersion))
	body = bytes.ReplaceAll(body, []byte("71cd0942ce7bda4fa0ed0492276effa2"), []byte(formVersion))
	body = bytes.ReplaceAll(body, []byte("03FB8707-3A8E-4C4C-AD75-8B18BA7F7D47"), []byte(strings.ToUpper(remoteKey)))
	body = bytes.ReplaceAll(body, []byte("03fb8707-3a8e-4c4c-ad75-8b18ba7f7d47"), []byte(strings.ToLower(remoteKey)))
	body = bytes.ReplaceAll(body, []byte("F2BFDD48-85C7-475D-9045-DAB9BC86839A"), []byte(strings.ToUpper(remoteKey)))
	body = bytes.ReplaceAll(body, []byte("f2bfdd48-85c7-475d-9045-dab9bc86839a"), []byte(strings.ToLower(remoteKey)))
	body = bytes.ReplaceAll(body, []byte("ipconfig"), []byte(html.EscapeString(command)))
	compressed, err := encoder.Encode(body)
	if err != nil {
		return nil, false, err
	}
	header = vrsStatPattern.ReplaceAll(header, nil)
	header = contentLengthPattern.ReplaceAll(header, []byte("Content-Length: "+strconv.Itoa(len(compressed))))
	result := append([]byte(nil), frame[:headerStart]...)
	result = append(result, header...)
	result = append(result, []byte("\r\n\r\n")...)
	result = append(result, compressed...)
	result = append(result, frame[bodyStart+length:]...)
	if headerStart >= 2 {
		binary.LittleEndian.PutUint16(result[headerStart-2:headerStart], uint16(len(result)-headerStart-34))
	}
	return result, true, nil
}

func extractCommandOutput(frame []byte, decoder thickCodec) string {
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
	body, err := decoder.Decode(frame[bodyStart : bodyStart+length])
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

func extractCommandError(frame []byte, decoder thickCodec) string {
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
	if bytes.Contains(frame[headerStart:headerEnd], []byte("Content-Encoding: zstd")) || bytes.Contains(frame[headerStart:headerEnd], []byte("Content-Encoding: lz4")) {
		body, err = decoder.Decode(body)
		if err != nil {
			return "неизвестная ошибка протокола"
		}
	}
	if match := descriptionPattern.FindSubmatch(body); match != nil {
		return strings.TrimSpace(html.UnescapeString(string(match[1])))
	}
	return strings.TrimSpace(string(body))
}
