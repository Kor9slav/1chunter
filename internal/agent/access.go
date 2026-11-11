package agent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type AdminStatus string

const (
	AdminAccepted AdminStatus = "ДОСТУП РАЗРЕШЁН"
	AdminDenied   AdminStatus = "ДОСТУП ЗАПРЕЩЁН"
	AdminUnknown  AdminStatus = "НЕИЗВЕСТНО"
)

var (
	uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	infoBaseSequence = [][]byte{
		{
			0x41, 0x95, 0x42, 0xc7, 0x2e, 0x60, 0x89, 0xc8, 0xbd, 0x48, 0xb1, 0x3b, 0xef, 0x26, 0x8c, 0xa6,
			0xae, 0x1c, 0x8d, 0x11, 0x0f, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43, 0xb7,
			0x38, 0x58, 0xc7, 0x72, 0xe3, 0xa0, 0xbf, 0x81, 0x82, 0x81, 0x20, 0x66, 0x53, 0xb2, 0xa6,
		},
		{
			0x41, 0x95, 0x42, 0xc7, 0x2e, 0x60, 0x89, 0xc8, 0xbd, 0x48, 0xb1, 0x3b, 0xef, 0x26, 0x8c, 0xa6,
			0xae, 0x1c, 0x8d, 0x12, 0x0f, 0x81, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43,
			0xb7, 0x38, 0x58, 0xc7, 0x72, 0xe3, 0xa0, 0xbf, 0x86, 0x82, 0x82, 0x81, 0xcb, 0x23, 0x95, 0x32,
			0x59, 0x13, 0xae, 0x94, 0x4f, 0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15, 0xa9, 0x28, 0x48, 0xc2,
			0x95, 0x1d, 0x33, 0x6c, 0x0f, 0x71, 0x3b, 0x2d, 0x4f, 0xbf, 0x72, 0x3a, 0xfa, 0x6b, 0xa3, 0x38,
			0xf7, 0x20, 0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
		},
		{
			0x41, 0x95, 0x42, 0xc7, 0x2e, 0x60, 0x89, 0xc8, 0xbd, 0x48, 0xb1, 0x3b, 0xef, 0x26, 0x8c, 0xa6,
			0xae, 0x1c, 0x8d, 0x13, 0x0f, 0x81, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43,
			0xb7, 0x38, 0x58, 0xc7, 0x72, 0xe3, 0xa0, 0xbf, 0x8a, 0x84, 0x84, 0x81, 0xcb, 0x23, 0x95, 0x32,
			0x59, 0x13, 0xae, 0x94, 0x4f, 0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15, 0xa9, 0x28, 0x48, 0xc2,
			0x95, 0x1d, 0x33, 0x6c, 0x0f, 0x71, 0x3b, 0x2d, 0x4f, 0xbf, 0x72, 0x3a, 0xfa, 0x6b, 0xa3, 0x38,
			0xf7, 0x20, 0xa1, 0xcb, 0x53, 0x81, 0xa1, 0xcb, 0x53, 0x81, 0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
		},
		{
			0x41, 0x95, 0x42, 0xc7, 0x2e, 0x60, 0x89, 0xc8, 0xbd, 0x48, 0xb1, 0x3b, 0xef, 0x26, 0x8c, 0xa6,
			0xae, 0x1c, 0x8d, 0x14, 0x0f, 0x81, 0x85, 0x95, 0x77, 0xaa, 0xcd, 0x73, 0xfc, 0x2a, 0x6c, 0x43,
			0xb7, 0x38, 0x58, 0xc7, 0x72, 0xe3, 0xa0, 0xbf, 0x86, 0x82, 0x82, 0x81, 0xcb, 0x23, 0x95, 0x32,
			0x59, 0x13, 0xae, 0x94, 0x4f, 0xdf, 0x44, 0x92, 0xc1, 0xc9, 0x1f, 0x15, 0xa9, 0x28, 0x48, 0xc2,
			0x95, 0x1d, 0x33, 0x6c, 0x0f, 0x71, 0x3b, 0x2d, 0x4f, 0xbf, 0x72, 0x3a, 0xfa, 0x6b, 0xa3, 0x38,
			0xf7, 0x20, 0x20, 0x20, 0x66, 0x53, 0xb2, 0xa6,
		},
	}
)

func checkAdminAccess(connection net.Conn, reader *frameReader, authenticationFrame []byte, platformVersion string) ([]ClusterInfo, AdminStatus, string, error) {
	return checkAdminAccessWithFlag(connection, reader, authenticationFrame, platformVersion, 0)
}

func checkAdminAccessWithFlag(connection net.Conn, reader *frameReader, authenticationFrame []byte, platformVersion string, flagOverride byte) ([]ClusterInfo, AdminStatus, string, error) {
	ids := uuidPattern.FindAllString(string(authenticationFrame), -1)
	if len(ids) < 2 {
		return nil, AdminUnknown, "", fmt.Errorf("не найден идентификатор привязки AdminProcess")
	}
	bind := fmt.Sprintf("{0,%s,16686,1,73cdaa77-2afc-436c-b738-58c772e3a0bf}", ids[1])
	packet := append([]byte{}, utf8BOM...)
	packet = append(packet, []byte(bind)...)
	packet = append(packet, MessageEnd...)
	if _, err := connection.Write(packet); err != nil {
		return nil, AdminUnknown, "", fmt.Errorf("привязка AdminProcess: %w", err)
	}
	if _, err := reader.readFrame(maxProtocolFrame); err != nil {
		return nil, AdminUnknown, "", fmt.Errorf("ответ привязки AdminProcess: %w", err)
	}

	requestFlag := byte(0x06)
	if platformVersion == "8.3.23.1782" {
		requestFlag = 0x4c
	}
	if flagOverride != 0 {
		requestFlag = flagOverride
	}
	centralRequest := withSessionID(infoBaseSequence[0], ids[1])
	centralRequest[20] = requestFlag
	if _, err := connection.Write(centralRequest); err != nil {
		return nil, AdminUnknown, "", fmt.Errorf("запрос списка кластеров: %w", err)
	}
	centralResponse, err := reader.readFrame(maxProtocolFrame)
	if err != nil {
		return nil, AdminUnknown, "", fmt.Errorf("ответ со списком кластеров: %w", err)
	}
	clusters := clusterEntries(centralResponse)
	if len(clusters) == 0 {
		name := firstTextRun(centralResponse)
		if isAccessFailure(name) {
			return nil, AdminDenied, name, nil
		}
		if name != "" {
			clusters = []ClusterInfo{{Name: name, AdminStatus: ClusterAdminUnknown}}
		}
	}

	adminStatus := AdminUnknown
	adminDetail := ""
	requestID := uint16(infoBaseSequence[0][19])
	currentCluster := 0
	for step := 1; step <= 100; step++ {
		operation := (step-1)%3 + 1
		requestID++
		request := withSessionID(infoBaseSequence[operation], ids[1])
		request = withClusterID(request, clusters[currentCluster].ID, currentCluster, platformVersion)
		request[19] = byte(requestID)
		request[20] = requestFlag
		if _, err := connection.Write(request); err != nil {
			return clusters, adminStatus, adminDetail, err
		}
		response, err := reader.readFrame(maxProtocolFrame)
		if err != nil {
			return clusters, adminStatus, adminDetail, err
		}
		switch operation {
		case 1:
			adminDetail = firstTextRun(response)
			if len(response) == len(MessageEnd) {
				return clusters, adminStatus, adminDetail, nil
			}
			if isAccessFailure(adminDetail) {
				adminStatus = AdminDenied
			}
		case 2:
			if clusterAdminStatus(response) == ClusterAdminPresent {
				clusters[currentCluster].AdminStatus = ClusterAdminPresent
			}
		case len(infoBaseSequence) - 1:
			if clusters[currentCluster].AdminStatus != ClusterAdminPresent {
				clusters[currentCluster].AdminStatus = clusterAdminStatus(response)
			}
			infoBaseName, description := infoBaseFields(response)
			if infoBaseName != "" {
				clusters[currentCluster].InfoBases = append(clusters[currentCluster].InfoBases,
					InfoBaseInfo{Name: infoBaseName, Description: description})
			}
			if currentCluster+1 < len(clusters) {
				currentCluster++
				continue
			}
			return clusters, adminStatus, adminDetail, nil
		}
	}
	return clusters, adminStatus, adminDetail, fmt.Errorf("превышен предел объектов при обходе кластеров")
}

func clusterEntries(data []byte) []ClusterInfo {
	var clusters []ClusterInfo
	seen := make(map[string]struct{})
	for index := 16; index+1 < len(data); index += 2 {
		nameStart := index + 2
		var name []rune
		if data[index] == 0x0b {
			nameStart = index + 1
			for nameStart < len(data) && (data[nameStart] == 0x20 || data[nameStart] >= 0x21 && data[nameStart] < 0x7f) {
				name = append(name, rune(data[nameStart]))
				nameStart++
			}
		} else if data[index] == 0x97 {
			for nameStart+1 < len(data) {
				value := binary.LittleEndian.Uint16(data[nameStart : nameStart+2])
				if !(value == 0x20 || value >= 0x21 && value < 0x7f || value >= 0x400 && value <= 0x45f) {
					break
				}
				name = append(name, rune(value))
				nameStart += 2
			}
		} else {
			continue
		}
		if len(name) < 4 {
			continue
		}
		nameString := strings.TrimSpace(string(name))
		if strings.IndexFunc(nameString, func(r rune) bool {
			return r >= 0x400 && r <= 0x45f || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
		}) < 0 {
			continue
		}
		if _, exists := seen[nameString]; exists {
			continue
		}
		seen[nameString] = struct{}{}
		idStart := index - 16
		if idStart < 0 {
			continue
		}
		id := append([]byte(nil), data[idStart:index]...)
		port := 0
		for marker := nameStart; marker+2 < len(data) && marker < nameStart+64; marker++ {
			if data[marker] != 0x8d {
				continue
			}
			candidate := int(binary.LittleEndian.Uint16(data[marker+1 : marker+3]))
			if candidate > 0 {
				port = candidate
				break
			}
		}
		clusters = append(clusters, ClusterInfo{ID: id, Name: nameString, Port: port, AdminStatus: ClusterAdminUnknown})
	}
	return clusters
}

func withClusterID(request []byte, id []byte, clusterIndex int, platformVersion string) []byte {
	if len(id) != 16 || len(request) < 82 {
		return request
	}
	offset := 65
	if platformVersion == "8.3.23.1782" && clusterIndex == 1 {
		request[65] = 0x97
		offset = 66
		copy(request[offset:offset+15], id[:15])
		return request
	}
	copy(request[offset:offset+16], id)
	return request
}

func clusterAdminStatus(data []byte) ClusterAdminStatus {
	detail := strings.ToLower(firstTextRun(data))
	if strings.Contains(detail, "администратор кластера") && strings.Contains(detail, "не аутентифицирован") {
		return ClusterAdminPresent
	}
	if isAccessFailure(detail) {
		return ClusterAdminUnknown
	}
	return ClusterAdminAbsent
}

func isAccessFailure(detail string) bool {
	lower := strings.ToLower(detail)
	return strings.Contains(lower, "не аутентифицирован") || strings.Contains(lower, "недостаточно прав") ||
		strings.Contains(lower, "отказано в доступе") || strings.Contains(lower, "сеанс работы завершен") ||
		strings.Contains(lower, "не является центральным")
}

func firstTextRun(data []byte) string {
	runs := textRuns(data)
	for _, run := range runs {
		if strings.IndexFunc(run, func(r rune) bool { return r >= 0x400 && r <= 0x45f }) >= 0 {
			return run
		}
	}
	if len(runs) == 0 {
		return ""
	}
	return runs[0]
}

func infoBaseFields(data []byte) (string, string) {
	if isAccessFailure(firstTextRun(data)) {
		return "", ""
	}
	asciiTokens := regexp.MustCompile(`[A-Za-z0-9_]+`).FindAllString(string(data), -1)
	tokens := make([]string, 0, len(asciiTokens))
	for _, token := range asciiTokens {
		if len(token) >= 2 && token != "fS" && token != "JeY" {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) >= 2 {
		return tokens[len(tokens)-2], tokens[len(tokens)-1]
	}
	if len(tokens) == 1 {
		return tokens[0], ""
	}
	return "", ""
}

func textRuns(data []byte) []string {
	var runs []string
	var current []rune
	flush := func() {
		if len(current) >= 4 {
			runs = append(runs, strings.TrimSpace(string(current)))
		}
		current = nil
	}

	for index := 0; index+1 < len(data); index += 2 {
		value := binary.LittleEndian.Uint16(data[index : index+2])
		r := rune(value)
		if value == 0x20 || value >= 0x21 && value < 0x7f || r >= 0x400 && r <= 0x45f {
			current = append(current, r)
		} else {
			flush()
		}
	}
	flush()
	return runs
}

func withSessionID(template []byte, id string) []byte {
	packet := append([]byte(nil), template...)
	decoded, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(decoded) != 16 {
		return packet
	}
	forward := func(from, size int) {
		for index := 0; index < size; index++ {
			packet[2+from+index] = decoded[from+size-1-index]
		}
	}
	forward(0, 4)
	forward(4, 2)
	forward(6, 2)
	copy(packet[2+8:2+16], decoded[8:])
	return packet
}
