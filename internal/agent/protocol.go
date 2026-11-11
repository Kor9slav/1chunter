package agent

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

var (
	utf8BOM          = []byte{0xef, 0xbb, 0xbf}
	base64Pattern    = regexp.MustCompile(`(?s)\{#base64:([^}]+)\}`)
	windowsNegotiate = []byte{
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xb7, 0xb2, 0x08, 0xe2, 0x09, 0x00, 0x09, 0x00, 0x37, 0x00, 0x00, 0x00,
		0x0f, 0x00, 0x0f, 0x00, 0x28, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x61, 0x4a,
		0x00, 0x00, 0x00, 0x0f, 0x44, 0x45, 0x53, 0x4b, 0x54, 0x4f, 0x50, 0x2d,
		0x44, 0x48, 0x50, 0x45, 0x55, 0x33, 0x34, 0x57, 0x4f, 0x52, 0x4b, 0x47,
		0x52, 0x4f, 0x55, 0x50,
	}
	anonymousAuthenticate = []byte{
		0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x58, 0x00, 0x00, 0x00, 0x35, 0xc2, 0x88, 0xe2, 0x0a, 0x00, 0x61, 0x4a,
		0x00, 0x00, 0x00, 0x0f, 0x0e, 0xa1, 0x1c, 0xff, 0x51, 0xe0, 0x09, 0xee,
		0x33, 0x9a, 0x86, 0x64, 0x58, 0xd6, 0x89, 0x4f,
	}
)

const (
	creatorID             = "e23134a2-14ff-4160-ba5f-ccef04e3786f"
	adminProcessInterface = "7f58f27d-5ad8-43a1-aa1e-c982f41bed5c"
	adminProcessClass     = "ae135932-4f94-44df-92c1-c91f15a92848"
	authenticationClass   = "671507fd-50a9-4b63-b70e-58b3d364f48f"
)

func buildInitialRequest(modulus []byte, sessionID, workstation, username, platformVersion, locale, objectID string, sequence int) []byte {
	ticket := buildIntroTicket(username)
	body := fmt.Sprintf("\"n\",\r\n{#base64:%s},\r\n{#base64:AQAB}", encodeBase64(modulus))
	request := fmt.Sprintf("{0,%s,%d,4,%s,0,1,11,0,\r\n"+
		"{\"S\",\"##AdminProcess##:##AdminProcess##\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,%s}\r\n},0,\r\n"+
		"{\"S\",\"SrvrConsole\"},0,\r\n"+
		"{\"S\",\"%s\"},2,\r\n"+
		"{\"#\",%s,\r\n{%s}\r\n},1,0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,00000000-0000-0000-0000-000000000000}\r\n},1}",
		sessionID, sequence, adminProcessInterface, adminProcessClass, objectID,
		workstation, authenticationClass, encodeBase64(ticket), platformVersion, locale, locale, adminProcessClass)

	packet := []byte{0xd6, 0x00}
	packet = append(packet, utf8BOM...)
	packet = append(packet, []byte(body)...)
	packet = append(packet, utf8BOM...)
	packet = append(packet, []byte(request)...)
	packet = append(packet, MessageEnd...)
	return packet
}

func buildAuthenticationRequest(token []byte, sessionID, workstation, platformVersion, locale, objectID string, sequence int) []byte {
	request := fmt.Sprintf("{0,%s,%d,4,%s,0,1,11,0,\r\n"+
		"{\"S\",\"##AdminProcess##:##AdminProcess##\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,%s}\r\n},0,\r\n"+
		"{\"S\",\"SrvrConsole\"},0,\r\n"+
		"{\"S\",\"%s\"},2,\r\n"+
		"{\"#\",%s,\r\n{%s}\r\n},1,0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"S\",\"%s\"},0,\r\n"+
		"{\"#\",%s,\r\n{1,00000000-0000-0000-0000-000000000000}\r\n},1}",
		sessionID, sequence, adminProcessInterface, adminProcessClass, objectID,
		workstation, authenticationClass, encodeBase64(token), platformVersion, locale, locale, adminProcessClass)

	packet := append([]byte{}, utf8BOM...)
	packet = append(packet, []byte(request)...)
	packet = append(packet, MessageEnd...)
	return packet
}

func buildIntroTicket(username string) []byte {
	ticket := []byte("V8IntroTicketReq")
	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len(username)))
	ticket = append(ticket, length...)
	ticket = append(ticket, []byte(username)...)
	ticket = append(ticket, 0)
	return ticket
}

func encodeBase64(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var builder strings.Builder
	for offset := 0; offset < len(encoded); offset += 64 {
		end := offset + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		if offset > 0 {
			builder.WriteString("\r\r\n")
		}
		builder.WriteString(encoded[offset:end])
	}
	return builder.String()
}

func decodeBase64Block(data []byte) ([]byte, error) {
	var encoded []byte
	match := base64Pattern.FindSubmatch(data)
	if match != nil {
		encoded = match[1]
	} else if start := bytes.Index(data, []byte("{TlRMTVNTUA")); start >= 0 {
		encoded = data[start+1:]
		if end := bytes.IndexByte(encoded, '}'); end >= 0 {
			encoded = encoded[:end]
		}
	} else {
		return nil, fmt.Errorf("блок base64 не найден")
	}
	value := strings.ReplaceAll(string(encoded), "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return base64.StdEncoding.DecodeString(value)
}

type frameReader struct {
	reader *bufio.Reader
	buffer []byte
}

func newFrameReader(reader *bufio.Reader) *frameReader {
	return &frameReader{reader: reader}
}

func (reader *frameReader) readFrame(maxSize int) ([]byte, error) {
	for {
		if index := bytes.Index(reader.buffer, MessageEnd); index >= 0 {
			end := index + len(MessageEnd)
			frame := append([]byte(nil), reader.buffer[:end]...)
			reader.buffer = reader.buffer[end:]
			return frame, nil
		}
		if len(reader.buffer) > maxSize {
			return nil, fmt.Errorf("кадр превышает %d байт", maxSize)
		}
		chunk := make([]byte, 4096)
		read, err := reader.reader.Read(chunk)
		if read > 0 {
			reader.buffer = append(reader.buffer, chunk[:read]...)
		}
		if err != nil {
			return nil, err
		}
	}
}
