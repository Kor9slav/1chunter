package agent

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

func buildNTLMAnonymousAuthenticate(negotiate, challenge []byte) []byte {
	authenticate := buildNTLMAuthenticateMessage(challenge, nil, nil, "", "", "", nil)
	sessionBaseKey := hmacMD5(ntlmV2Hash("", "", ""), nil)
	mic := hmacMD5(sessionBaseKey, joinBytes(negotiate, challenge, authenticate))
	copy(authenticate[72:88], mic)
	return authenticate
}

func buildNTLMKeyExchangeAuthenticate(negotiate, challenge []byte, username, password, workstation string) ([]byte, error) {
	if len(challenge) < 56 || len(negotiate) == 0 {
		return nil, fmt.Errorf("некорректный NTLM challenge")
	}
	serverChallenge := challenge[24:32]
	targetInfoLength := int(binary.LittleEndian.Uint16(challenge[40:42]))
	targetInfoOffset := int(binary.LittleEndian.Uint32(challenge[44:48]))
	var targetInfo []byte
	if targetInfoLength > 0 {
		if targetInfoOffset+targetInfoLength > len(challenge) {
			return nil, fmt.Errorf("некорректный TargetInfo NTLM")
		}
		targetInfo = challenge[targetInfoOffset : targetInfoOffset+targetInfoLength]
	}
	timestamp := ntlmTimestamp(targetInfo)
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, err
	}
	user, domain := splitNTLMUsername(username)
	hash := ntlmV2Hash(password, user, domain)
	proof, blob := ntlmV2Proof(hash, serverChallenge, clientChallenge, timestamp, targetInfo)
	ntResponse := append(proof, blob...)
	var lmResponse []byte
	if len(targetInfo) == 0 {
		lmResponse = hmacMD5(hash, append(append([]byte(nil), serverChallenge...), clientChallenge...))
		lmResponse = append(lmResponse, clientChallenge...)
	}
	sessionBaseKey := hmacMD5(hash, proof)
	exportedSessionKey := make([]byte, 16)
	if _, err := rand.Read(exportedSessionKey); err != nil {
		return nil, err
	}
	cipher, err := rc4.NewCipher(sessionBaseKey)
	if err != nil {
		return nil, err
	}
	encryptedSessionKey := make([]byte, 16)
	cipher.XORKeyStream(encryptedSessionKey, exportedSessionKey)

	authenticate := buildNTLMAuthenticateMessage(challenge, lmResponse, ntResponse, domain, user, workstation, nil)
	mic := hmacMD5(sessionBaseKey, joinBytes(negotiate, challenge, authenticate))
	copy(authenticate[72:88], mic)
	authenticate[63] &^= 0x40
	return authenticate, nil
}

func buildNTLMAuthenticateMessage(challenge, lmResponse, ntResponse []byte, domain, username, workstation string, encryptedSessionKey []byte) []byte {
	domainBytes := utf16LE(domain)
	userBytes := utf16LE(username)
	workstationBytes := utf16LE(workstation)
	payloadSize := len(lmResponse) + len(ntResponse) + len(domainBytes) + len(userBytes) + len(workstationBytes) + len(encryptedSessionKey)
	message := make([]byte, 88+payloadSize)
	copy(message[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(message[8:12], 3)
	copy(message[60:64], challenge[20:24])
	copy(message[64:72], []byte{0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f})

	offset := 88
	fields := [][]byte{lmResponse, ntResponse, domainBytes, userBytes, workstationBytes, encryptedSessionKey}
	for index, value := range fields {
		field := message[12+index*8 : 20+index*8]
		binary.LittleEndian.PutUint16(field[0:2], uint16(len(value)))
		binary.LittleEndian.PutUint16(field[2:4], uint16(len(value)))
		binary.LittleEndian.PutUint32(field[4:8], uint32(offset))
		copy(message[offset:offset+len(value)], value)
		offset += len(value)
	}
	return message
}

func splitNTLMUsername(username string) (string, string) {
	if index := strings.Index(username, "\\"); index >= 0 {
		return username[index+1:], username[:index]
	}
	return username, ""
}

func ntlmV2Hash(password, username, domain string) []byte {
	passwordHash := md4.New()
	passwordHash.Write(utf16LE(password))
	return hmacMD5(passwordHash.Sum(nil), utf16LE(strings.ToUpper(username)+domain))
}

func ntlmV2Proof(hash, serverChallenge, clientChallenge, timestamp, targetInfo []byte) ([]byte, []byte) {
	blob := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	blob = append(blob, timestamp...)
	blob = append(blob, clientChallenge...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, targetInfo...)
	blob = append(blob, 0, 0, 0, 0)
	proofInput := append(append([]byte(nil), serverChallenge...), blob...)
	return hmacMD5(hash, proofInput), blob
}

func ntlmTimestamp(targetInfo []byte) []byte {
	for offset := 0; offset+4 <= len(targetInfo); {
		id := binary.LittleEndian.Uint16(targetInfo[offset : offset+2])
		length := int(binary.LittleEndian.Uint16(targetInfo[offset+2 : offset+4]))
		offset += 4
		if id == 0 || offset+length > len(targetInfo) {
			break
		}
		if id == 7 && length == 8 {
			return append([]byte(nil), targetInfo[offset:offset+8]...)
		}
		offset += length
	}
	ft := uint64(time.Now().UnixNano())/100 + 116444736000000000
	timestamp := make([]byte, 8)
	binary.LittleEndian.PutUint64(timestamp, ft)
	return timestamp
}

func utf16LE(value string) []byte {
	encoded := utf16.Encode([]rune(value))
	result := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(result[index*2:index*2+2], value)
	}
	return result
}

func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func joinBytes(parts ...[]byte) []byte {
	var result []byte
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}
