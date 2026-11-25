package agent

import "testing"

func TestCompressedHexVersion(t *testing.T) {
	const expected = "5a468273e7e00143be3ed5658e4b7a8b"
	plain := []byte(`v="5a468273e7e00143be3ed5658e4b7a8b00000000"`)
	if actual := compressedHexVersion(plain, formVersionPattern); actual != expected {
		t.Fatalf("plain version: got %q, want %q", actual, expected)
	}

	compressed := []byte(`v="5a468273e7e`)
	compressed = append(compressed, 0x89, 0x39, 0x13, 0x01)
	compressed = append(compressed, []byte(`143be3ed5658e4b7a8b`)...)
	compressed = append(compressed, 0x8f, 0x39, '"')
	if actual := compressedHexVersion(compressed, formVersionPattern); actual != expected {
		t.Fatalf("1CSDC version: got %q, want %q", actual, expected)
	}

	module := []byte(`version='94131f55ba2758499fa5e19`)
	module = append(module, 0x9e, 0x39, 0x07, 0x01)
	module = append(module, []byte(`eb0e713`)...)
	module = append(module, 0xa4, 0x39, '\'')
	const moduleExpected = "94131f55ba2758499fa5e1900eb0e713"
	if actual := compressedHexVersion(module, moduleVersionPattern); actual != moduleExpected {
		t.Fatalf("alternate 1CSDC version: got %q, want %q", actual, moduleExpected)
	}

	short := []byte(`v="b83e6ad35a928845985785da480a39f`)
	short = append(short, 0x47, 0x3f, '"')
	const shortExpected = "b83e6ad35a928845985785da480a39f0"
	if actual := compressedHexVersion(short, formVersionPattern); actual != shortExpected {
		t.Fatalf("1CSDC 0x3f version: got %q, want %q", actual, shortExpected)
	}
}

func TestCompressedHexVersionRejectsIncompleteValue(t *testing.T) {
	if actual := compressedHexVersion([]byte(`v="abc"`), formVersionPattern); actual != "" {
		t.Fatalf("unexpected version %q", actual)
	}
}
