package agent

import (
	"strings"
	"testing"
)

func TestThickInitialRequestProfiles(t *testing.T) {
	modulus := make([]byte, 128)
	cluster := thickProfile{
		service: "RegMngrCntxt:RegMngrCntxt", objectID: "4ecea39c-b4c9-453e-aed0-ce8a24cc71c2",
		finalObjectID: "00000000-0000-0000-0000-000000000000", sequence: 21185,
	}
	request := buildThickInitialRequest(modulus, cluster, "DESKTOP-DHPEU34", "", "8.3.27.1786")
	if len(request) != 703 {
		t.Fatalf("unexpected cluster request length: %d", len(request))
	}
	if !strings.Contains(string(request), "RegMngrCntxt:RegMngrCntxt") {
		t.Fatal("cluster service not encoded")
	}

	worker := thickProfile{
		service: "infosec:infosec", objectID: "1e01900d-82fd-413a-bfe5-571a4c30a685",
		finalObjectID: "4be1b023-3dc5-4777-993e-d47b88906e00", sequence: 21189,
	}
	request = buildThickInitialRequest(modulus, worker, "DESKTOP-DHPEU34", "kor9k@DESKTOP-DHPEU34", "8.3.27.1786")
	if len(request) != 749 {
		t.Fatalf("unexpected worker request length: %d", len(request))
	}
}
