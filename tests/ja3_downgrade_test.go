package tests

import (
	"fmt"
	"testing"

	cycletls "github.com/talrasha007/CycleTLS"
)

// A TLS 1.2 JA3 without extension 43 must complete the handshake against a
// TLS 1.3 capable server instead of tripping the downgrade canary check.
// Note the library reports handshake failures as status 495 with a nil error.
func TestJA3WithoutSupportedVersions(t *testing.T) {
	client := cycletls.Init()
	defer client.Close()

	resp, err := client.Do("https://tls.peet.ws/api/all", cycletls.Options{
		Ja3:                 "771,49195-49199-49196-49200-52393-52392-49161-49171-49162-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		SignatureAlgorithms: "0403,0804,0401,0503,0805,0501,0806,0601,0201",
		ForceHTTP1:          true,
		MaxResponseBodySize: -1,
		UserAgent:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
	}, "GET")
	if err != nil {
		t.Fatal("Request Failed: " + err.Error())
	}
	if resp.Status != 200 {
		t.Fatalf("Status %d: %s", resp.Status, resp.Body)
	}
	fmt.Println(resp.Body)
}
