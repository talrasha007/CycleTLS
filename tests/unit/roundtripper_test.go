package unit

import (
	"testing"

	cycletls "github.com/talrasha007/CycleTLS"
)

const (
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Fatalf("%s != %s", a, b)
	}
}

func TestValidSpec(t *testing.T) {
	spec, err := cycletls.StringToSpec("771,52244-52243-52245-49195-49199-158-49162-49172-57-49161-49171-51-156-53-47-10-255,0-23-35-13-5-13172-18-16-30032-11-10,23-24,0", false, UserAgent, false, "", nil)
	if err != nil {
		t.Fatal("Error with valid spec")
	}
	_ = spec
}

func TestInvalidSpec(t *testing.T) {
	spec, err := cycletls.StringToSpec("771,52244-52243-52245-49195-49199-158-49162-49172-57-49161-49171-51-156-53-47-10-255,0-23-35-13-5-13172-18-16-111111-10,23-24,0", false, UserAgent, false, "", nil)
	if err != nil {
		assertEqual(t, err.Error(), "Extension {{ 111111 }} is not Supported by CycleTLS please raise an issue")
	}
	_ = spec

}

func TestUnknownExtensionCodepoint(t *testing.T) {
	// 51764 (trust_anchors) has no dedicated uTLS extension; it must not error.
	_, err := cycletls.StringToSpec("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,51-43-13-17613-27-45-65281-16-18-10-0-23-35-11-65037-51764-5,4588-29-23-24,0", false, UserAgent, false, "", nil)
	if err != nil {
		t.Fatal(err)
	}
}
