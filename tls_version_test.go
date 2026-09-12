package cycletls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// A JA3 without extension 43 cannot negotiate TLS 1.3, and claiming a 1.3
// maximum makes crypto/tls reject the server's downgrade canary.
func TestMaxVersionFollowsSupportedVersionsExt(t *testing.T) {
	const ciphers = "49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53"
	for _, tc := range []struct {
		name, ja3 string
		want      uint16
	}{
		{"no ext 43", "771," + ciphers + ",0-23-65281-10-11-35-16-5-13,29-23-24-21,0", utls.VersionTLS12},
		{"with ext 43", "771," + ciphers + ",0-23-65281-10-11-35-16-5-13-43,29-23-24-21,0", utls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := StringToSpec(tc.ja3, false, "chrome", false, "0403,0804,0401,0503,0805,0501,0806,0601,0201", nil)
			if err != nil {
				t.Fatal(err)
			}
			if spec.TLSVersMax != tc.want {
				t.Fatalf("TLSVersMax = 0x%04x, want 0x%04x", spec.TLSVersMax, tc.want)
			}
		})
	}
}
