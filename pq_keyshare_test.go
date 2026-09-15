package cycletls

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

// Advertising X25519MLKEM768 in supported_groups without a matching key_share
// makes servers reply with a HelloRetryRequest selecting it, which uTLS cannot
// answer ("tls: CurvePreferences includes unsupported curve").
func TestPQCurveGetsKeyShare(t *testing.T) {
	const ja3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53," +
		"5-18-10-17613-65281-16-27-65037-0-43-51-11-35-13-23-45,4588-29-23-24,0"

	spec, err := StringToSpec(ja3, false, "chrome", false, "0403,0804,0401,0503,0805,0501,0806,0601", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, ext := range spec.Extensions {
		ks, ok := ext.(*utls.KeyShareExtension)
		if !ok {
			continue
		}
		for _, share := range ks.KeyShares {
			if share.Group == utls.X25519MLKEM768 {
				return
			}
		}
		t.Fatalf("key_share missing X25519MLKEM768: %+v", ks.KeyShares)
	}
	t.Fatal("no key_share extension in spec")
}
