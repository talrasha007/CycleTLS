package cycletls

import (
	"math/rand/v2"
	"slices"
	"strings"
)

// Choose the length first so that short and long lists are just as likely
// as intermediate ones. Keep the preference order of the selected entries.
func randomSubset(options ...string) []string {
	indices := rand.Perm(len(options))[:rand.IntN(len(options)+1)]
	slices.Sort(indices)
	selected := make([]string, 0, len(indices))
	for _, i := range indices {
		selected = append(selected, options[i])
	}
	return selected
}

func randomJA3() string {
	// TLS 1.3 AEADs and TLS 1.2 ECDHE with both RSA and ECDSA certificates.
	ciphers := []string{"4865", "4866", "4867", "49195", "49199", "49196", "49200", "52393", "52392"}
	ciphers = append(ciphers, randomSubset(
		"52243", "52244", // uTLS's draft ECDHE ChaCha20 suites (RSA and ECDSA).
		"49161", "49171", "49162", "49172", "49187", "49191",
		"156", "157", "60", "47", "53",
	)...)

	// SNI, supported groups/points, signatures, ALPN, extended master
	// secret, supported versions and key share are present in every offer.
	exts := []string{"0", "10", "11", "13", "16", "23", "43", "51"}
	// Keep ticket/PSK extensions out of this full-handshake profile. uTLS
	// cannot recompute a PSK binder on HelloRetryRequest with a warm cache.
	exts = append(exts, randomSubset("5", "18", "27", "45", "50", "65281", "21")...)
	if !slices.Contains(exts, "65281") {
		// Signal secure renegotiation to TLS 1.2 servers via SCSV instead.
		ciphers = append(ciphers, "255")
	}
	groups := append([]string{"29", "23", "24"}, randomSubset("25")...)
	return strings.Join([]string{"771", strings.Join(ciphers, "-"), strings.Join(exts, "-"), strings.Join(groups, "-"), "0"}, ",")
}

// resolveBrowserFingerprint materializes the original random policies for one
// transport generation. Its result must never be used to identify the pool.
func resolveBrowserFingerprint(browser Browser) Browser {
	if browser.JA3 != "RAND" && browser.SignatureAlgorithms != "RAND" && !browser.ShuffleExtensions {
		return browser
	}
	if browser.JA3 == "RAND" {
		browser.JA3 = randomJA3()
	}
	if browser.SignatureAlgorithms == "RAND" {
		// Cover P-256/P-384 ECDSA and RSA (PSS and PKCS#1) even in the
		// shortest list. Only advertise schemes uTLS can actually verify.
		sigAlgs := append([]string{"0403", "0503", "0804", "0401"}, randomSubset("0603", "0807", "0805", "0806", "0501", "0601")...)
		rand.Shuffle(len(sigAlgs), func(i, j int) { sigAlgs[i], sigAlgs[j] = sigAlgs[j], sigAlgs[i] })
		browser.SignatureAlgorithms = strings.Join(sigAlgs, ",")
	}
	if browser.JA3 != "" && browser.ShuffleExtensions {
		parts := strings.Split(browser.JA3, ",")
		if len(parts) >= 4 {
			extensions := strings.Split(parts[2], "-")
			rand.Shuffle(len(extensions), func(i, j int) {
				if extensions[i] != "41" && extensions[j] != "41" {
					extensions[i], extensions[j] = extensions[j], extensions[i]
				}
			})
			parts[2] = strings.Join(extensions, "-")
			browser.JA3 = strings.Join(parts, ",")
		}
	}
	return browser
}
