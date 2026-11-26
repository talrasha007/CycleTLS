package cycletls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestRandomFingerprintLengthDistribution(t *testing.T) {
	cipherCounts := map[int]int{}
	extCounts, sigCounts := map[int]int{}, map[int]int{}
	for range 4096 {
		b := resolveBrowserFingerprint(Browser{JA3: "RAND", SignatureAlgorithms: "RAND"})
		fields := strings.Split(b.JA3, ",")
		ciphers := strings.Split(fields[1], "-")
		if len(ciphers) < 9 || len(ciphers) > 23 {
			t.Fatalf("unexpected cipher count %d in %s", len(ciphers), fields[1])
		}
		if len(ciphers) == 23 {
			for _, required := range []string{"52243", "52244", "60", "255"} {
				if !slices.Contains(ciphers, required) {
					t.Fatalf("missing cipher-list entry %s in %s", required, fields[1])
				}
			}
		}
		cipherCounts[len(ciphers)]++
		exts := strings.Split(fields[2], "-")
		sigs := strings.Split(b.SignatureAlgorithms, ",")
		extCounts[len(exts)]++
		sigCounts[len(sigs)]++
		for _, required := range []string{"0403", "0503", "0804", "0401"} {
			if !slices.Contains(sigs, required) {
				t.Fatalf("missing signature scheme %s in %v", required, sigs)
			}
		}
	}
	for n := 9; n <= 23; n++ {
		if cipherCounts[n] < 80 {
			t.Errorf("underrepresented cipher count %d in %v", n, cipherCounts)
		}
	}
	for n := 8; n <= 15; n++ {
		if extCounts[n] < 200 {
			t.Errorf("underrepresented extension count %d in %v", n, extCounts)
		}
	}
	for n := 4; n <= 10; n++ {
		if sigCounts[n] < 250 {
			t.Errorf("underrepresented signature count %d in %v", n, sigCounts)
		}
	}
}

func TestRandomFingerprintHandshakes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, cert := range []string{"rsa", "ecdsa-p384"} {
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(version), cert), func(t *testing.T) {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					fmt.Fprintf(w, "%d/%t/%s", r.TLS.Version, r.TLS.DidResume, r.TLS.ServerName)
				}))
				s.TLS = &tls.Config{MinVersion: version, MaxVersion: version, CurvePreferences: []tls.CurveID{tls.CurveP256}}
				if cert == "ecdsa-p384" {
					s.TLS.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
				}
				s.EnableHTTP2 = true
				s.StartTLS()
				defer s.Close()

				host := cert + ".example.test"
				url := strings.Replace(s.URL, "127.0.0.1", host, 1)
				client := Init()
				defer client.Close()
				opts := Options{Ja3: "RAND", SignatureAlgorithms: "RAND", ShuffleExtensions: true,
					ForceTLS12: version == tls.VersionTLS12, UserAgent: "chrome", IP: "127.0.0.1",
					InsecureSkipVerify: true, Timeout: 5, MaxResponseBodySize: -1}
				for i := range 18 {
					// Repeat the full handshake with client session caching enabled.
					opts.EnableClientSessionCache = i >= 16
					resp, err := client.Do(url, opts, "GET")
					want := fmt.Sprintf("%d/false/%s", version, host)
					if err != nil || resp.Status != http.StatusOK || resp.Body != want {
						t.Fatalf("sample %d: want %q, got %q (status %d, err %v)", i, want, resp.Body, resp.Status, err)
					}
				}
			})
		}
	}
}
