package cycletls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gaukas/clienthellod"
)

type observedFingerprint struct {
	Ja3                 string `json:"ja3"`
	SignatureAlgorithms string `json:"signatureAlgorithms"`
}

// The server parses the bytes it receives independently of the client metadata.
type fingerprintListener struct{ net.Listener }
type fingerprintConn struct {
	net.Conn
	reader      io.Reader
	fingerprint observedFingerprint
}

func (c *fingerprintConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (l fingerprintListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hello, err := clienthellod.ReadClientHello(c)
	if err == nil {
		err = hello.ParseClientHello()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	decimal := func(values []uint16) string {
		var parts []string
		for _, v := range values {
			if v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) {
				continue
			}
			parts = append(parts, strconv.Itoa(int(v)))
		}
		return strings.Join(parts, "-")
	}
	var points, signatures []string
	for _, p := range hello.ECPointFormatList {
		points = append(points, strconv.Itoa(int(p)))
	}
	for _, s := range hello.SignatureSchemeList {
		signatures = append(signatures, fmt.Sprintf("%04x", s))
	}
	f := observedFingerprint{
		Ja3:                 fmt.Sprintf("%d,%s,%s,%s,%s", hello.TLSHandshakeVersion, decimal(hello.CipherSuites), decimal(hello.Extensions), decimal(hello.NamedGroupList), strings.Join(points, "-")),
		SignatureAlgorithms: strings.Join(signatures, ","),
	}
	return &fingerprintConn{Conn: c, reader: io.MultiReader(bytes.NewReader(hello.Raw()), c), fingerprint: f}, nil
}

type observedFingerprintKey struct{}

func fingerprintOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if target := r.URL.Query().Get("redirect"); target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		json.NewEncoder(w).Encode(r.Context().Value(observedFingerprintKey{}))
	}))
	s.Listener = fingerprintListener{s.Listener}
	s.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, observedFingerprintKey{}, c.(*tls.Conn).NetConn().(*fingerprintConn).fingerprint)
	}
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func checkResponseFingerprint(t *testing.T, resp Response) observedFingerprint {
	t.Helper()
	if resp.Status != 200 {
		t.Fatalf("request failed: %+v", resp)
	}
	var wire, returned observedFingerprint
	if err := json.Unmarshal([]byte(resp.Body), &wire); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &returned); err != nil {
		t.Fatal(err)
	}
	if returned.Ja3 == "" || returned.SignatureAlgorithms == "" || returned != wire {
		t.Fatalf("returned fingerprint=%+v, server observed=%+v", returned, wire)
	}
	return returned
}

func TestResponseFingerprintMatchesWireAndCanBeReplayed(t *testing.T) {
	for _, mode := range []string{"random-h1", "random-h2", "default", "tls13-upgrade", "tls12-fallback"} {
		t.Run(mode, func(t *testing.T) {
			s := fingerprintOrigin(t)
			c := Init()
			defer c.Close()
			opts := Options{Ja3: "RAND", SignatureAlgorithms: "RAND", ShuffleExtensions: true, ForceTLS12: true, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxResponseBodySize: -1, Timeout: 5, UserAgent: "chrome"}
			opts.ForceHTTP1 = mode == "random-h1"
			if mode == "default" {
				opts.Ja3 = ""
				opts.SignatureAlgorithms = ""
				opts.ShuffleExtensions = false
			}
			if mode == "tls13-upgrade" {
				opts.ForceTLS12 = false
				opts.TLS13AutoRetry = true
			}
			var attempts atomic.Int32
			if mode == "tls12-fallback" {
				opts.Ja3 = "771,4865-4866-4867-49195-49199,0-10-11-13-16-43-51-45,29-23-24,0"
				opts.ShuffleExtensions = false
				opts.ForceTLS12 = false
				opts.TLS13AutoRetry = true
				// Reject the upgraded attempt so the original JA3 fallback
				// succeeds with its different supported_groups list.
				s.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
					if attempts.Add(1) == 1 {
						return nil, fmt.Errorf("reject first attempt")
					}
					return nil, nil
				}
			}
			resp, err := c.Do(s.URL, opts, "GET")
			if err != nil {
				t.Fatal(err)
			}
			first := checkResponseFingerprint(t, resp)
			if mode == "tls12-fallback" && (attempts.Load() != 2 || !strings.Contains(first.Ja3, ",29-23-24,")) {
				t.Fatalf("did not report successful fallback: attempts=%d fingerprint=%+v", attempts.Load(), first)
			}
			// Reusing the connection must report the same actual fingerprint.
			resp, err = c.Do(s.URL, opts, "GET")
			if err != nil {
				t.Fatal(err)
			}
			if got := checkResponseFingerprint(t, resp); got != first {
				t.Fatalf("reuse changed fingerprint: %+v -> %+v", first, got)
			}
			// Force a new client and connection with the returned explicit values.
			opts.Ja3 = first.Ja3
			opts.SignatureAlgorithms = first.SignatureAlgorithms
			opts.ShuffleExtensions = false
			opts.TLS13AutoRetry = false
			opts.EnableConnectionReuse = false
			resp, err = c.Do(s.URL, opts, "GET")
			if err != nil {
				t.Fatal(err)
			}
			if got := checkResponseFingerprint(t, resp); got != first {
				t.Fatalf("replayed fingerprint changed: %+v -> %+v", first, got)
			}
		})
	}
}

func TestResponseFingerprintConcurrentPoolRotation(t *testing.T) {
	s := fingerprintOrigin(t)
	c := Init()
	defer c.Close()
	opts := Options{Ja3: "RAND", SignatureAlgorithms: "RAND", ShuffleExtensions: true, ForceTLS12: true, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxTotalRequests: 2, MaxResponseBodySize: -1, Timeout: 5, IP: "127.0.0.1"}
	var wg sync.WaitGroup
	for worker := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			target := s.URL
			if worker%2 != 0 {
				// This origin sends SNI, unlike the IP URL. Both origins can
				// share a client generation but have different actual JA3s.
				target = strings.Replace(target, "127.0.0.1", "origin.invalid", 1)
			}
			resp, err := c.Do(target, opts, "GET")
			if err != nil {
				t.Error(err)
				return
			}
			checkResponseFingerprint(t, resp)
		}()
	}
	wg.Wait()
}

func TestPlainHTTPResponseHasNoTLSFingerprint(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer s.Close()
	c := Init()
	defer c.Close()
	resp, err := c.Do(s.URL, Options{Ja3: "RAND", SignatureAlgorithms: "RAND", Timeout: 5}, "GET")
	if err != nil || resp.Status != 200 {
		t.Fatalf("response=%+v err=%v", resp, err)
	}
	raw, _ := json.Marshal(resp)
	var f observedFingerprint
	json.Unmarshal(raw, &f)
	if f != (observedFingerprint{}) {
		t.Fatalf("plain HTTP reported TLS fingerprint: %+v", f)
	}
}

func TestResponseFingerprintFollowsFinalRedirect(t *testing.T) {
	origin := fingerprintOrigin(t)
	final := fingerprintOrigin(t)
	c := Init()
	defer c.Close()
	opts := Options{Ja3: "RAND", SignatureAlgorithms: "RAND", ShuffleExtensions: true, ForceTLS12: true, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxResponseBodySize: -1, Timeout: 5, IP: "127.0.0.1"}
	// The final origin has SNI while the redirecting origin does not.
	finalURL := strings.Replace(final.URL, "127.0.0.1", "origin.invalid", 1)
	resp, err := c.Do(origin.URL+"/?redirect="+url.QueryEscape(finalURL), opts, "GET")
	if err != nil {
		t.Fatal(err)
	}
	checkResponseFingerprint(t, resp)
	if resp.FinalUrl != finalURL {
		t.Fatalf("final URL=%q, want %q", resp.FinalUrl, finalURL)
	}
}
