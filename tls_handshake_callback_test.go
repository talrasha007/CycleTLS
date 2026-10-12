package cycletls

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestTLSHandshakeDoneCallback(t *testing.T) {
	for _, mode := range []string{"http-success", "http-failure", "bad-certificate"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Load() != 1 {
					t.Errorf("callback must precede HTTP request: calls=%d", calls.Load())
				}
				if mode == "http-failure" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				w.WriteHeader(403)
			}))
			s.Config.ErrorLog = log.New(io.Discard, "", 0)
			s.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
			s.StartTLS()
			defer s.Close()
			client := Init()
			defer client.Close()
			response, err := client.Do(s.URL, Options{Timeout: 2, InsecureSkipVerify: mode != "bad-certificate", EnableConnectionReuse: false, TLSHandshakeDone: func() { calls.Add(1) }}, "GET")
			if err != nil {
				t.Fatal(err)
			}
			want := int32(1)
			if mode == "bad-certificate" {
				want = 0
			}
			if calls.Load() != want {
				t.Fatalf("callback calls=%d want=%d response=%+v", calls.Load(), want, response)
			}
			if mode == "http-success" && response.Status != 403 {
				t.Fatalf("response=%+v", response)
			}
			if mode != "http-success" && response.Headers != nil {
				t.Fatalf("expected HTTP/transport failure: %+v", response)
			}
		})
	}
}

func TestTLSHandshakeDoneUsesCurrentRequestNotPoolOwner(t *testing.T) {
	var conns atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(200)
	}))
	s.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	s.StartTLS()
	defer s.Close()
	client := Init()
	defer client.Close()
	var first, second atomic.Int32
	for _, counter := range []*atomic.Int32{&first, &second} {
		response, err := client.Do(s.URL, Options{Timeout: 2, InsecureSkipVerify: true, EnableConnectionReuse: true, Meta: "callback-current-request", TLSHandshakeDone: func() { counter.Add(1) }}, "GET")
		if err != nil || response.Status != 200 {
			t.Fatalf("response=%+v err=%v", response, err)
		}
	}
	if first.Load() != 1 || second.Load() != 1 || conns.Load() != 2 {
		t.Fatalf("first=%d second=%d conns=%d", first.Load(), second.Load(), conns.Load())
	}
}
