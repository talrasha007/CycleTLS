package cycletls

import (
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRandomOptionsShareHTTP2Generation(t *testing.T) {
	for _, tc := range []struct {
		name, ja3  string
		shuffle    bool
		forceTLS12 bool
		signature  string
	}{
		{"signature_only", DefaultChrome_JA3, false, true, "RAND"},
		{"both_random", "RAND", false, true, "RAND"},
		{"both_random_shuffled", "RAND", true, true, "RAND"},
		{"both_random_tls13", "RAND", true, false, "RAND"},
		{"shuffle_only", DefaultChrome_JA3, true, false, "0403,0804,0401"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var connections atomic.Int32
			s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if r.ProtoMajor != 2 {
					t.Errorf("protocol=%s, want HTTP2", r.Proto)
				}
				io.WriteString(w, r.URL.Query().Get("id"))
			}))
			s.EnableHTTP2 = true
			s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
				if state == stdhttp.StateNew {
					connections.Add(1)
				}
			}
			s.StartTLS()
			defer s.Close()
			c := Init()
			defer c.Close()
			opts := Options{Ja3: tc.ja3, SignatureAlgorithms: tc.signature, ShuffleExtensions: tc.shuffle, ForceTLS12: tc.forceTLS12, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxTotalRequests: 256, MaxResponseBodySize: -1, Timeout: 10}
			var wg sync.WaitGroup
			errs := make(chan error, 64)
			for worker := 0; worker < 64; worker++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					for i := 0; i < 8; i++ {
						id := fmt.Sprintf("%d-%d", worker, i)
						r, err := c.Do(s.URL+"/?id="+id, opts, "GET")
						if err != nil || r.Status != 200 || r.Body != id {
							errs <- fmt.Errorf("request=%s status=%d err=%v body=%q", id, r.Status, err, r.Body)
							return
						}
					}
				}(worker)
			}
			wg.Wait()
			close(errs)
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
			if n := connections.Load(); n != 2 {
				t.Fatalf("512 requests / limit 256 opened %d connections, want 2", n)
			}
			if opts.Ja3 != tc.ja3 || opts.SignatureAlgorithms != tc.signature {
				t.Fatal("caller options mutated")
			}
		})
	}
}

func TestRandomPoolKeepsOriginalKeyAndResolvesNewGeneration(t *testing.T) {
	clearAllConnections()
	defer clearAllConnections()
	raw := Browser{JA3: "RAND", SignatureAlgorithms: "RAND"}
	first, err := newClientWithReuse(raw, 2, 15, false, "", true, "")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseClient(first)
	second, err := newClientWithReuse(raw, 2, 15, false, "", true, "")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseClient(second)
	third, err := newClientWithReuse(raw, 2, 15, false, "", true, "")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseClient(third)
	if first != second || first == third {
		t.Fatal("original RAND options did not share/rotate by acquisition limit")
	}
	rt := first.Transport.(*roundTripper)
	if rt.JA3 == "RAND" || rt.SignatureAlgorithms == "RAND" {
		t.Fatal("new generation did not resolve RAND")
	}
	key := generateClientKey(raw, 15, false, "", "", "") + ":2"
	if rt.poolEntry.key != key {
		t.Fatalf("pool key is not based on raw options")
	}
	// An explicit resolved fingerprint must not collide with the RAND policy.
	explicit := raw
	explicit.JA3, explicit.SignatureAlgorithms = rt.JA3, rt.SignatureAlgorithms
	if generateClientKey(explicit, 15, false, "", "", "") == generateClientKey(raw, 15, false, "", "", "") {
		t.Fatal("explicit fingerprint collided with random policy")
	}
}

func TestRandomOptionsShareAcrossSyncAndAsync(t *testing.T) {
	var connections, hits atomic.Int32
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		hits.Add(1)
		io.WriteString(w, "ok")
	}))
	s.EnableHTTP2 = true
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			connections.Add(1)
		}
	}
	s.StartTLS()
	defer s.Close()
	c := Init()
	defer c.Close()
	opts := Options{Ja3: "RAND", SignatureAlgorithms: "RAND", ShuffleExtensions: true, ForceTLS12: true, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxTotalRequests: 256, MaxResponseBodySize: -1, Timeout: 10}
	r, err := c.Do(s.URL, opts, "GET")
	if err != nil || r.Status != 200 || r.Body != "ok" {
		t.Fatalf("synchronous request: %+v, %v", r, err)
	}
	opts.URL, opts.Method = s.URL, "GET"
	out := make(chan []byte)
	drained := make(chan struct{})
	go func() {
		for range out {
		}
		close(drained)
	}()
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		request := processRequest(cycleTLSRequest{RequestID: fmt.Sprintf("random-async-%d", i), Options: opts})
		wg.Add(1)
		go func(req fullRequest) { defer wg.Done(); dispatcherAsync(req, out) }(request)
	}
	wg.Wait()
	close(out)
	<-drained
	if hits.Load() != 65 || connections.Load() != 1 {
		t.Fatalf("hits=%d connections=%d, want 65 requests over 1 connection", hits.Load(), connections.Load())
	}
}
