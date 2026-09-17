package cycletls

import (
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/Danny-Dasilva/fhttp"
)

type sharedObservedRequestBody struct {
	io.Reader
	closed atomic.Int32
}

func (b *sharedObservedRequestBody) Close() error { b.closed.Add(1); return nil }

func TestSharedTransportEarlyErrorClosesRequestBody(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed=%t", closed), func(t *testing.T) {
			rt := newRoundTripper(Browser{}).(*roundTripper)
			defer rt.Close()
			if closed {
				rt.Close()
			}
			body := &sharedObservedRequestBody{Reader: strings.NewReader("payload")}
			req, _ := fhttp.NewRequest("POST", "unsupported://host/path", body)
			if _, err := rt.RoundTrip(req); err == nil {
				t.Fatal("request unexpectedly succeeded")
			}
			if got := body.closed.Load(); got != 1 {
				t.Fatalf("request body close count=%d, want 1", got)
			}
		})
	}
}

func TestSharedHTTP2RequestIPKeepsTLSOriginsSeparate(t *testing.T) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, r.TLS.ServerName)
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	c, err := createNewClient(Browser{InsecureSkipVerify: true}, 5, false, "", "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer closeClientTransport(c)
	rt := c.Transport.(*roundTripper)
	a, _ := fhttp.NewRequest("GET", "https://first.test:"+port, nil)
	// Leave the first origin's negotiated connection awaiting its first stream.
	if _, err := rt.GetCached(a, rt.getDialTLSAddr(a)); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]string{"second.test": "second.test", "bücher.test": "xn--bcher-kva.test"} {
		b, _ := fhttp.NewRequest("GET", "https://"+host+":"+port, nil)
		resp, err := c.Do(b)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || string(body) != want {
			t.Fatalf("origin %s used SNI %q, err=%v", host, body, err)
		}
	}
}

func TestSharedPoolAsyncReleasesEveryAcquisition(t *testing.T) {
	for _, protocol := range []string{"http2", "http3"} {
		t.Run(protocol, func(t *testing.T) {
			clearAllConnections()
			defer clearAllConnections()
			handler := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				id := r.URL.Query().Get("id")
				if r.UserAgent() != "agent-"+id || r.Header.Get("Cookie") != "session="+id {
					t.Errorf("async request %s received UA=%q Cookie=%q", id, r.UserAgent(), r.Header.Get("Cookie"))
				}
				io.WriteString(w, "ok")
			})
			var target string
			if protocol == "http3" {
				s := startSharedH3Server(t, handler)
				target = s.url
			} else {
				s := httptest.NewUnstartedServer(handler)
				s.EnableHTTP2 = true
				s.StartTLS()
				defer s.Close()
				target = s.URL
			}
			const workers = 128
			requests := make([]fullRequest, workers)
			for i := range requests {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				id := fmt.Sprint(i)
				requests[i] = processRequest(cycleTLSRequest{RequestID: fmt.Sprintf("async-%s-%d", protocol, i), Options: Options{URL: target + "/?id=" + id, Method: "GET", ForceHTTP3: protocol == "http3", InsecureSkipVerify: true, EnableConnectionReuse: true, Meta: "async-sharing", Timeout: 5, UserAgent: "agent-" + id, Cookies: []Cookie{{Name: "session", Value: id}}, HeaderOrder: []string{"cookie", "user-agent"}}}, ctx)
				if i%2 == 0 {
					cancel()
				}
				if requests[i].client.Transport != requests[0].client.Transport {
					t.Fatal("asynchronous requests did not share transport")
				}
			}
			entry := requests[0].client.Transport.(*roundTripper).poolEntry
			var wg sync.WaitGroup
			for _, req := range requests {
				wg.Add(1)
				go func(req fullRequest) {
					defer wg.Done()
					out := make(chan []byte)
					done := make(chan struct{})
					go func() {
						for range out {
						}
						close(done)
					}()
					dispatcherAsync(req, out)
					close(out)
					<-done
				}(req)
			}
			wg.Wait()
			advancedClientPoolMutex.RLock()
			active := entry.active
			advancedClientPoolMutex.RUnlock()
			if active != 0 {
				t.Fatalf("%d acquisitions remain after completion/cancellation", active)
			}
			activeRequestsMutex.Lock()
			defer activeRequestsMutex.Unlock()
			for _, req := range requests {
				if _, exists := activeRequests[req.options.RequestID]; exists {
					t.Errorf("request %s remains registered", req.options.RequestID)
				}
			}
		})
	}
}

func TestSharedPoolReleasesMalformedRequest(t *testing.T) {
	clearAllConnections()
	defer clearAllConnections()
	c := Init()
	defer c.Close()
	if _, err := c.Do("://invalid", Options{EnableConnectionReuse: true}, "GET"); err == nil {
		t.Fatal("malformed URL succeeded")
	}
	advancedClientPoolMutex.RLock()
	defer advancedClientPoolMutex.RUnlock()
	for _, entry := range advancedClientPool {
		if entry.active != 0 {
			t.Fatalf("invalid request leaked %d acquisitions", entry.active)
		}
	}
}

func TestSharedHTTP2ClientMultiplexing(t *testing.T) {
	const parallel = 128
	const perWorker = 16
	var connections atomic.Int32
	arrived := make(chan struct{}, parallel)
	start := make(chan struct{})
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Query().Get("wave") == "0" {
			arrived <- struct{}{}
			select {
			case <-start:
			case <-r.Context().Done():
				return
			}
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
	opts := Options{InsecureSkipVerify: true, EnableConnectionReuse: true, MaxResponseBodySize: -1, Timeout: 15}
	var wg sync.WaitGroup
	errs := make(chan error, parallel)
	for worker := 0; worker < parallel; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("worker-%d-request-%d", worker, i)
				resp, err := c.Do(fmt.Sprintf("%s/?wave=%d&id=%s", s.URL, i, id), opts, "GET")
				if err != nil || resp.Status != 200 || resp.Body != id {
					errs <- fmt.Errorf("%s: status=%d body=%q err=%v", id, resp.Status, resp.Body, err)
					return
				}
			}
		}(worker)
	}
	for i := 0; i < parallel; i++ {
		select {
		case <-arrived:
		case <-time.After(10 * time.Second):
			close(start)
			wg.Wait()
			t.Fatal("concurrent requests did not reach server")
		}
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := connections.Load(); got != 1 {
		t.Errorf("%d requests / %d workers opened %d TCP connections, want 1", parallel*perWorker, parallel, got)
	}
	t.Logf("requests=%d parallel=%d TCP connections=%d", parallel*perWorker, parallel, connections.Load())
}

func TestSharedPoolConfigurationIsolation(t *testing.T) {
	base := Browser{JA3: DefaultChrome_JA3, UserAgent: "test", Cookies: []Cookie{{Name: "session", Value: "one"}}}
	variants := []struct {
		name string
		edit func(*Browser)
	}{
		{"forceTLS12", func(b *Browser) { b.ForceTLS12 = true }},
		{"sessionCache", func(b *Browser) { b.EnableClientSessionCache = true }},
		{"shuffleExtensions", func(b *Browser) { b.ShuffleExtensions = true }},
		{"signatureAlgorithms", func(b *Browser) { b.SignatureAlgorithms = "0403,0804" }},
		{"JA3EvenWithMeta", func(b *Browser) { b.JA3 = "771,4865,0-43,29,0" }},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			changed := base
			v.edit(&changed)
			if generateClientKey(base, 15, false, "same-meta", "", "") == generateClientKey(changed, 15, false, "same-meta", "", "") {
				t.Fatal("incompatible configurations share a pool key")
			}
		})
	}
}

func TestPoolCleanupPreservesActiveRequest(t *testing.T) {
	clearAllConnections()
	defer clearAllConnections()
	finish := make(chan struct{})
	defer close(finish)
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(200)
		w.(stdhttp.Flusher).Flush()
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "ok")
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	client, err := newClientWithReuse(Browser{InsecureSkipVerify: true}, 0, 5, false, "", true, "")
	if err != nil {
		t.Fatal(err)
	}
	var released sync.Once
	release := func() { released.Do(func() { releaseClient(client) }) }
	defer release()
	resp, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Clearing the shared pool must retire its generation, never abort this stream.
	clearAllConnections()
	select {
	case <-resp.Request.Context().Done():
		t.Fatal("cleanup canceled active request")
	default:
	}
	// Release server without closing the finish channel twice.
	finish <- struct{}{}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "ok" {
		t.Fatalf("active stream: %q %v", body, err)
	}
	resp.Body.Close()
	release()
}

func BenchmarkCycleTLSSharedHTTP2(b *testing.B) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	for _, reuse := range []bool{false, true} {
		b.Run(fmt.Sprintf("reuse=%t", reuse), func(b *testing.B) {
			c := Init()
			defer c.Close()
			opts := Options{InsecureSkipVerify: true, EnableConnectionReuse: reuse, MaxResponseBodySize: -1, Timeout: 15}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r, err := c.Do(s.URL, opts, "GET")
					if err != nil || r.Status != 200 {
						b.Errorf("status=%d err=%v", r.Status, err)
					}
				}
			})
		})
	}
}

func TestSharedPoolRetirementUnderLoad(t *testing.T) {
	for _, maxRequests := range []int64{0, 31} {
		t.Run(fmt.Sprintf("max=%d", maxRequests), func(t *testing.T) {
			var connections atomic.Int32
			s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				w.WriteHeader(200)
				w.(stdhttp.Flusher).Flush()
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
			const workers = 128
			const each = 8
			var wg sync.WaitGroup
			failures := make(chan error, workers)
			for worker := 0; worker < workers; worker++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						id := fmt.Sprintf("%d-%d", worker, i)
						r, err := c.Do(s.URL+"/?id="+id, Options{InsecureSkipVerify: true, EnableConnectionReuse: true, MaxTotalRequests: maxRequests, MaxResponseBodySize: -1, Timeout: 15}, "GET")
						if err != nil || r.Status != 200 || r.Body != id {
							failures <- fmt.Errorf("id=%s status=%d body=%q err=%v", id, r.Status, r.Body, err)
							return
						}
					}
				}(worker)
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			if maxRequests == 0 {
				// Retire generations while requests are in flight, then permit new acquisitions.
				for i := 0; i < 20; i++ {
					clearAllConnections()
					CleanupClientPool(-time.Nanosecond)
					select {
					case <-done:
						i = 20
					case <-time.After(time.Millisecond):
					}
				}
			}
			<-done
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			if maxRequests > 0 {
				want := int32((workers*each + int(maxRequests) - 1) / int(maxRequests))
				if got := connections.Load(); got != want {
					t.Errorf("generation connections=%d, want %d", got, want)
				}
			}
			clearAllConnections()
		})
	}
}

func TestSharedPoolRequestHeadersRemainIsolated(t *testing.T) {
	var connections atomic.Int32
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		fmt.Fprintf(w, "%s|%s", r.UserAgent(), r.Header.Get("Cookie"))
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
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ua := fmt.Sprintf("agent-%d", i)
			value := fmt.Sprint(i)
			order := []string{"user-agent", "cookie"}
			if i%2 == 0 {
				order = []string{"cookie", "user-agent"}
			}
			r, err := c.Do(s.URL, Options{InsecureSkipVerify: true, EnableConnectionReuse: true, Meta: "same", UserAgent: ua, Cookies: []Cookie{{Name: "session", Value: value}}, HeaderOrder: order, MaxResponseBodySize: -1}, "GET")
			if err != nil || r.Body != ua+"|session="+value {
				t.Errorf("client %d received %q err=%v", i, r.Body, err)
			}
		}(i)
	}
	wg.Wait()
	r, err := c.Do(s.URL, Options{InsecureSkipVerify: true, EnableConnectionReuse: true, Meta: "same", MaxResponseBodySize: -1}, "GET")
	if err != nil || r.Body != "|" {
		t.Fatalf("empty settings inherited other request: %q, %v", r.Body, err)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("request settings split shared connection: %d connections", got)
	}
}

func TestSharedPoolKeyIgnoresRequestSettings(t *testing.T) {
	base := Browser{JA3: DefaultChrome_JA3}
	for name, b := range map[string]Browser{
		"userAgent":   {JA3: base.JA3, UserAgent: "other-agent"},
		"cookies":     {JA3: base.JA3, Cookies: []Cookie{{Name: "session", Value: "other", Domain: "example.test"}}},
		"headerOrder": {JA3: base.JA3, HeaderOrder: []string{"cookie", "user-agent"}},
	} {
		if generateClientKey(base, 15, false, "", "", "") != generateClientKey(b, 15, false, "", "", "") {
			t.Errorf("%s changed pool key", name)
		}
	}
}
