package cycletls

import (
	"context"
	"crypto/tls"
	"errors"
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
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestHTTP3BodyReadPreservesContextError(t *testing.T) {
	s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "partial:")
		w.(stdhttp.Flusher).Flush()
		<-r.Context().Done()
	}))
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline=%t", deadline), func(t *testing.T) {
			rt := NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
			defer rt.Close()
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
				want = context.DeadlineExceeded
			}
			defer cancel()
			req, _ := fhttp.NewRequestWithContext(ctx, "GET", s.url, nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if !deadline {
				cancel()
			}
			_, err = io.ReadAll(resp.Body)
			if !errors.Is(err, want) {
				t.Fatalf("body read error=%v, want %v", err, want)
			}
		})
	}
}

type sharedH3Server struct {
	url         string
	connections atomic.Int64
	peers       chan *quic.Conn
}

func startSharedH3Server(t testing.TB, handler stdhttp.Handler) *sharedH3Server {
	t.Helper()
	cert := httptest.NewTLSServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	conf := cert.TLS.Clone()
	cert.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sharedH3Server{url: "https://" + udp.LocalAddr().String(), peers: make(chan *quic.Conn, 2048)}
	server := &http3.Server{TLSConfig: conf, QUICConfig: &quic.Config{MaxIncomingStreams: 1024}, Handler: handler, ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
		s.connections.Add(1)
		s.peers <- c
		return ctx
	}}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(udp) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = udp.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("HTTP3 server did not stop")
		}
	})
	return s
}
func sharedH3Transports() map[string]func() fhttp.RoundTripper {
	return map[string]func() fhttp.RoundTripper{
		"standard":       func() fhttp.RoundTripper { return NewHTTP3Transport(&tls.Config{InsecureSkipVerify: true}) },
		"uquic_fallback": func() fhttp.RoundTripper { return NewUQuicHTTP3Transport(&tls.Config{InsecureSkipVerify: true}, nil) },
		"roundtripper":   func() fhttp.RoundTripper { return NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil) },
		"custom_dial": func() fhttp.RoundTripper {
			rt := NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
			rt.Dialer = quic.DialAddrEarly
			return rt
		},
	}
}
func sharedH3Fetch(rt fhttp.RoundTripper, url string) error {
	req, _ := fhttp.NewRequest("GET", url, nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if string(body) != req.URL.Query().Get("id") {
		return fmt.Errorf("response %q, want %q", body, req.URL.Query().Get("id"))
	}
	return nil
}
func TestHTTP3SharedWarmReuse(t *testing.T) {
	for name, makeRT := range sharedH3Transports() {
		t.Run(name, func(t *testing.T) {
			s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, r.URL.Query().Get("id")) }))
			rt := makeRT()
			if c, ok := rt.(io.Closer); ok {
				defer c.Close()
			}
			for i := 0; i < 8; i++ {
				if err := sharedH3Fetch(rt, fmt.Sprintf("%s/?id=%d", s.url, i)); err != nil {
					t.Fatal(err)
				}
			}
			if n := s.connections.Load(); n != 1 {
				t.Fatalf("8 warm requests opened %d QUIC connections; want 1", n)
			}
		})
	}
}

func TestHTTP3SharedConcurrentIntegrity(t *testing.T) {
	for name, makeRT := range sharedH3Transports() {
		t.Run(name, func(t *testing.T) {
			var first atomic.Int64
			gate := make(chan struct{})
			arrived := make(chan struct{})
			s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if n := first.Add(1); n <= 128 {
					if n == 128 {
						close(arrived)
					}
					select {
					case <-gate:
					case <-r.Context().Done():
						return
					}
				}
				io.WriteString(w, r.URL.Query().Get("id"))
			}))
			rt := makeRT()
			if c, ok := rt.(io.Closer); ok {
				defer c.Close()
			}
			var wg sync.WaitGroup
			errors := make(chan error, 128)
			for worker := 0; worker < 128; worker++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					for j := 0; j < 8; j++ {
						if err := sharedH3Fetch(rt, fmt.Sprintf("%s/?id=%d-%d", s.url, worker, j)); err != nil {
							errors <- err
							return
						}
					}
				}(worker)
			}
			select {
			case <-arrived:
			case <-time.After(15 * time.Second):
				t.Error("128 HTTP3 streams did not overlap")
			}
			close(gate)
			wg.Wait()
			close(errors)
			for err := range errors {
				t.Error(err)
			}
			if n := s.connections.Load(); n != 1 {
				t.Errorf("1024 requests opened %d QUIC connections; want 1", n)
			}
		})
	}
}

func TestHTTP3SharedIdleCleanupPreservesStreams(t *testing.T) {
	for name, makeRT := range sharedH3Transports() {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if r.URL.Path == "/slow" {
					io.WriteString(w, "prefix:")
					w.(stdhttp.Flusher).Flush()
					select {
					case <-release:
						io.WriteString(w, "complete")
					case <-r.Context().Done():
						return
					}
					return
				}
				io.WriteString(w, r.URL.Query().Get("id"))
			}))
			rt := makeRT()
			closer, ok := rt.(interface {
				Close() error
				CloseIdleConnections()
			})
			if !ok {
				t.Fatal("transport lacks explicit lifecycle methods")
			}
			defer closer.Close()
			req, _ := fhttp.NewRequest("GET", s.url+"/slow", nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			prefix := make([]byte, 7)
			if _, err = io.ReadFull(resp.Body, prefix); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			req2, _ := fhttp.NewRequestWithContext(ctx, "GET", s.url+"/slow", nil)
			resp2, err := rt.RoundTrip(req2)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			_ = resp2.Body.Close()
			closer.CloseIdleConnections()
			if err = sharedH3Fetch(rt, s.url+"/?id=peer"); err != nil {
				t.Fatalf("partial close or idle cleanup interrupted peer: %v", err)
			}
			if n := s.connections.Load(); n != 1 {
				t.Fatalf("active stream's connection was replaced: %d", n)
			}
			// Closing the remaining stream completes deferred idle cleanup.
			_ = resp.Body.Close()
			peer := <-s.peers
			select {
			case <-peer.Context().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("idle QUIC connection was not released")
			}
			if err = sharedH3Fetch(rt, s.url+"/?id=after-idle"); err != nil {
				t.Fatal(err)
			}
			if n := s.connections.Load(); n != 2 {
				t.Fatalf("post-idle request opened %d total connections; want 2", n)
			}
			_ = closer.Close()
			peer = <-s.peers
			select {
			case <-peer.Context().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not release QUIC connection")
			}
			if err = sharedH3Fetch(rt, s.url+"/?id=closed"); err == nil {
				t.Fatal("closed transport accepted request")
			}
		})
	}
}

func TestHTTP3SharedCancellationAndPartialClosePreservePeerBody(t *testing.T) {
	for name, makeRT := range sharedH3Transports() {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				io.WriteString(w, "prefix:")
				w.(stdhttp.Flusher).Flush()
				select {
				case <-release:
					io.WriteString(w, r.URL.Query().Get("id"))
				case <-r.Context().Done():
				}
			}))
			rt := makeRT()
			defer rt.(io.Closer).Close()
			req, _ := fhttp.NewRequest("GET", s.url+"/?id=survives", nil)
			peer, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Body.Close()
			for i := 0; i < 32; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				req, _ = fhttp.NewRequestWithContext(ctx, "GET", s.url, nil)
				resp, err := rt.RoundTrip(req)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				prefix := make([]byte, 7)
				_, err = io.ReadFull(resp.Body, prefix)
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				if i%2 == 0 {
					cancel()
				}
				resp.Body.Close()
				cancel()
			}
			once.Do(func() { close(release) })
			body, err := io.ReadAll(peer.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "prefix:survives" {
				t.Fatalf("peer body=%q", body)
			}
			if n := s.connections.Load(); n != 1 {
				t.Fatalf("partial closes/cancellations created %d connections", n)
			}
		})
	}
}

func TestHTTP3RoundTripDoesNotFollowRedirects(t *testing.T) {
	for name, makeRT := range sharedH3Transports() {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int64
			s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				requests.Add(1)
				stdhttp.Redirect(w, r, "/target", stdhttp.StatusFound)
			}))
			rt := makeRT()
			defer rt.(io.Closer).Close()
			req, _ := fhttp.NewRequest("GET", s.url, nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 302 || requests.Load() != 1 {
				t.Fatalf("RoundTrip followed redirect: status=%d requests=%d", resp.StatusCode, requests.Load())
			}
		})
	}
}

func TestHTTP3ConcurrentCloseAndRequests(t *testing.T) {
	for name, makeRT := range sharedH3Transports() {
		t.Run(name, func(t *testing.T) {
			s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, r.URL.Query().Get("id")) }))
			rt := makeRT()
			closer := rt.(interface {
				Close() error
				CloseIdleConnections()
			})
			if err := sharedH3Fetch(rt, s.url+"/?id=warm"); err != nil {
				t.Fatal(err)
			}
			gate := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < 128; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-gate
					if i%3 == 0 {
						closer.Close()
					} else if i%3 == 1 {
						closer.CloseIdleConnections()
					} else {
						_ = sharedH3Fetch(rt, s.url+"/?id=race")
					}
				}(i)
			}
			close(gate)
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("concurrent Close deadlocked")
			}
			if err := sharedH3Fetch(rt, s.url); err == nil {
				t.Fatal("request succeeded after Close")
			}
		})
	}
}

func BenchmarkHTTP3SharedTransport(b *testing.B) {
	s := startSharedH3Server(b, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "payload") }))
	rt := NewHTTP3Transport(&tls.Config{InsecureSkipVerify: true})
	defer rt.Close()
	if err := sharedH3Fetch(rt, s.url+"/?id=payload"); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := sharedH3Fetch(rt, s.url+"/?id=payload"); err != nil {
				b.Error(err)
				return
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(s.connections.Load()), "connections")
}

func TestHTTP3PublicSharedRequestIPPreservesHostAndSNI(t *testing.T) {
	s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.TLS.ServerName != "logical.example.test" {
			stdhttp.Error(w, "wrong SNI: "+r.TLS.ServerName, 500)
			return
		}
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "logical.example.test" {
			stdhttp.Error(w, "wrong Host: "+r.Host, 500)
			return
		}
		io.WriteString(w, r.URL.Query().Get("id"))
	}))
	_, port, _ := net.SplitHostPort(s.url[len("https://"):])
	url := "https://logical.example.test:" + port
	client := Init()
	defer client.Close()
	opts := Options{ForceHTTP3: true, IP: "127.0.0.1", InsecureSkipVerify: true, EnableConnectionReuse: true, MaxResponseBodySize: -1, Timeout: 10}
	var wg sync.WaitGroup
	errs := make(chan error, 128)
	for worker := 0; worker < 128; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				id := fmt.Sprintf("%d-%d", worker, j)
				resp, err := client.Do(url+"/?id="+id, opts, "GET")
				if err != nil {
					errs <- err
					return
				}
				if resp.Status != 200 || resp.Body != id || resp.ResolvedIP != "127.0.0.1" {
					errs <- fmt.Errorf("status=%d body=%q IP=%q", resp.Status, resp.Body, resp.ResolvedIP)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := s.connections.Load(); n != 1 {
		t.Fatalf("public HTTP3 1024 requests opened %d connections; want 1", n)
	}
	CleanupClientPool(-time.Nanosecond)
	peer := <-s.peers
	select {
	case <-peer.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("pool cleanup did not close QUIC connection")
	}
}

func TestHTTP3PublicVerifiesTLSAndRejectsProxy(t *testing.T) {
	var hits atomic.Int64
	s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { hits.Add(1); io.WriteString(w, "ok") }))
	client := Init()
	defer client.Close()
	opts := Options{ForceHTTP3: true, EnableConnectionReuse: true, MaxResponseBodySize: -1, Timeout: 2}
	if resp, err := client.Do(s.url, opts, "GET"); err == nil && resp.Status == 200 {
		t.Fatal("untrusted certificate was accepted")
	}
	opts.InsecureSkipVerify = true
	opts.Proxy = "http://127.0.0.1:1"
	if resp, err := client.Do(s.url, opts, "GET"); err == nil && resp.Status == 200 {
		t.Fatal("HTTP3 silently bypassed HTTP proxy")
	}
	opts.Proxy = "socks5://127.0.0.1:1"
	if resp, err := client.Do(s.url, opts, "GET"); err == nil && resp.Status == 200 {
		t.Fatal("HTTP3 silently bypassed SOCKS proxy")
	}
	if hits.Load() != 0 {
		t.Fatal("rejected request reached origin")
	}
	CleanupClientPool(-time.Nanosecond)
}

type sharedH3ObservedContext struct {
	context.Context
	doneObserved chan struct{}
	once         sync.Once
}

func (c *sharedH3ObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.doneObserved) })
	return c.Context.Done()
}

func TestHTTP3CanceledDialOwnerDoesNotCancelWaitingPeer(t *testing.T) {
	s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, r.URL.Query().Get("id")) }))
	rt := NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
	defer rt.Close()
	dialing := make(chan struct{})
	release := make(chan struct{})
	rt.Dialer = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		close(dialing)
		select {
		case <-release:
			return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	firstCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstReq, _ := fhttp.NewRequestWithContext(firstCtx, "GET", s.url, nil)
	firstDone := make(chan error, 1)
	go func() {
		resp, err := rt.RoundTrip(firstReq)
		if resp != nil {
			resp.Body.Close()
		}
		firstDone <- err
	}()
	select {
	case <-dialing:
	case <-time.After(5 * time.Second):
		t.Fatal("dial did not begin")
	}
	secondCtx := &sharedH3ObservedContext{Context: context.Background(), doneObserved: make(chan struct{})}
	secondReq, _ := fhttp.NewRequestWithContext(secondCtx, "GET", s.url+"/?id=peer", nil)
	secondDone := make(chan error, 1)
	go func() {
		resp, err := rt.RoundTrip(secondReq)
		if err == nil {
			defer resp.Body.Close()
			var body []byte
			body, err = io.ReadAll(resp.Body)
			if err == nil && string(body) != "peer" {
				err = fmt.Errorf("peer body=%q", body)
			}
		}
		secondDone <- err
	}()
	select {
	case <-secondCtx.doneObserved:
	case <-time.After(5 * time.Second):
		t.Fatal("second request did not wait for shared dial")
	}
	cancel()
	select {
	case err := <-firstDone:
		if err == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled request did not return")
	}
	close(release)
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("first dial owner's cancellation interrupted peer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer did not complete")
	}
	if s.connections.Load() != 1 {
		t.Fatalf("connections=%d", s.connections.Load())
	}
}

func TestHTTP3CanceledColdDialAllowsNextRequest(t *testing.T) {
	s := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, r.URL.Query().Get("id")) }))
	rt := NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
	defer rt.Close()
	var calls atomic.Int64
	dialing := make(chan struct{})
	dialStopped := make(chan struct{})
	rt.Dialer = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if calls.Add(1) == 1 {
			close(dialing)
			<-ctx.Done()
			close(dialStopped)
			return nil, ctx.Err()
		}
		return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", s.url, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, _ := rt.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	<-dialing
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled request stuck")
	}
	select {
	case <-dialStopped:
	case <-time.After(5 * time.Second):
		t.Fatal("unneeded dial was not canceled")
	}
	if err := sharedH3Fetch(rt, s.url+"/?id=next"); err != nil {
		t.Fatalf("previous canceled dial poisoned new request: %v", err)
	}
}

func TestHTTP3CanceledDialDoesNotRemainAliveForUnrelatedOrigin(t *testing.T) {
	releaseBody := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(releaseBody) })
	origin := startSharedH3Server(t, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "prefix:")
		w.(stdhttp.Flusher).Flush()
		select {
		case <-releaseBody:
			io.WriteString(w, "alive")
		case <-r.Context().Done():
		}
	}))
	rt := NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
	defer rt.Close()
	dialing := make(chan struct{})
	stopped := make(chan struct{})
	rt.Dialer = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		if addr == "blocked.example.test:443" {
			close(dialing)
			<-ctx.Done()
			close(stopped)
			return nil, ctx.Err()
		}
		return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
	}
	req, _ := fhttp.NewRequest("GET", origin.url, nil)
	response, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocked, _ := fhttp.NewRequestWithContext(ctx, "GET", "https://blocked.example.test/", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r, _ := rt.RoundTrip(blocked)
		if r != nil {
			r.Body.Close()
		}
	}()
	select {
	case <-dialing:
	case <-time.After(5 * time.Second):
		t.Fatal("second origin dial did not begin")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("canceled request did not return")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("unrelated origin's body retained a canceled dial")
	}
	once.Do(func() { close(releaseBody) })
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "prefix:alive" {
		t.Fatalf("unrelated live body=%q", body)
	}
}

type sharedH3RequestBody struct {
	io.Reader
	closes atomic.Int64
}

func (b *sharedH3RequestBody) Close() error { b.closes.Add(1); return nil }
func TestHTTP3RejectedRequestClosesBody(t *testing.T) {
	for _, reason := range []string{"closed", "proxy", "canceled_lock"} {
		t.Run(reason, func(t *testing.T) {
			rt := &roundTripper{}
			ctx := context.Background()
			switch reason {
			case "closed":
				rt.closed = true
			case "proxy":
				rt.dialer = &connectDialer{}
			case "canceled_lock":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			body := &sharedH3RequestBody{Reader: strings.NewReader("upload")}
			req, _ := fhttp.NewRequestWithContext(ctx, "POST", "https://example.test/", body)
			if _, err := rt.roundTripHTTP3(req); err == nil {
				t.Fatal("request unexpectedly accepted")
			}
			if n := body.closes.Load(); n != 1 {
				t.Fatalf("rejected request body closed %d times; want 1", n)
			}
		})
	}
}
