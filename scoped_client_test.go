package cycletls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"
)

func scopedTestServer(t *testing.T, limit uint32, handler stdhttp.Handler) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = true
	if err := xhttp2.ConfigureServer(s.Config, &xhttp2.Server{MaxConcurrentStreams: limit}); err != nil {
		t.Fatal(err)
	}
	total, live := new(atomic.Int32), new(atomic.Int32)
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			total.Add(1)
			live.Add(1)
		}
		if state == stdhttp.StateClosed {
			live.Add(-1)
		}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, total, live
}

func awaitScopedConnections(t *testing.T, live *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for live.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("live connections=%d, want %d", live.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestScopedClientMultiplexesWithoutRotation(t *testing.T) {
	s, connections, live := scopedTestServer(t, 8, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol=%s", r.Proto)
		}
		time.Sleep(time.Millisecond)
		io.WriteString(w, r.URL.Query().Get("id"))
	}))
	c, err := NewClient(Options{Ja3: "RAND", SignatureAlgorithms: "RAND", InsecureSkipVerify: true, MaxResponseBodySize: -1, Timeout: 10, MaxTotalRequests: 2, EnableConnectionReuse: false})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var wg sync.WaitGroup
	for worker := 0; worker < 128; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				id := fmt.Sprintf("%d-%d", worker, i)
				r, err := c.Do(s.URL+"/?id="+id, "GET")
				if err != nil || r.Status != 200 || r.Body != id {
					t.Errorf("request %s: status=%d body=%q err=%v", id, r.Status, r.Body, err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	if n := connections.Load(); n != 1 {
		t.Fatalf("1024 requests opened %d connections, want 1", n)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	awaitScopedConnections(t, live, 0)
	if _, err := c.Do(s.URL, "GET"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("request after Close: %v", err)
	}
}

func TestScopedClientsOwnTheirConnections(t *testing.T) {
	s, connections, live := scopedTestServer(t, 256, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }))
	opts := Options{InsecureSkipVerify: true, MaxResponseBodySize: -1, EnableConnectionReuse: true}
	a, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, c := range []*Client{a, b} {
		if r, err := c.Do(s.URL, "GET"); err != nil || r.Body != "ok" {
			t.Fatalf("private request: %+v %v", r, err)
		}
	}
	pooled := Init()
	defer pooled.Close()
	if r, err := pooled.Do(s.URL, opts, "GET"); err != nil || r.Body != "ok" {
		t.Fatalf("pooled request: %+v %v", r, err)
	}
	if n := connections.Load(); n != 3 {
		t.Fatalf("independent clients opened %d connections, want 3", n)
	}
	a.Close()
	awaitScopedConnections(t, live, 2)
	// Global cleanup must leave the private client's connection intact.
	clearAllConnections()
	awaitScopedConnections(t, live, 1)
	if r, err := b.Do(s.URL, "GET"); err != nil || r.Body != "ok" {
		t.Fatalf("surviving client: %+v %v", r, err)
	}
	if n := connections.Load(); n != 3 {
		t.Fatalf("cleanup replaced surviving client's connection: %d", n)
	}
	b.Close()
	awaitScopedConnections(t, live, 0)
}

func TestScopedClientCloseCancelsActiveAndQueuedRequests(t *testing.T) {
	for _, body := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%t", body), func(t *testing.T) {
			started := make(chan struct{}, 1)
			s, connections, live := scopedTestServer(t, 1, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if body {
					io.WriteString(w, "partial")
					w.(stdhttp.Flusher).Flush()
				}
				select {
				case started <- struct{}{}:
				default:
				}
				<-r.Context().Done()
			}))
			c, err := NewClient(Options{InsecureSkipVerify: true, MaxResponseBodySize: -1, Timeout: 30})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var wg sync.WaitGroup
			var failures atomic.Int32
			for i := 0; i < 128; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := c.Do(s.URL, "GET")
					if err != nil {
						failures.Add(1)
					}
				}()
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("no active request")
			}
			done := make(chan struct{})
			go func() {
				var closers sync.WaitGroup
				for i := 0; i < 16; i++ {
					closers.Add(1)
					go func() { defer closers.Done(); c.Close() }()
				}
				closers.Wait()
				wg.Wait()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("Close did not cancel active/queued requests")
			}
			if failures.Load() != 128 {
				t.Fatalf("only %d requests observed cancellation/closure", failures.Load())
			}
			awaitScopedConnections(t, live, 0)
			if n := connections.Load(); n != 1 {
				t.Fatalf("queued work opened %d connections", n)
			}
		})
	}
}

func TestScopedClientSnapshotsOptionsAndReclaimsRepeatedUse(t *testing.T) {
	s, _, live := scopedTestServer(t, 256, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s|%s|%s", r.Header.Get("X-Value"), r.Header.Get("Cookie"), body)
	}))
	baseline := runtime.NumGoroutine()
	for i := 0; i < 32; i++ {
		opts := Options{InsecureSkipVerify: true, MaxResponseBodySize: -1, Headers: map[string]string{"X-Value": "original"}, Cookies: []Cookie{{Name: "session", Value: "one"}}, BodyBytes: []byte("body")}
		c, err := NewClient(opts)
		if err != nil {
			t.Fatal(err)
		}
		opts.Headers["X-Value"] = "changed"
		opts.Cookies[0].Value = "other"
		opts.BodyBytes[0] = 'x'
		r, err := c.DoContext(context.Background(), s.URL, "POST")
		c.Close()
		if err != nil || r.Body != "original|session=one|body" {
			t.Fatalf("request inherited external mutation: %+v %v", r, err)
		}
		awaitScopedConnections(t, live, 0)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseline+4 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline+4 {
		t.Fatalf("goroutines grew from %d to %d", baseline, n)
	}
}

func TestScopedClientCloseCancelsTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started, peerClosed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(peerClosed)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var first [1]byte
		if _, err := conn.Read(first[:]); err != nil {
			return
		}
		close(started)
		io.Copy(io.Discard, conn) // Accept ClientHello without replying.
	}()
	c, err := NewClient(Options{InsecureSkipVerify: true, Timeout: 30})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	result := make(chan error, 1)
	go func() { _, err := c.Do("https://"+listener.Addr().String(), "GET"); result <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not start")
	}
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for handshake timeout")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("handshake error=%v", err)
	}
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("handshake socket remained open")
	}
}

func TestScopedClientDeadlineDoesNotDiscardHealthyConnection(t *testing.T) {
	started := make(chan struct{})
	s, connections, live := scopedTestServer(t, 256, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/slow" {
			io.WriteString(w, "partial")
			w.(stdhttp.Flusher).Flush()
			close(started)
			<-r.Context().Done()
			return
		}
		io.WriteString(w, "ok")
	}))
	c, err := NewClient(Options{InsecureSkipVerify: true, MaxResponseBodySize: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := c.DoContext(ctx, s.URL+"/slow", "GET"); result <- err }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("slow stream did not start")
	}
	for i := 0; i < 2; i++ {
		if r, err := c.Do(s.URL, "GET"); err != nil || r.Body != "ok" {
			t.Fatalf("peer request: %+v %v", r, err)
		}
		if i == 0 {
			if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline error=%v", err)
			}
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("request deadline replaced healthy connection")
	}
	// An explicitly failed connection may be replaced.
	s.CloseClientConnections()
	awaitScopedConnections(t, live, 0)
	if r, err := c.Do(s.URL, "GET"); err != nil || r.Body != "ok" {
		t.Fatalf("reconnection: %+v %v", r, err)
	}
	if connections.Load() != 2 {
		t.Fatalf("reconnection count=%d", connections.Load())
	}
}

func TestScopedClientRejectsForcedConnectionClose(t *testing.T) {
	if _, err := NewClient(Options{Headers: map[string]string{"connection": "keep-alive, Close"}}); err == nil {
		t.Fatal("accepted request defaults that forbid persistent connections")
	}
}
