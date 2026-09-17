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
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	xhttp2 "golang.org/x/net/http2"
)

// Windows supplies an OS handle count in reuse256_windows_test.go. Other
// platforms still assert peer closure, pool references and goroutine recovery.
var reuse256HandleCount = func() uint32 { return 0 }

type reuse256PeerKey struct{}
type reuse256Peer struct {
	requests atomic.Int64
	active   atomic.Int64
	peak     atomic.Int64
	closed   atomic.Bool
}
type reuse256Server struct {
	url    string
	mu     sync.Mutex
	peers  []*reuse256Peer
	live   atomic.Int64
	active atomic.Int64
}

func (s *reuse256Server) peer() *reuse256Peer {
	p := new(reuse256Peer)
	s.mu.Lock()
	s.peers = append(s.peers, p)
	s.mu.Unlock()
	s.live.Add(1)
	return p
}
func (s *reuse256Server) closed(p *reuse256Peer) {
	if p.closed.CompareAndSwap(false, true) {
		s.live.Add(-1)
	}
}

func startReuse256Server(t *testing.T, protocol string) *reuse256Server {
	t.Helper()
	s := new(reuse256Server)
	handler := stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		p := r.Context().Value(reuse256PeerKey{}).(*reuse256Peer)
		p.requests.Add(1)
		n := p.active.Add(1)
		for old := p.peak.Load(); n > old && !p.peak.CompareAndSwap(old, n); old = p.peak.Load() {
		}
		s.active.Add(1)
		defer p.active.Add(-1)
		defer s.active.Add(-1)
		switch r.URL.Query().Get("mode") {
		case "headers":
			<-r.Context().Done()
			return
		case "body":
			io.WriteString(w, "partial:")
			w.(stdhttp.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		// Give concurrent streams time to overlap while keeping the response
		// much shorter than the 2-second client timeout in mixed traffic.
		time.Sleep(2 * time.Millisecond)
		io.WriteString(w, r.URL.Query().Get("id"))
	})
	if protocol == "http2" {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		if err := xhttp2.ConfigureServer(server.Config, &xhttp2.Server{MaxConcurrentStreams: 256}); err != nil {
			t.Fatal(err)
		}
		var peers sync.Map
		server.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
			p := s.peer()
			peers.Store(conn, p)
			return context.WithValue(ctx, reuse256PeerKey{}, p)
		}
		server.Config.ConnState = func(conn net.Conn, state stdhttp.ConnState) {
			if state == stdhttp.StateClosed {
				if p, ok := peers.LoadAndDelete(conn); ok {
					s.closed(p.(*reuse256Peer))
				}
			}
		}
		server.StartTLS()
		s.url = server.URL
		t.Cleanup(server.Close)
	} else {
		cert := httptest.NewTLSServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
		config := cert.TLS.Clone()
		cert.Close()
		udp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		s.url = "https://" + udp.LocalAddr().String()
		server := &http3.Server{TLSConfig: config, QUICConfig: &quic.Config{MaxIncomingStreams: 256}, Handler: handler,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				p := s.peer()
				context.AfterFunc(conn.Context(), func() { s.closed(p) })
				return context.WithValue(ctx, reuse256PeerKey{}, p)
			}}
		done := make(chan struct{})
		go func() { defer close(done); _ = server.Serve(udp) }()
		t.Cleanup(func() { server.Close(); udp.Close(); <-done })
	}
	return s
}

func (s *reuse256Server) drained(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.live.Load() != 0 || s.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("resources survived completed generations: live connections=%d active handlers=%d", s.live.Load(), s.active.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	advancedClientPoolMutex.RLock()
	entries := len(advancedClientPool)
	advancedClientPoolMutex.RUnlock()
	if entries != 0 {
		t.Fatalf("completed 256-request generations left %d registry entries", entries)
	}
}

type reuse256Resources struct {
	goroutines  int
	handles     uint32
	heapBytes   uint64
	heapObjects uint64
}

func sampleReuse256Resources() reuse256Resources {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return reuse256Resources{runtime.NumGoroutine(), reuse256HandleCount(), m.HeapAlloc, m.HeapObjects}
}

func reuse256Wave(t *testing.T, s *reuse256Server, protocol string, requests, workers int, mixed bool) {
	t.Helper()
	s.mu.Lock()
	initialConnections := len(s.peers)
	s.mu.Unlock()
	c := Init()
	// Do not clear the registry between waves: exact generation rollover must
	// close sockets without the test masking leaks via CleanupClientPool.
	opts := Options{EnableConnectionReuse: true, MaxTotalRequests: 256, InsecureSkipVerify: true, ForceHTTP3: protocol == "http3", Timeout: 10, MaxResponseBodySize: -1}
	if mixed {
		opts.Timeout = 2
	}
	var next atomic.Int64
	var successes, headerTimeouts, bodyTimeouts atomic.Int64
	var inFlight, peakCalls atomic.Int64
	start := make(chan struct{})
	latencies := make([]time.Duration, requests)
	problems := make(chan string, requests)
	var wg sync.WaitGroup
	started := time.Now()
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				id := int(next.Add(1) - 1)
				if id >= requests {
					return
				}
				mode := "ok"
				if mixed {
					if id%16 == 0 {
						mode = "headers"
					}
					if id%16 == 1 {
						mode = "body"
					}
				}
				begin := time.Now()
				n := inFlight.Add(1)
				for old := peakCalls.Load(); n > old && !peakCalls.CompareAndSwap(old, n); old = peakCalls.Load() {
				}
				resp, err := c.Do(s.url+"/?id="+strconv.Itoa(id)+"&mode="+mode, opts, "GET")
				inFlight.Add(-1)
				elapsed := time.Since(begin)
				latencies[id] = elapsed
				if mode == "ok" {
					if err != nil || resp.Status != 200 || resp.Body != strconv.Itoa(id) {
						problems <- fmt.Sprintf("unexpected failure id=%d status=%d err=%v body=%q duration=%s", id, resp.Status, err, resp.Body, elapsed)
					} else {
						successes.Add(1)
					}
					continue
				}
				isTimeout := errors.Is(err, context.DeadlineExceeded)
				var netErr net.Error
				isTimeout = isTimeout || (errors.As(err, &netErr) && netErr.Timeout())
				// Public Do preserves its legacy error-as-response behavior before
				// headers, while a body read timeout is returned as a Go error.
				if mode == "headers" && err == nil {
					isTimeout = resp.Status != 200 && (strings.Contains(resp.Body, "deadline exceeded") || strings.Contains(resp.Body, "Client.Timeout"))
				}
				if !isTimeout || elapsed < 1900*time.Millisecond || elapsed > 4*time.Second {
					problems <- fmt.Sprintf("bad timeout id=%d mode=%s duration=%s status=%d err=%v body=%q", id, mode, elapsed, resp.Status, err, resp.Body)
				} else if mode == "headers" {
					headerTimeouts.Add(1)
				} else {
					bodyTimeouts.Add(1)
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(problems)
	for problem := range problems {
		t.Error(problem)
	}
	if t.Failed() {
		c.Close()
		t.FailNow()
	}
	s.drained(t)
	s.mu.Lock()
	connections := len(s.peers) - initialConnections
	var peak int64
	for _, peer := range s.peers[initialConnections:] {
		if n := peer.requests.Load(); n != 256 {
			t.Errorf("connection handled %d requests, want 256", n)
		}
		if n := peer.peak.Load(); n > peak {
			peak = n
		}
		if peer.peak.Load() > 256 {
			t.Error("server stream limit exceeded")
		}
	}
	s.mu.Unlock()
	if connections != requests/256 {
		t.Errorf("connections=%d want %d", connections, requests/256)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	t.Logf("requests=%d workers=%d peak_calls=%d mixed=%t ok=%d header_timeouts=%d body_timeouts=%d connections=%d peak_streams_per_connection=%d p99=%s max=%s elapsed=%s", requests, workers, peakCalls.Load(), mixed, successes.Load(), headerTimeouts.Load(), bodyTimeouts.Load(), connections, peak, latencies[(requests-1)*99/100], latencies[requests-1], time.Since(started))
}

func TestReuse256HighConcurrencyTimeoutAndResources(t *testing.T) {
	if testing.Short() {
		t.Skip("real HTTP2/HTTP3 high-concurrency lifecycle stress")
	}
	for _, protocol := range []string{"http2", "http3"} {
		t.Run(protocol, func(t *testing.T) {
			clearAllConnections()
			s := startReuse256Server(t, protocol)
			t.Cleanup(clearAllConnections)
			// Warm transport caches and worker/runtime allocation before sampling.
			reuse256Wave(t, s, protocol, 4096, 1024, false)
			time.Sleep(100 * time.Millisecond)
			baseline := sampleReuse256Resources()
			t.Logf("resource baseline: %+v", baseline)
			for cycle := 1; cycle <= 3; cycle++ {
				reuse256Wave(t, s, protocol, 4096, 1024, true)
				reuse256Wave(t, s, protocol, 4096, 1024, false)
				time.Sleep(100 * time.Millisecond)
				t.Logf("resource cycle %d: %+v", cycle, sampleReuse256Resources())
			}
			deadline := time.Now().Add(5 * time.Second)
			for runtime.NumGoroutine() > baseline.goroutines+8 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			final := sampleReuse256Resources()
			if final.goroutines > baseline.goroutines+8 {
				var stacks strings.Builder
				pprof.Lookup("goroutine").WriteTo(&stacks, 2)
				t.Errorf("goroutines did not recover: baseline=%d final=%d\n%s", baseline.goroutines, final.goroutines, stacks.String())
			}
			// Runtime worker threads can create a few handles after warmup. A
			// socket-per-generation leak would exceed this allowance manyfold.
			if final.handles > baseline.handles+16 {
				t.Errorf("OS handles grew: baseline=%d final=%d", baseline.handles, final.handles)
			}
			t.Logf("resource final: %+v; live connections=%d active handlers=%d", final, s.live.Load(), s.active.Load())
		})
	}
}
