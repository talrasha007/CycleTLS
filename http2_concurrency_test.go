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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
	"github.com/Danny-Dasilva/fhttp/http2"
	"github.com/Danny-Dasilva/fhttp/httptrace"
	xhttp2 "golang.org/x/net/http2"
)

func newConcurrentHTTP2Server(t *testing.T, limit uint32, handler stdhttp.Handler) (*httptest.Server, *contextHTTP2Transport, *atomic.Int32) {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = true
	if err := xhttp2.ConfigureServer(s.Config, &xhttp2.Server{MaxConcurrentStreams: limit}); err != nil {
		t.Fatal(err)
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	dials := new(atomic.Int32)
	p := newContextHTTP2Transport(&http2.Transport{}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}}).DialContext(ctx, network, addr)
	})
	t.Cleanup(p.CloseIdleConnections)
	return s, p, dials
}

func TestHTTP2ConcurrentCancellationAndIdleCleanup(t *testing.T) {
	const requests = 128
	finish := make(chan struct{})
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(finish) })
	s, p, dials := newConcurrentHTTP2Server(t, 256, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/fast" {
			io.WriteString(w, "fast")
			return
		}
		io.WriteString(w, "start:")
		w.(stdhttp.Flusher).Flush()
		select {
		case <-finish:
			io.WriteString(w, r.URL.Query().Get("id"))
		case <-r.Context().Done():
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var responses [requests]*http.Response
	var cancels [requests]context.CancelFunc
	var workers sync.WaitGroup
	for id := range responses {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			requestCtx, requestCancel := context.WithCancel(ctx)
			cancels[id] = requestCancel
			req, _ := http.NewRequestWithContext(requestCtx, "GET", s.URL+"/?id="+strconv.Itoa(id), nil)
			resp, err := p.RoundTrip(req)
			if err != nil {
				t.Errorf("request %d: %v", id, err)
				return
			}
			responses[id] = resp
		}(id)
	}
	workers.Wait()
	defer func() {
		for id, resp := range responses {
			cancels[id]()
			if resp != nil {
				resp.Body.Close()
			}
		}
	}()
	if t.Failed() {
		return
	}
	for id := 0; id < requests/2; id++ {
		cancels[id]()
		if _, err := io.ReadAll(responses[id].Body); !errors.Is(err, context.Canceled) {
			t.Errorf("request %d cancellation: %v", id, err)
		}
		responses[id].Body.Close()
	}
	for range 32 {
		p.CloseIdleConnections()
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/fast", nil)
	resp, err := p.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "fast" {
		t.Fatalf("new stream after peer cancellations: %q, %v", body, err)
	}
	finishOnce.Do(func() { close(finish) })
	for id := requests / 2; id < requests; id++ {
		body, err := io.ReadAll(responses[id].Body)
		responses[id].Body.Close()
		if err != nil || string(body) != "start:"+strconv.Itoa(id) {
			t.Errorf("peer stream %d interrupted: %q, %v", id, body, err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("cancellation/idle cleanup caused %d connections", got)
	}
}

func TestHTTP2CloseCancelsDialAndRejectsReuse(t *testing.T) {
	started := make(chan struct{})
	p := newContextHTTP2Transport(&http2.Transport{}, func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://example.invalid", nil)
	done := make(chan error, 1)
	go func() { _, err := p.RoundTrip(req); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	closer, ok := any(p).(io.Closer)
	if !ok {
		t.Fatal("HTTP/2 pool has no full shutdown")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed transport completed outstanding dial")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel outstanding dial")
	}
	if _, err := p.RoundTrip(req); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed transport reuse: %v", err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP2CancelQueuedStreamsPreservesActivePeer(t *testing.T) {
	finish := make(chan struct{})
	var finishOnce sync.Once
	defer finishOnce.Do(func() { close(finish) })
	s, p, dials := newConcurrentHTTP2Server(t, 1, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "start:")
		w.(stdhttp.Flusher).Flush()
		select {
		case <-finish:
			io.WriteString(w, "done")
		case <-r.Context().Done():
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	peer, err := p.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Body.Close()
	const queued = 128
	selected := make(chan struct{}, queued)
	done := make(chan error, queued)
	queuedCtx, cancelQueued := context.WithCancel(ctx)
	defer cancelQueued()
	queuedCtx = httptrace.WithClientTrace(queuedCtx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { selected <- struct{}{} }})
	for range queued {
		go func() {
			req, _ := http.NewRequestWithContext(queuedCtx, "POST", s.URL, io.NopCloser(strings.NewReader("queued payload")))
			resp, err := p.RoundTrip(req)
			if resp != nil {
				resp.Body.Close()
			}
			done <- err
		}()
	}
	for range queued {
		select {
		case <-selected:
		case <-ctx.Done():
			t.Fatal("queued streams did not obtain shared connection")
		}
	}
	cancelQueued()
	for range queued {
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("queued cancellation: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("queued cancellation blocked behind active stream")
		}
	}
	p.CloseIdleConnections()
	finishOnce.Do(func() { close(finish) })
	body, err := io.ReadAll(peer.Body)
	if err != nil || string(body) != "start:done" {
		t.Fatalf("queued cancellation interrupted active peer: %q, %v", body, err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("queued requests opened %d connections", got)
	}
}

func TestHTTP2CloseAbortsActiveStreams(t *testing.T) {
	s, p, _ := newConcurrentHTTP2Server(t, 256, stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "start")
		w.(stdhttp.Flusher).Flush()
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	resp, err := p.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("full shutdown did not abort active stream")
	}
	if _, err := p.RoundTrip(req); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed pool reused: %v", err)
	}
}

// A shared transport must obey even a one-stream peer without connection churn,
// retry backoff, or replaying a POST merely because other callers filled it.
func TestHTTP2ConcurrentStreamLimits(t *testing.T) {
	for _, tc := range []struct{ concurrency, limit int }{{128, 1}, {128, 8}, {256, 256}} {
		t.Run(fmt.Sprintf("workers_%d_streams_%d", tc.concurrency, tc.limit), func(t *testing.T) {
			const requests = 1024
			var seen [requests]atomic.Int32
			var active, peak atomic.Int32
			s, p, dials := newConcurrentHTTP2Server(t, uint32(tc.limit), stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if r.URL.Path == "/warmup" {
					io.WriteString(w, "ready")
					return
				}
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				id, err := strconv.Atoi(r.URL.Query().Get("id"))
				if err != nil || id < 0 || id >= requests {
					stdhttp.Error(w, "bad id", 400)
					return
				}
				seen[id].Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return
				}
				// Hold slots long enough for concurrently admitted requests to
				// exercise the server's SETTINGS_MAX_CONCURRENT_STREAMS limit.
				time.Sleep(time.Millisecond)
				w.Header().Set("X-Request-ID", strconv.Itoa(id))
				fmt.Fprintf(w, "%s:%d:%s", r.Method, id, body)
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			warmup, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/warmup", nil)
			resp, err := p.RoundTrip(warmup)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			start := make(chan struct{})
			errors := make(chan error, requests)
			var workers sync.WaitGroup
			began := time.Now()
			for worker := 0; worker < tc.concurrency; worker++ {
				workers.Add(1)
				go func(worker int) {
					defer workers.Done()
					<-start
					for id := worker; id < requests; id += tc.concurrency {
						method, payload := "GET", ""
						var body io.Reader
						if id%3 != 0 {
							method, payload = "POST", strings.Repeat(fmt.Sprintf("request-%d/", id), 256)
							body = strings.NewReader(payload)
							if id%3 == 2 {
								body = io.NopCloser(body) // Deliberately no GetBody replay hook.
							}
						}
						req, _ := http.NewRequestWithContext(ctx, method, s.URL+"/?id="+strconv.Itoa(id), body)
						resp, err := p.RoundTrip(req)
						if err != nil {
							errors <- fmt.Errorf("request %d: %w", id, err)
							return
						}
						got, err := io.ReadAll(resp.Body)
						resp.Body.Close()
						want := fmt.Sprintf("%s:%d:%s", method, id, payload)
						if err != nil || resp.ProtoMajor != 2 || resp.Header.Get("X-Request-ID") != strconv.Itoa(id) || string(got) != want {
							errors <- fmt.Errorf("request %d: corrupt response, protocol %s, read error %v", id, resp.Proto, err)
							return
						}
					}
				}(worker)
			}
			close(start)
			workers.Wait()
			close(errors)
			for err := range errors {
				t.Error(err)
			}
			if t.Failed() {
				return
			}
			for id := range seen {
				if got := seen[id].Load(); got != 1 {
					t.Fatalf("request %d reached handler %d times", id, got)
				}
			}
			if got := dials.Load(); got != 1 {
				t.Errorf("stream limit caused connection churn: %d dials", got)
			}
			if got := peak.Load(); got > int32(tc.limit) {
				t.Errorf("server had %d simultaneous handlers with stream limit %d", got, tc.limit)
			}
			t.Logf("%d requests, %d workers, peak %d handlers, %d dials, %s", requests, tc.concurrency, peak.Load(), dials.Load(), time.Since(began))
		})
	}
}

type flushingHTTP2ProxyWriter struct{ stdhttp.ResponseWriter }

func (w flushingHTTP2ProxyWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.ResponseWriter.(stdhttp.Flusher).Flush()
	return n, err
}

func TestHTTP2ProxyConnectSetupStillHonorsCancellation(t *testing.T) {
	started, abandoned := make(chan struct{}), make(chan struct{})
	proxy := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		close(started)
		<-r.Context().Done()
		close(abandoned)
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	defer proxy.CloseClientConnections()
	dialer, err := newConnectDialer(proxy.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := dialer.DialContext(ctx, "tcp", "example.invalid:443")
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("CONNECT setup never reached proxy")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("CONNECT cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT setup ignored cancellation")
	}
	select {
	case <-abandoned:
	case <-time.After(time.Second):
		t.Fatal("canceled CONNECT left its server stream active")
	}
}

func TestHTTP2ProxyTunnelSurvivesRequestCompletionAndReconnect(t *testing.T) {
	finish := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var finished [2]sync.Once
	defer func() {
		for phase := range finish {
			finished[phase].Do(func() { close(finish[phase]) })
		}
	}()
	origin := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.URL.Path == "/active" {
			io.WriteString(w, "active:")
			w.(stdhttp.Flusher).Flush()
			phase, _ := strconv.Atoi(r.URL.Query().Get("phase"))
			select {
			case <-finish[phase]:
			case <-r.Context().Done():
				return
			}
		}
		io.WriteString(w, "origin response")
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	var tunnels atomic.Int32
	proxy := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != "CONNECT" || r.ProtoMajor != 2 {
			stdhttp.Error(w, "expected HTTP/2 CONNECT", 400)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			stdhttp.Error(w, err.Error(), 502)
			return
		}
		defer upstream.Close()
		tunnels.Add(1)
		w.WriteHeader(200)
		w.(stdhttp.Flusher).Flush()
		forwarded := make(chan struct{})
		go func() {
			defer close(forwarded)
			io.Copy(upstream, r.Body)
			upstream.Close()
		}()
		io.Copy(flushingHTTP2ProxyWriter{w}, upstream)
		r.Body.Close()
		<-forwarded
	}))
	proxy.EnableHTTP2 = true
	proxy.StartTLS()
	defer proxy.Close()
	dialer, err := newConnectDialer(proxy.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	rt := newRoundTripper(Browser{InsecureSkipVerify: true}, dialer).(*roundTripper)
	defer rt.Close()
	request := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", origin.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.ProtoMajor != 2 || string(body) != "origin response" {
			t.Fatalf("response through proxy: %q, %v (%s)", body, err, resp.Proto)
		}
	}
	for phase := range finish {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ownerCtx, cancelOwner := context.WithCancel(ctx)
		defer cancelOwner()
		activeURL := origin.URL + "/active?phase=" + strconv.Itoa(phase)
		ownerReq, _ := http.NewRequestWithContext(ownerCtx, "GET", activeURL, nil)
		owner, err := rt.RoundTrip(ownerReq)
		if err != nil {
			t.Fatalf("phase %d tunnel owner: %v", phase, err)
		}
		defer owner.Body.Close()
		peerReq, _ := http.NewRequestWithContext(ctx, "GET", activeURL, nil)
		peer, err := rt.RoundTrip(peerReq)
		if err != nil {
			t.Fatalf("phase %d active peer: %v", phase, err)
		}
		defer peer.Body.Close()
		request()     // Completing a request must leave both active peers alive.
		cancelOwner() // Even the request which created CONNECT owns only its origin stream.
		if _, err := io.ReadAll(owner.Body); !errors.Is(err, context.Canceled) {
			t.Fatalf("phase %d canceled owner: %v", phase, err)
		}
		owner.Body.Close()
		request()
		finished[phase].Do(func() { close(finish[phase]) })
		body, err := io.ReadAll(peer.Body)
		peer.Body.Close()
		if err != nil || string(body) != "active:origin response" {
			t.Fatalf("phase %d tunnel owner cancellation interrupted peer: %q, %v", phase, body, err)
		}
		request()
		if got := tunnels.Load(); got != int32(phase+1) {
			t.Fatalf("phase %d completion/cancellation discarded shared tunnel: %d CONNECTs", phase, got)
		}
		rt.CloseIdleConnections() // Next phase exercises the H2 wrapper's reconnect path.
	}
}
