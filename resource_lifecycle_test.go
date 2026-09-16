package cycletls

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	fhttp "github.com/Danny-Dasilva/fhttp"
	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const lifecycleTestTimeout = 2 * time.Second

type pipeDialer struct{ conn net.Conn }

type contextDialFunc func(context.Context, string, string) (net.Conn, error)

func (f contextDialFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func awaitClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("connection or operation did not close")
	}
}

func connectionClosedChannel(s *httptest.Server) <-chan struct{} {
	closed := make(chan struct{}, 16)
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateClosed {
			closed <- struct{}{}
		}
	}
	return closed
}

func TestHTTPIdleConnectionsAreClosed(t *testing.T) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	}))
	closed := connectionClosedChannel(s)
	s.Start()
	defer s.Close()
	rt := newRoundTripper(Browser{}).(*roundTripper)
	resp, err := (&fhttp.Client{Transport: rt}).Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	defer func() { // Also clean up when testing the broken implementation.
		for addr := range rt.cachedTransports {
			rt.closeCachedTransport(addr)
		}
	}()
	rt.CloseIdleConnections()
	awaitClosed(t, closed)
}

func TestHTTPDefaultPortConnectionSurvivesSelectiveCleanup(t *testing.T) {
	var connections atomic.Int32
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }))
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			connections.Add(1)
		}
	}
	s.Start()
	defer s.Close()
	dial := contextDialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	})
	rt := newRoundTripper(Browser{}, dial).(*roundTripper)
	defer rt.CloseIdleConnections()
	c := &fhttp.Client{Transport: rt}
	for i := 0; i < 2; i++ {
		resp, err := c.Get("http://example.test/")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		rt.closeIdleConnectionsExcept("example.test:80")
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections=%d, want 1", got)
	}
}

func TestFingerprintFailureClosesConnection(t *testing.T) {
	for _, attempt := range []string{"initial", "tls13-retry", "tls12-retry"} {
		t.Run(attempt, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			rt := newRoundTripper(Browser{JA3: "invalid,4865,0,29,0"}, pipeDialer{a}).(*roundTripper)
			var err error
			switch attempt {
			case "initial":
				_, err = rt.dialTLSImpl(context.Background(), "tcp", "example.com:443")
			case "tls13-retry":
				_, err = rt.retryWithTLS13CompatibleCurves(context.Background(), "tcp", "example.com:443", "example.com")
			case "tls12-retry":
				_, err = rt.retryWithOriginalTLS12JA3(context.Background(), "tcp", "example.com:443", "example.com")
			}
			if err == nil {
				t.Fatal("expected invalid fingerprint error")
			}
			b.SetReadDeadline(time.Now().Add(lifecycleTestTimeout))
			if _, err = b.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("peer connection still open: %v", err)
			}
		})
	}
}

func TestHandshakeCancellation(t *testing.T) {
	for _, kind := range []string{"tls", "http-proxy", "https-proxy"} {
		t.Run(kind, func(t *testing.T) {
			a, b := net.Pipe()
			readDone := make(chan struct{})
			started := make(chan struct{})
			go func() {
				defer close(readDone)
				if _, err := b.Read(make([]byte, 4096)); err == nil {
					close(started)
					io.Copy(io.Discard, b)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			defer func() { cancel(); a.Close(); b.Close(); awaitClosed(t, done); awaitClosed(t, readDone) }()
			go func() {
				defer close(done)
				if kind == "tls" {
					rt := newRoundTripper(Browser{}, pipeDialer{a}).(*roundTripper)
					_, _ = rt.dialTLS(ctx, "tcp", "example.com:443")
				} else {
					u, _ := url.Parse(map[string]string{"http-proxy": "http://127.0.0.1:8080", "https-proxy": "https://127.0.0.1:8080"}[kind])
					d := &connectDialer{ProxyURL: *u, Dialer: pipeDialer{a}}
					_, _ = d.DialContext(ctx, "tcp", "example.com:443")
				}
			}()
			awaitClosed(t, started)
			cancel()
			awaitClosed(t, done)
		})
	}
}

func TestHTTP1ReuseWithDefaultPoolLimits(t *testing.T) {
	var connections atomic.Int32
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }))
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			connections.Add(1)
		}
	}
	s.StartTLS()
	defer s.Close()
	c := Init()
	defer c.Close()
	for i := 0; i < 2; i++ {
		r, err := c.Do(s.URL, Options{ForceHTTP1: true, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxResponseBodySize: -1}, "GET")
		if err != nil || r.Status != 200 {
			t.Fatalf("request failed: %+v %v", r, err)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("connections=%d, want 1", got)
	}
}

func TestCanceledResponseDoesNotBlockOnConsumer(t *testing.T) {
	s := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", s.URL, nil)
	res := fullRequest{req: req, client: fhttp.Client{Transport: newRoundTripper(Browser{})}, options: cycleTLSRequest{Options: Options{URL: s.URL}}}
	out := make(chan []byte)
	done := make(chan struct{})
	go func() { dispatcherAsync(res, out); close(done) }()
	defer func() {
		cancel()
		go func() {
			for {
				select {
				case <-out:
				case <-done:
					return
				}
			}
		}()
		awaitClosed(t, done)
	}()
	cancel()
	awaitClosed(t, done)
}

func TestWebSocketEndpointDisconnectCancelsUpstream(t *testing.T) {
	peers := make(chan *websocket.Conn, 1)
	upstream := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			peers <- conn
		}
	}))
	defer upstream.Close()
	endpointDone := make(chan struct{})
	s := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { defer close(endpointDone); WSEndpoint(w, r) }))
	defer s.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+s.URL[4:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	err = conn.WriteJSON(cycleTLSRequest{RequestID: "test-endpoint-cancel", Options: Options{URL: upstream.URL, Protocol: "websocket"}})
	if err != nil {
		t.Fatal(err)
	}
	var peer *websocket.Conn
	select {
	case peer = <-peers:
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("upstream did not connect")
	}
	defer peer.Close()
	conn.Close()
	peer.SetReadDeadline(time.Now().Add(lifecycleTestTimeout))
	_, _, err = peer.ReadMessage()
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("upstream websocket survived downstream disconnect")
	}
	awaitClosed(t, endpointDone)
}

func TestBrowserSSECloseReleasesTransport(t *testing.T) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: done\n\n")
	}))
	s.EnableHTTP2 = true
	closed := connectionClosedChannel(s)
	s.StartTLS()
	defer s.Close()
	r, err := (Browser{InsecureSkipVerify: true}).SSEConnect(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer r.client.HTTPClient.CloseIdleConnections()
	for {
		_, err = r.NextEvent()
		if err != nil {
			break
		}
	}
	if !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	r.Close()
	awaitClosed(t, closed)
}

func TestHTTP3CustomDialReceivesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", "https://example.com/", nil)
	rt := NewHTTP3RoundTripper(nil, nil)
	entered := make(chan struct{})
	observed := make(chan error, 1)
	rt.Dialer = func(dialCtx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		close(entered)
		select {
		case <-dialCtx.Done():
			observed <- dialCtx.Err()
			return nil, dialCtx.Err()
		case <-time.After(lifecycleTestTimeout):
			observed <- nil
			return nil, errors.New("dial was not canceled")
		}
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = rt.RoundTrip(req) }()
	awaitClosed(t, entered)
	cancel()
	if err := <-observed; !errors.Is(err, context.Canceled) {
		t.Errorf("dial cancellation=%v", err)
	}
	awaitClosed(t, done)
}

func TestProxyCleanupDoesNotAbortActiveTunnels(t *testing.T) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(200)
		w.(stdhttp.Flusher).Flush()
		buf := make([]byte, 16)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				w.(stdhttp.Flusher).Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	s.EnableHTTP2 = true
	closed := connectionClosedChannel(s)
	s.StartTLS()
	defer s.Close()
	dialer, err := newConnectDialer(s.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.(*connectDialer)
	first, err := d.DialContext(context.Background(), "tcp", "one.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := d.DialContext(context.Background(), "tcp", "two.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	first.Close()
	d.CloseIdleConnections()
	second.SetDeadline(time.Now().Add(lifecycleTestTimeout))
	if _, err = second.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err = io.ReadFull(second, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("active tunnel was interrupted: %q %v", buf, err)
	}
	second.Close()
	awaitClosed(t, closed)
}

func TestWebSocketCloseReleasesSocketAfterWriteFailure(t *testing.T) {
	peers := make(chan *websocket.Conn, 1)
	s := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			peers <- conn
		}
	}))
	defer s.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+s.URL[4:], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-peers
	defer peer.Close()
	// Make the connection's write state fail before closing the response.
	conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if err = conn.WriteMessage(websocket.TextMessage, []byte("fail")); err == nil {
		t.Fatal("expected write deadline error")
	}
	_ = (&WebSocketResponse{Conn: conn}).Close()
	peer.SetReadDeadline(time.Now().Add(lifecycleTestTimeout))
	_, _, err = peer.ReadMessage()
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("socket remains open after close frame write failed")
	}
}

func TestWebSocketUpgradeCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { close(entered); <-release }))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	defer func() { cancel(); close(release); awaitClosed(t, done) }()
	go func() {
		defer close(done)
		conn, _, _ := NewWebSocketClient(nil, nil).ConnectContext(ctx, s.URL)
		if conn != nil {
			conn.Close()
		}
	}()
	awaitClosed(t, entered)
	cancel()
	awaitClosed(t, done)
}

func TestHTTP3CustomResponseCloseReleasesConnection(t *testing.T) {
	certServer := httptest.NewTLSServer(stdhttp.HandlerFunc(func(stdhttp.ResponseWriter, *stdhttp.Request) {}))
	tlsConfig := certServer.TLS.Clone()
	certServer.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConns := make(chan *quic.Conn, 1)
	s := &http3.Server{TLSConfig: tlsConfig, Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { io.WriteString(w, "ok") }), ConnContext: func(ctx context.Context, c *quic.Conn) context.Context { serverConns <- c; return ctx }}
	serverDone := make(chan struct{})
	go func() { defer close(serverDone); _ = s.Serve(udp) }()
	defer func() { s.Close(); udp.Close(); awaitClosed(t, serverDone) }()
	rt := NewHTTP3RoundTripper(&tls.Config{InsecureSkipVerify: true}, nil)
	rt.Dialer = func(ctx context.Context, addr string, tlsConf *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		return quic.DialAddrEarly(ctx, addr, tlsConf, cfg)
	}
	defer rt.Close()
	req, _ := fhttp.NewRequest("GET", "https://"+udp.LocalAddr().String(), nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var peer *quic.Conn
	select {
	case peer = <-serverConns:
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("missing QUIC connection")
	}
	awaitClosed(t, peer.Context().Done())
}

func TestSOCKS4HandshakeCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started := make(chan struct{})
	serverDone := make(chan struct{})
	peers := make(chan net.Conn, 1)
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		peers <- conn
		buf := make([]byte, 9)
		if _, err = io.ReadFull(conn, buf); err == nil {
			close(started)
			io.Copy(io.Discard, conn)
		}
	}()
	d, err := newConnectDialer("socks4://"+listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := d.DialContext(ctx, "tcp", "127.0.0.1:443")
		if conn != nil {
			conn.Close()
		}
	}()
	peer := <-peers
	defer func() { cancel(); peer.Close(); awaitClosed(t, done); awaitClosed(t, serverDone) }()
	awaitClosed(t, started)
	cancel()
	awaitClosed(t, done)
	awaitClosed(t, serverDone)
}

func TestSOCKS4TunnelSurvivesDialContextCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 9)
		if _, err = io.ReadFull(conn, buf); err != nil {
			return
		}
		conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
		io.Copy(conn, conn)
	}()
	d, err := newConnectDialer("socks4://"+listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { conn.Close(); awaitClosed(t, done) }()
	cancel()
	conn.SetDeadline(time.Now().Add(lifecycleTestTimeout))
	if _, err = conn.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err = io.ReadFull(conn, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("tunnel: %q %v", buf, err)
	}
}

func TestCanceledRequestDoesNotWaitForAnotherTLSHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	started := make(chan struct{})
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		if _, err := b.Read(make([]byte, 4096)); err == nil {
			close(started)
			io.Copy(io.Discard, b)
		}
	}()
	rt := newRoundTripper(Browser{}, pipeDialer{a}).(*roundTripper)
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); _, _ = rt.dialTLS(context.Background(), "tcp", "first.example:443") }()
	defer func() { a.Close(); b.Close(); awaitClosed(t, firstDone); awaitClosed(t, readDone) }()
	awaitClosed(t, started)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", "https://second.example/", nil)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = rt.GetCached(req, "second.example:443") }()
	defer func() { a.Close(); awaitClosed(t, done) }()
	cancel()
	awaitClosed(t, done)
}

func TestHTTP2ProxyConnectionIsReleased(t *testing.T) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.WriteHeader(200)
		w.(stdhttp.Flusher).Flush()
		io.Copy(io.Discard, r.Body)
	}))
	s.EnableHTTP2 = true
	closed := connectionClosedChannel(s)
	s.StartTLS()
	defer s.Close()
	dialer, err := newConnectDialer(s.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.(*connectDialer)
	conn, err := d.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer d.cachedH2ClientConn.Close()
	rt := newRoundTripper(Browser{}, d).(*roundTripper)
	rt.cachedConnections["example.com:443"] = conn
	rt.CloseIdleConnections()
	awaitClosed(t, closed)
}

func TestHTTPSHTTP1ConnectionReuse(t *testing.T) {
	for _, serverCloses := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep-alive", true: "server-close"}[serverCloses], func(t *testing.T) {
			var connections atomic.Int32
			s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				if serverCloses {
					w.Header().Set("Connection", "close")
				}
				io.WriteString(w, "ok")
			}))
			s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
				if state == stdhttp.StateNew {
					connections.Add(1)
				}
			}
			s.StartTLS()
			defer s.Close()
			c := Init()
			defer c.Close()
			opts := Options{ForceHTTP1: true, InsecureSkipVerify: true, EnableConnectionReuse: true, MaxIdleClients: 2, MaxTotalRequests: 10, MaxResponseBodySize: -1, Timeout: 2}
			for i := 0; i < 3; i++ {
				r, err := c.Do(s.URL, opts, "GET")
				if err != nil || r.Status != 200 || r.Body != "ok" {
					t.Fatalf("request %d: status=%d error=%v body=%s", i+1, r.Status, err, r.Body)
				}
			}
			want := int32(1)
			if serverCloses {
				want = 3
			}
			if got := connections.Load(); got != want {
				t.Fatalf("TCP connections=%d, want %d", got, want)
			}
		})
	}
}

func TestWebSocketRequestCancellation(t *testing.T) {
	peers := make(chan *websocket.Conn, 1)
	s := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			peers <- conn
		}
	}))
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := fhttp.NewRequestWithContext(ctx, "GET", s.URL, nil)
	res := fullRequest{req: req, wsClient: NewWebSocketClient(nil, nil), options: cycleTLSRequest{RequestID: "test-ws-cancel", Options: Options{URL: s.URL}}}
	output := make(chan []byte, 20)
	done := make(chan struct{})
	go func() { dispatchWebSocketAsync(res, output); close(done) }()
	var peer *websocket.Conn
	select {
	case peer = <-peers:
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("websocket did not connect")
	}
	defer func() { peer.Close(); awaitClosed(t, done) }()
	<-output
	<-output
	cancel()
	awaitClosed(t, done)
}
