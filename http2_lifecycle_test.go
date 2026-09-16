package cycletls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
	"github.com/Danny-Dasilva/fhttp/http2"
	"github.com/Danny-Dasilva/fhttp/http2/hpack"
)

func TestHTTP2GoAwayClosesConnectionAfterActiveResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finish := make(chan struct{})
	peerClosed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerClosed <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
			peerClosed <- err
			return
		}
		framer := http2.NewFramer(conn, conn)
		if err = framer.WriteSettings(); err != nil {
			peerClosed <- err
			return
		}
		var stream uint32
		for stream == 0 {
			frame, err := framer.ReadFrame()
			if err != nil {
				peerClosed <- err
				return
			}
			if headers, ok := frame.(*http2.HeadersFrame); ok {
				stream = headers.StreamID
			}
		}
		var headers bytes.Buffer
		encoder := hpack.NewEncoder(&headers)
		encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		if err = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, EndHeaders: true, BlockFragment: headers.Bytes()}); err != nil {
			peerClosed <- err
			return
		}
		if err = framer.WriteGoAway(stream, http2.ErrCodeNo, nil); err != nil {
			peerClosed <- err
			return
		}
		<-finish
		if err = framer.WriteData(stream, true, []byte("ok")); err != nil {
			peerClosed <- err
			return
		}
		_, err = io.Copy(io.Discard, conn)
		peerClosed <- err
	}()
	p := newContextHTTP2Transport(&http2.Transport{}, (&net.Dialer{}).DialContext)
	defer p.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://"+listener.Addr().String(), nil)
	resp, err := p.RoundTrip(req)
	if err != nil {
		close(finish)
		t.Fatal(err)
	}
	close(finish)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("active response interrupted by GOAWAY: %q, %v", body, err)
	}
	p.CloseIdleConnections()
	select {
	case err := <-peerClosed:
		if err != nil {
			t.Fatalf("retired connection stayed open: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GOAWAY connection leaked after final response completed")
	}
}

type h2ReconnectDialer struct {
	calls   atomic.Int32
	stalled net.Conn
}

func TestHTTP2DialCancellationDoesNotCancelOtherRequests(t *testing.T) {
	for _, cancelOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiter", true: "owner"}[cancelOwner], func(t *testing.T) {
			s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				io.WriteString(w, "ok")
			}))
			s.EnableHTTP2 = true
			s.StartTLS()
			defer s.Close()
			started, proceed := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			p := newContextHTTP2Transport(&http2.Transport{}, func(ctx context.Context, network, addr string) (net.Conn, error) {
				if calls.Add(1) == 1 {
					close(started)
					select {
					case <-proceed:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return (&tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}}).DialContext(ctx, network, addr)
			})
			defer p.CloseIdleConnections()
			ownerCtx, cancelOwnerRequest := context.WithCancel(context.Background())
			defer cancelOwnerRequest()
			waiterCtx, cancelWaiter := context.WithCancel(context.Background())
			defer cancelWaiter()
			run := func(ctx context.Context) <-chan error {
				done := make(chan error, 1)
				go func() {
					req, _ := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
					resp, err := p.RoundTrip(req)
					if err == nil {
						_, err = io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}
					done <- err
				}()
				return done
			}
			owner := run(ownerCtx)
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("dial did not start")
			}
			waiter := run(waiterCtx)
			canceled, live := waiter, owner
			if cancelOwner {
				cancelOwnerRequest()
				canceled, live = owner, waiter
			} else {
				cancelWaiter()
			}
			select {
			case err := <-canceled:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation, got %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("canceled request blocked behind another dial")
			}
			close(proceed)
			select {
			case err := <-live:
				if err != nil {
					t.Fatalf("another request's cancellation affected live request: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("live request failed to finish")
			}
		})
	}
}

func TestHTTP2CleanupPreservesActiveStreamAndReuse(t *testing.T) {
	finish := make(chan struct{})
	defer close(finish)
	closed := make(chan struct{}, 8)
	var connections atomic.Int32
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
		if r.URL.Path == "/active" {
			w.(stdhttp.Flusher).Flush()
			select {
			case <-finish:
			case <-r.Context().Done():
			}
		}
	}))
	s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
		if state == stdhttp.StateNew {
			connections.Add(1)
		}
		if state == stdhttp.StateClosed {
			closed <- struct{}{}
		}
	}
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	rt := newRoundTripper(Browser{InsecureSkipVerify: true}).(*roundTripper)
	defer rt.CloseIdleConnections()
	client := &http.Client{Transport: rt}
	active, err := client.Get(s.URL + "/active")
	if err != nil {
		t.Fatal(err)
	}
	defer active.Body.Close()
	rt.CloseIdleConnections()
	resp, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if connections.Load() != 1 {
		t.Fatalf("expected shared HTTP/2 connection, got %d", connections.Load())
	}
	active.Body.Close()
	rt.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle HTTP/2 connection did not close")
	}
	resp, err = client.Get(s.URL)
	if err != nil {
		t.Fatalf("request after cleanup failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if connections.Load() != 2 {
		t.Fatalf("expected new connection after cleanup, got %d", connections.Load())
	}
}

func (d *h2ReconnectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.calls.Add(1) == 1 {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return d.stalled, nil
}

func TestHTTP2ReconnectHandshakeCancellation(t *testing.T) {
	s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		io.WriteString(w, "ok")
	}))
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()
	a, b := net.Pipe()
	defer b.Close()
	defer a.Close()
	dialer := &h2ReconnectDialer{stalled: a}
	rt := newRoundTripper(Browser{InsecureSkipVerify: true}, dialer).(*roundTripper)
	client := &http.Client{Transport: rt}
	resp, err := client.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}
	s.CloseClientConnections()
	// Retire the idle entry synchronously: the dependency does not retry an
	// unexpected EOF if a new stream races the server-close notification.
	rt.CloseIdleConnections()

	started := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		if _, err := b.Read(make([]byte, 4096)); err == nil {
			close(started)
			io.Copy(io.Discard, b)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
	done := make(chan error, 1)
	go func() { _, err := client.Do(req); done <- err }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("request ended before reconnection handshake: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("reconnection handshake did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP/2 reconnect ignored request cancellation")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled handshake did not close its connection")
	}
	rt.CloseIdleConnections()
}
