package cycletls

import (
	"context"
	"io"
	"net"
	"sync"

	http "github.com/Danny-Dasilva/fhttp"
	"github.com/Danny-Dasilva/fhttp/http2"
	"github.com/Danny-Dasilva/fhttp/httptrace"
	"golang.org/x/net/http/httpguts"
)

// The bundled HTTP/2 transport only exposes a context-free DialTLS callback.
// Supply its pool instead, so each dial and each waiter retain their own
// request context. The wrapper tracks reservations through response-body
// completion because the dependency does not expose an idle-connection API.
type contextHTTP2Transport struct {
	transport *http2.Transport
	dial      func(context.Context, string, string) (net.Conn, error)
	mu        sync.Mutex
	conns     map[*http2.ClientConn]*http2Connection
	dialing   chan struct{}
}

type http2Connection struct {
	addr      string
	users     int
	singleUse bool
	retired   bool
}

type http2LeaseKey struct{}
type http2Lease map[*http2.ClientConn]bool

func newContextHTTP2Transport(t *http2.Transport, dial func(context.Context, string, string) (net.Conn, error)) *contextHTTP2Transport {
	p := &contextHTTP2Transport{transport: t, dial: dial, conns: make(map[*http2.ClientConn]*http2Connection)}
	t.ConnPool = p
	return p
}

func (p *contextHTTP2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	lease := make(http2Lease)
	req = req.WithContext(context.WithValue(req.Context(), http2LeaseKey{}, lease))
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		p.release(lease)
		return nil, err
	}
	resp.Body = &http2ResponseBody{ReadCloser: resp.Body, release: func() { p.release(lease) }}
	return resp, nil
}

func (p *contextHTTP2Transport) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	ctx := req.Context()
	if trace := httptrace.ContextClientTrace(ctx); trace != nil && trace.GetConn != nil {
		trace.GetConn(addr)
	}
	lease := ctx.Value(http2LeaseKey{}).(http2Lease)
	singleUse := req.Close || httpguts.HeaderValuesContainsToken(req.Header["Connection"], "close")
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		for cc, state := range p.conns {
			if !singleUse && !state.singleUse && !state.retired && state.addr == addr && cc.CanTakeNewRequest() {
				if !lease[cc] {
					state.users++
					lease[cc] = true
				}
				p.mu.Unlock()
				return cc, nil
			}
		}
		if waiting := p.dialing; waiting != nil {
			p.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		p.dialing = make(chan struct{})
		p.mu.Unlock()

		cc, err := p.dialClientConn(ctx, addr)
		p.mu.Lock()
		if err == nil {
			p.conns[cc] = &http2Connection{addr: addr, users: 1, singleUse: singleUse, retired: !cc.CanTakeNewRequest()}
			lease[cc] = true
		}
		close(p.dialing)
		p.dialing = nil
		p.mu.Unlock()
		return cc, err
	}
}

func (p *contextHTTP2Transport) dialClientConn(ctx context.Context, addr string) (*http2.ClientConn, error) {
	conn, err := p.dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// NewClientConn writes the HTTP/2 preface synchronously. Cancellation owns
	// this socket only until setup finishes; it must never close a shared conn.
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.Close(); close(closed) })
	cc, err := p.transport.NewClientConn(conn)
	if !stop() {
		<-closed
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}

func (p *contextHTTP2Transport) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	state := p.conns[cc]
	if state != nil {
		// GOAWAY retires the connection before existing responses finish.
		// Keep ownership until their final body releases the connection.
		state.retired = true
	}
	closeNow := state == nil || state.users == 0
	if closeNow {
		delete(p.conns, cc)
	}
	p.mu.Unlock()
	// An unknown connection can be marked dead during NewClientConn setup,
	// before registration. It has no requests yet and must not be revived.
	if closeNow {
		cc.Close()
	}
}

func (p *contextHTTP2Transport) release(lease http2Lease) {
	var closing []*http2.ClientConn
	p.mu.Lock()
	for cc := range lease {
		if state := p.conns[cc]; state != nil {
			state.users--
			if state.users == 0 && (state.singleUse || state.retired) {
				delete(p.conns, cc)
				closing = append(closing, cc)
			}
		}
	}
	p.mu.Unlock()
	for _, cc := range closing {
		cc.Close()
	}
}

func (p *contextHTTP2Transport) CloseIdleConnections() {
	var closing []*http2.ClientConn
	p.mu.Lock()
	for cc, state := range p.conns {
		if state.users == 0 {
			delete(p.conns, cc)
			closing = append(closing, cc)
		}
	}
	p.mu.Unlock()
	for _, cc := range closing {
		cc.Close()
	}
}

type http2ResponseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *http2ResponseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}

func (b *http2ResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}
