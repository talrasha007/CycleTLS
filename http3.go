package cycletls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"sync"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	uquic "github.com/refraction-networking/uquic"
	"golang.org/x/net/idna"
	"golang.org/x/net/proxy"
)

// sharedHTTP3 owns one transport. Configuration is snapshotted at first use;
// callers must finish configuration before issuing concurrent requests.
// active includes requests awaiting headers and response bodies not yet done.
// quic-go counts only requests awaiting headers for its idle cleanup, so this
// additional count prevents cleanup from closing a connection with live bodies.
type sharedHTTP3 struct {
	mu                sync.Mutex
	transport         *http3.Transport
	timeout           time.Duration
	active            int
	activeByAuthority map[string]int
	closed            bool
	closeDone         chan struct{}
	closeErr          error
	idlePending       bool
	idleDone          chan struct{}
	dials             map[*context.CancelFunc]string
}

func (s *sharedHTTP3) acquire(ctx context.Context, authority string, build func() (*http3.Transport, time.Duration)) (*http3.Transport, time.Duration, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, 0, net.ErrClosed
		}
		if done := s.idleDone; done != nil {
			s.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			}
		}
		if s.transport == nil {
			s.transport, s.timeout = build()
			t := s.transport
			if t.TLSClientConfig != nil {
				t.TLSClientConfig = t.TLSClientConfig.Clone()
			}
			if t.QUICConfig != nil {
				t.QUICConfig = t.QUICConfig.Clone()
			}
			dial := t.Dial
			if dial == nil {
				dial = quic.DialAddrEarly
			}
			// The first request does not own a multiplexed connection's handshake.
			// Cancel the dial when all interested requests leave, or on Close.
			t.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				dialCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
				s.mu.Lock()
				if s.closed || s.activeByAuthority[addr] == 0 {
					cancel()
				} else {
					if s.dials == nil {
						s.dials = make(map[*context.CancelFunc]string)
					}
					s.dials[&cancel] = addr
				}
				s.mu.Unlock()
				defer func() { cancel(); s.mu.Lock(); delete(s.dials, &cancel); s.mu.Unlock() }()
				return dial(dialCtx, addr, tlsCfg, cfg)
			}
		}
		s.active++
		if s.activeByAuthority == nil {
			s.activeByAuthority = make(map[string]int)
		}
		s.activeByAuthority[authority]++
		t, timeout := s.transport, s.timeout
		s.mu.Unlock()
		return t, timeout, nil
	}
}

func (s *sharedHTTP3) release(authority string) {
	s.mu.Lock()
	s.active--
	s.activeByAuthority[authority]--
	if s.activeByAuthority[authority] == 0 {
		delete(s.activeByAuthority, authority)
		for cancel, dialAuthority := range s.dials {
			if dialAuthority == authority {
				(*cancel)()
			}
		}
	}
	idle := s.active == 0 && s.idlePending
	s.mu.Unlock()
	if idle {
		s.CloseIdleConnections()
	}
}

func (s *sharedHTTP3) CloseIdleConnections() {
	s.mu.Lock()
	if s.closed || s.transport == nil {
		s.mu.Unlock()
		return
	}
	s.idlePending = true
	if s.active != 0 || s.idleDone != nil {
		s.mu.Unlock()
		return
	}
	s.idlePending = false
	done := make(chan struct{})
	s.idleDone = done
	t := s.transport
	s.mu.Unlock()
	t.CloseIdleConnections()
	s.mu.Lock()
	s.idleDone = nil
	close(done)
	s.mu.Unlock()
}

func (s *sharedHTTP3) Close() error {
	s.mu.Lock()
	if s.closed {
		done := s.closeDone
		s.mu.Unlock()
		<-done
		return s.closeErr
	}
	s.closed = true
	s.closeDone = make(chan struct{})
	t := s.transport
	for cancel := range s.dials {
		(*cancel)()
	}
	s.mu.Unlock()
	var err error
	if t != nil {
		err = t.Close()
	}
	s.mu.Lock()
	s.closeErr = err
	close(s.closeDone)
	s.mu.Unlock()
	return err
}

type http3StreamBody struct {
	io.ReadCloser
	release     func()
	releaseOnce sync.Once
	closeOnce   sync.Once
	closeErr    error
}

func (b *http3StreamBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.releaseOnce.Do(b.release)
	}
	return n, err
}
func (b *http3StreamBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.ReadCloser.Close(); b.releaseOnce.Do(b.release) })
	return b.closeErr
}

func (s *sharedHTTP3) roundTrip(req *http.Request, build func() (*http3.Transport, time.Duration)) (*http.Response, error) {
	// Match quic-go's authority key, including default ports and IDNA names,
	// so requests for one origin cannot retain another origin's abandoned dial.
	authority := ""
	if req.URL != nil {
		host, port := req.URL.Hostname(), req.URL.Port()
		if ascii, err := idna.ToASCII(host); err == nil {
			host = ascii
		}
		if port == "" {
			port = "443"
		}
		authority = net.JoinHostPort(host, port)
	}
	t, timeout, err := s.acquire(req.Context(), authority, build)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	ctx := req.Context()
	cancel := func() {}
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	finish := func() { cancel(); s.release(authority) }
	stdReq := (&stdhttp.Request{
		Method: req.Method, URL: req.URL, Proto: req.Proto, ProtoMajor: req.ProtoMajor, ProtoMinor: req.ProtoMinor,
		Header: ConvertFhttpHeader(req.Header), Body: req.Body, GetBody: req.GetBody, ContentLength: req.ContentLength,
		TransferEncoding: req.TransferEncoding, Close: req.Close, Host: req.Host, Form: req.Form, PostForm: req.PostForm,
		MultipartForm: req.MultipartForm, Trailer: ConvertFhttpHeader(req.Trailer), RemoteAddr: req.RemoteAddr,
		RequestURI: req.RequestURI, Cancel: req.Cancel,
	}).WithContext(ctx)
	// fhttp's header-order metadata is not an HTTP header.
	delete(stdReq.Header, http.HeaderOrderKey)
	delete(stdReq.Header, http.PHeaderOrderKey)
	resp, err := t.RoundTrip(stdReq)
	// quic-go reports a previous, canceled handshake once while evicting its
	// failed connection entry. A live request may retry that pre-stream failure;
	// request bodies must be replayable because RoundTrip closed the first body.
	if errors.Is(err, context.Canceled) && ctx.Err() == nil {
		retry := stdReq.Body == nil || stdReq.Body == http.NoBody || stdReq.Body == stdhttp.NoBody
		if !retry && stdReq.GetBody != nil {
			stdReq.Body, err = stdReq.GetBody()
			retry = err == nil
		}
		if retry {
			resp, err = t.RoundTrip(stdReq)
		}
	}
	if err != nil {
		finish()
		return nil, err
	}
	return &http.Response{
		Status: resp.Status, StatusCode: resp.StatusCode, Proto: resp.Proto, ProtoMajor: resp.ProtoMajor, ProtoMinor: resp.ProtoMinor,
		Header: ConvertHttpHeader(resp.Header), Body: &http3StreamBody{ReadCloser: resp.Body, release: finish},
		ContentLength: resp.ContentLength, TransferEncoding: resp.TransferEncoding, Close: resp.Close,
		Uncompressed: resp.Uncompressed, Trailer: ConvertHttpHeader(resp.Trailer), Request: req,
	}, nil
}

// HTTP3Transport represents an HTTP/3 transport with customizable settings.
// Set fields before first use. Close releases its shared connections.
type HTTP3Transport struct {
	QuicConfig            *quic.Config
	TLSClientConfig       *tls.Config
	UQuicConfig           *uquic.Config
	QUICSpec              *uquic.QUICSpec
	UseUQuic              bool
	MaxIdleConns          int
	IdleConnTimeout       time.Duration
	ResponseHeaderTimeout time.Duration
	DialTimeout           time.Duration
	ForceAttemptHTTP2     bool
	DisableCompression    bool
	shared                sharedHTTP3
}

func defaultHTTP3Config() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 30 * time.Second, MaxIdleTimeout: 90 * time.Second, KeepAlivePeriod: 15 * time.Second}
}
func NewHTTP3Transport(tlsConfig *tls.Config) *HTTP3Transport {
	return &HTTP3Transport{TLSClientConfig: tlsConfig, QuicConfig: defaultHTTP3Config(), MaxIdleConns: 100, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DialTimeout: 30 * time.Second}
}
func NewHTTP3TransportWithUQuic(tlsConfig *tls.Config, quicSpec *uquic.QUICSpec) *HTTP3Transport {
	t := NewHTTP3Transport(tlsConfig)
	if quicSpec != nil {
		t.QUICSpec = quicSpec
		t.UseUQuic = true
		t.UQuicConfig = &uquic.Config{}
	}
	return t
}
func (t *HTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.shared.roundTrip(req, func() (*http3.Transport, time.Duration) {
		// UQuic requests retain the existing standard HTTP/3 fallback. Native QUIC
		// fingerprint application is not implemented by this adapter.
		return &http3.Transport{TLSClientConfig: t.TLSClientConfig, QUICConfig: t.QuicConfig, DisableCompression: t.DisableCompression}, t.DialTimeout
	})
}
func (t *HTTP3Transport) Close() error          { return t.shared.Close() }
func (t *HTTP3Transport) CloseIdleConnections() { t.shared.CloseIdleConnections() }

// UQuicHTTP3Transport currently uses the standard HTTP/3 implementation as a
// fallback. QUICSpec is retained for compatibility; it is not applied on wire.
type UQuicHTTP3Transport struct {
	TLSClientConfig *tls.Config
	UQuicConfig     *uquic.Config
	QUICSpec        *uquic.QUICSpec
	DialTimeout     time.Duration
	shared          sharedHTTP3
}

func NewUQuicHTTP3Transport(tlsConfig *tls.Config, quicSpec *uquic.QUICSpec) *UQuicHTTP3Transport {
	return &UQuicHTTP3Transport{TLSClientConfig: tlsConfig, UQuicConfig: &uquic.Config{}, QUICSpec: quicSpec, DialTimeout: 30 * time.Second}
}
func (t *UQuicHTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.shared.roundTrip(req, func() (*http3.Transport, time.Duration) {
		return &http3.Transport{TLSClientConfig: t.TLSClientConfig, QUICConfig: defaultHTTP3Config()}, t.DialTimeout
	})
}
func (t *UQuicHTTP3Transport) Close() error          { return t.shared.Close() }
func (t *UQuicHTTP3Transport) CloseIdleConnections() { t.shared.CloseIdleConnections() }

func ConfigureHTTP3Client(client *stdhttp.Client, tlsConfig *tls.Config) {
	client.Transport = &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: defaultHTTP3Config()}
}

// HTTP3RoundTripper shares one transport, including when Dialer is supplied.
// Configuration and Forwarder must not be changed after first use.
type HTTP3RoundTripper struct {
	TLSClientConfig *tls.Config
	QuicConfig      *quic.Config
	Forwarder       *http3.Transport
	Dialer          func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error)
	shared          sharedHTTP3
}

func NewHTTP3RoundTripper(tlsConfig *tls.Config, quicConfig *quic.Config) *HTTP3RoundTripper {
	return &HTTP3RoundTripper{TLSClientConfig: tlsConfig, QuicConfig: quicConfig, Forwarder: &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: quicConfig}}
}
func (rt *HTTP3RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.shared.roundTrip(req, func() (*http3.Transport, time.Duration) {
		t := rt.Forwarder
		if t == nil {
			t = &http3.Transport{}
		}
		if rt.TLSClientConfig != nil {
			t.TLSClientConfig = rt.TLSClientConfig
		}
		if rt.QuicConfig != nil {
			t.QUICConfig = rt.QuicConfig
		}
		if rt.Dialer != nil {
			t.Dial = rt.Dialer
		}
		rt.Forwarder = t
		return t, 0
	})
}
func (rt *HTTP3RoundTripper) Close() error          { return rt.shared.Close() }
func (rt *HTTP3RoundTripper) CloseIdleConnections() { rt.shared.CloseIdleConnections() }

func (rt *roundTripper) roundTripHTTP3(req *http.Request) (*http.Response, error) {
	bodyTransferred := false
	defer func() {
		if !bodyTransferred && req.Body != nil {
			_ = req.Body.Close()
		}
	}()
	if err := rt.LockContext(req.Context()); err != nil {
		return nil, err
	}
	if rt.closed {
		rt.Unlock()
		return nil, net.ErrClosed
	}
	// HTTP CONNECT and SOCKS dialers cannot carry QUIC's UDP traffic. Never
	// silently bypass a configured proxy with a direct QUIC connection.
	if rt.dialer != nil && rt.dialer != proxy.Direct {
		rt.Unlock()
		return nil, fmt.Errorf("HTTP/3 proxy or custom TCP dialer is not supported")
	}
	if rt.http3Transport == nil {
		tlsCfg := ConvertUtlsConfig(rt.TLSConfig)
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		} else {
			tlsCfg = tlsCfg.Clone()
		}
		tlsCfg.InsecureSkipVerify = rt.InsecureSkipVerify
		tlsCfg.NextProtos = []string{http3.NextProtoH3}
		h3 := NewHTTP3RoundTripper(tlsCfg, defaultHTTP3Config())
		requestIP := rt.RequestIP
		h3.Dialer = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			target := addr
			if requestIP != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				target = net.JoinHostPort(requestIP, port)
			}
			conn, err := quic.DialAddrEarly(ctx, target, tlsCfg, cfg)
			if err == nil {
				host, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
				if splitErr == nil {
					rt.setResolvedIP(addr, host)
				}
			}
			return conn, err
		}
		rt.http3Transport = h3
	}
	h3 := rt.http3Transport
	rt.Unlock()
	bodyTransferred = true
	return h3.RoundTrip(req)
}

// HTTP3Connection represents an HTTP/3 connection with associated metadata
type HTTP3Connection struct {
	QuicConn interface{} // Can be *quic.Conn or uquic.EarlyConnection
	RawConn  net.PacketConn
	Proxys   []string
	IsUQuic  bool // Flag to indicate if this is a UQuic connection
}

func (c *HTTP3Connection) Close() error {
	var err error
	switch conn := c.QuicConn.(type) {
	case *quic.Conn:
		err = conn.CloseWithError(0, "request completed")
	case uquic.EarlyConnection:
		err = conn.CloseWithError(0, "request completed")
	}
	if c.RawConn != nil {
		if closeErr := c.RawConn.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}
