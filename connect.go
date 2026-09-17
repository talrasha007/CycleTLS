package cycletls

// borrowed from from https://github.com/caddyserver/forwardproxy/blob/master/httpclient/httpclient.go
import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"

	http "github.com/Danny-Dasilva/fhttp"
	http2 "github.com/Danny-Dasilva/fhttp/http2"
	"golang.org/x/net/proxy"
)

type SocksDialer struct {
	proxyAddr string
}

func (d *SocksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, d.proxyAddr)
	if err != nil {
		return nil, err
	}
	owned := true
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stop()
		if owned {
			_ = conn.Close()
		}
	}()
	// SOCKS4 CONNECT with the anonymous user ID used by the existing API.
	request := []byte{4, 1, byte(portNumber >> 8), byte(portNumber), 0, 0, 0, 0, 0}
	copy(request[4:8], ips[0].To4())
	if _, err = conn.Write(request); err != nil {
		return nil, err
	}
	var response [8]byte
	if _, err = io.ReadFull(conn, response[:]); err != nil {
		return nil, err
	}
	if response[1] != 90 {
		return nil, fmt.Errorf("SOCKS4 CONNECT rejected: code %d", response[1])
	}
	if !stop() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	owned = false
	return conn, nil
}

func (d *SocksDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// connectDialer allows to configure one-time use HTTP CONNECT client
type connectDialer struct {
	ProxyURL      url.URL
	DefaultHeader http.Header

	Dialer proxy.ContextDialer // overridden dialer allow to control establishment of TCP connection

	// overridden DialTLS allows user to control establishment of TLS connection
	// MUST return connection with completed Handshake, and NegotiatedProtocol
	DialTLS func(network string, address string) (net.Conn, string, error)

	EnableH2ConnReuse  bool
	cacheH2Mu          sync.Mutex
	cachedH2ClientConn *http2.ClientConn
	cachedH2RawConn    net.Conn
	h2Connections      map[*http2.ClientConn]*proxyH2Connection
}

type proxyH2Connection struct {
	active  int
	closing bool
}

// CloseIdleConnections retires the proxy sessions. Active tunnels keep their
// session until their last Close, so another request's stream is not aborted.
func (c *connectDialer) CloseIdleConnections() {
	c.cacheH2Mu.Lock()
	defer c.cacheH2Mu.Unlock()
	c.cachedH2ClientConn = nil
	c.cachedH2RawConn = nil
	for conn, state := range c.h2Connections {
		state.closing = true
		if state.active == 0 {
			_ = conn.Close()
			delete(c.h2Connections, conn)
		}
	}
}

func (c *connectDialer) releaseH2(conn *http2.ClientConn, failed bool) {
	c.cacheH2Mu.Lock()
	defer c.cacheH2Mu.Unlock()
	state := c.h2Connections[conn]
	state.active--
	state.closing = state.closing || failed || !c.EnableH2ConnReuse
	if state.active == 0 && state.closing {
		_ = conn.Close()
		delete(c.h2Connections, conn)
		if c.cachedH2ClientConn == conn {
			c.cachedH2ClientConn, c.cachedH2RawConn = nil, nil
		}
	}
}

var (
	ProxyDialersMu sync.Mutex
	ProxyDialers   = make(map[string]*proxy.ContextDialer)
)

// maxProxyDialers bounds the ProxyDialers cache. Per-session proxy URLs
// (common with rotating residential proxies) would otherwise grow it forever.
const maxProxyDialers = 1024

// newConnectDialer creates a dialer to issue CONNECT requests and tunnel traffic via HTTP/S proxy.
// proxyUrlStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func newConnectDialer(proxyURLStr string, UserAgent string) (proxy.ContextDialer, error) {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, err
	}

	if proxyURL.Host == "" || proxyURL.Host == "undefined" {
		return nil, errors.New("invalid url `" + proxyURLStr +
			"`, make sure to specify full url like https://username:password@hostname.com:443/")
	}

	client := &connectDialer{
		ProxyURL:          *proxyURL,
		DefaultHeader:     make(http.Header),
		EnableH2ConnReuse: true,
	}

	switch proxyURL.Scheme {
	case "http":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
		}
	case "https":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "443")
		}
	case "socks5", "socks5h":
		var contextDialer proxy.ContextDialer
		ProxyDialersMu.Lock()
		defer ProxyDialersMu.Unlock()

		if cachedDialer, ok := ProxyDialers[proxyURLStr]; ok {
			contextDialer = *cachedDialer
		} else {
			var auth *proxy.Auth
			if proxyURL.User != nil {
				if proxyURL.User.Username() != "" {
					username := proxyURL.User.Username()
					password, _ := proxyURL.User.Password()
					auth = &proxy.Auth{User: username, Password: password}
				}
			}
			var forward proxy.Dialer
			if proxyURL.Scheme == "socks5h" {
				forward = proxy.Direct
			}
			dialSocksProxy, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, forward)
			if err != nil {
				return nil, fmt.Errorf("Error creating SOCKS5 proxy, reason %s", err)
			}
			if cd, ok := dialSocksProxy.(proxy.ContextDialer); ok {
				contextDialer = cd
				if len(ProxyDialers) >= maxProxyDialers {
					// Dialers hold no open resources, so dropping the cache is safe
					ProxyDialers = make(map[string]*proxy.ContextDialer)
				}
				ProxyDialers[proxyURLStr] = &contextDialer
			} else {
				return nil, errors.New("failed type assertion to DialContext")
			}
		}
		client.Dialer = contextDialer
		client.DefaultHeader.Set("User-Agent", UserAgent)
		return client, nil
	case "socks4":
		var dialer *SocksDialer
		dialer = &SocksDialer{proxyAddr: proxyURL.Host}
		client.Dialer = dialer
		client.DefaultHeader.Set("User-Agent", UserAgent)
		return client, nil
	case "":
		return nil, errors.New("specify scheme explicitly (https://)")
	default:
		return nil, errors.New("scheme " + proxyURL.Scheme + " is not supported")
	}

	client.Dialer = &net.Dialer{}

	if proxyURL.User != nil {
		if proxyURL.User.Username() != "" {
			// password, _ := proxyUrl.User.Password()
			// transport.DefaultHeader.Set("Proxy-Authorization", "Basic "+
			// 	base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.Username()+":"+password)))

			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()

			// transport.DefaultHeader.SetBasicAuth(username, password)
			auth := username + ":" + password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			client.DefaultHeader.Add("Proxy-Authorization", basicAuth)
		}
	}
	client.DefaultHeader.Set("User-Agent", UserAgent)
	return client, nil
}

func (c *connectDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// ContextKeyHeader Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

// ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.ProxyURL.Scheme == "socks5" || c.ProxyURL.Scheme == "socks4" || c.ProxyURL.Scheme == "socks5h" {
		return c.Dialer.DialContext(ctx, network, address)
	}

	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)
	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}
	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}
	connectHTTP2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
		// DialContext cancellation owns setup only. A successful CONNECT is a
		// long-lived stream, so its context must survive the dialing request.
		pr, pw := io.Pipe()
		tunnelCtx, cancelTunnel := context.WithCancel(context.WithoutCancel(ctx))
		cancelSetup := func() {
			cancelTunnel()
			// The dependency waits for the CONNECT body writer on cancellation;
			// unblock its pipe read while it finishes resetting this stream.
			pr.CloseWithError(ctx.Err())
			pw.CloseWithError(ctx.Err())
		}
		stop := context.AfterFunc(ctx, cancelSetup)
		connected := false
		defer func() {
			stop()
			if !connected {
				cancelTunnel()
				pr.Close()
				pw.Close()
			}
		}()
		connectReq := req.WithContext(tunnelCtx)
		// Reserve the session before beginning the CONNECT stream.
		c.cacheH2Mu.Lock()
		if c.h2Connections == nil {
			c.h2Connections = make(map[*http2.ClientConn]*proxyH2Connection)
		}
		if c.h2Connections[h2clientConn] == nil {
			c.h2Connections[h2clientConn] = &proxyH2Connection{}
		}
		c.h2Connections[h2clientConn].active++
		c.cacheH2Mu.Unlock()
		connectReq.Proto = "HTTP/2.0"
		connectReq.ProtoMajor = 2
		connectReq.ProtoMinor = 0
		connectReq.Body = pr

		resp, err := h2clientConn.RoundTrip(connectReq)
		if !stop() {
			cancelSetup()
		}
		if tunnelCtx.Err() != nil {
			if resp != nil {
				resp.Body.Close()
			}
			err = tunnelCtx.Err()
		}
		if err != nil {
			_ = pr.Close()
			_ = pw.Close()
			c.releaseH2(h2clientConn, true)
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			_ = pr.Close()
			_ = pw.Close()
			c.releaseH2(h2clientConn, true)
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status + "StatusCode:" + strconv.Itoa(resp.StatusCode))
		}
		conn := newHTTP2Conn(rawConn, pw, resp.Body).(*http2Conn)
		conn.release = func() {
			cancelTunnel()
			c.releaseH2(h2clientConn, false)
		}
		connected = true
		return conn, nil
	}

	connectHTTP1 := func(rawConn net.Conn) (net.Conn, error) {
		stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
		defer stop()
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		err := req.Write(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			_ = rawConn.Close()
			_ = resp.Body.Close()
			return nil, errors.New("Proxy responded with non 200 code: " + resp.Status + " StatusCode:" + strconv.Itoa(resp.StatusCode))
		}
		if !stop() || ctx.Err() != nil {
			_ = rawConn.Close()
			return nil, ctx.Err()
		}
		return rawConn, nil
	}

	if c.EnableH2ConnReuse {
		c.cacheH2Mu.Lock()
		unlocked := false
		if c.cachedH2ClientConn != nil && c.cachedH2RawConn != nil {
			if c.cachedH2ClientConn.CanTakeNewRequest() {
				rc := c.cachedH2RawConn
				cc := c.cachedH2ClientConn
				c.cacheH2Mu.Unlock()
				unlocked = true
				proxyConn, err := connectHTTP2(rc, cc)
				if err == nil {
					return proxyConn, err
				}
				// else: carry on and try again
			}
		}
		if !unlocked {
			c.cacheH2Mu.Unlock()
		}
	}

	var err error
	var rawConn net.Conn
	negotiatedProtocol := ""
	switch c.ProxyURL.Scheme {
	case "http":
		rawConn, err = c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
		if err != nil {
			return nil, err
		}
	case "https":
		if c.DialTLS != nil {
			rawConn, negotiatedProtocol, err = c.DialTLS(network, c.ProxyURL.Host)
			if err != nil {
				return nil, err
			}
		} else {
			tlsConf := tls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         c.ProxyURL.Hostname(),
				InsecureSkipVerify: true,
			}
			conn, err := c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, &tlsConf)
			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			negotiatedProtocol = tlsConn.ConnectionState().NegotiatedProtocol
			rawConn = tlsConn
		}
	default:
		return nil, errors.New("scheme " + c.ProxyURL.Scheme + " is not supported")
	}

	switch negotiatedProtocol {
	case "":
		fallthrough
	case "http/1.1":
		return connectHTTP1(rawConn)
	case "h2":
		stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
		//TODO: update this with correct navigator
		t := http2.Transport{Navigator: "chrome"}
		h2clientConn, err := t.NewClientConn(rawConn)
		stop()
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		proxyConn, err := connectHTTP2(rawConn, h2clientConn)
		if err != nil {
			_ = h2clientConn.Close()
			_ = rawConn.Close()
			return nil, err
		}
		if c.EnableH2ConnReuse {
			c.cacheH2Mu.Lock()
			if old := c.cachedH2ClientConn; old != nil && old != h2clientConn {
				state := c.h2Connections[old]
				if state != nil {
					state.closing = true
					if state.active == 0 {
						_ = old.Close()
						delete(c.h2Connections, old)
					}
				}
			}
			if state := c.h2Connections[h2clientConn]; state != nil && !state.closing {
				c.cachedH2ClientConn = h2clientConn
				c.cachedH2RawConn = rawConn
			}
			c.cacheH2Mu.Unlock()
		}
		return proxyConn, err
	default:
		_ = rawConn.Close()
		return nil, errors.New("negotiated unsupported application layer protocol: " +
			negotiatedProtocol)
	}
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) net.Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in        *io.PipeWriter
	out       io.ReadCloser
	release   func()
	closeOnce sync.Once
	closeErr  error
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	h.closeOnce.Do(func() {
		h.closeErr = errors.Join(h.in.Close(), h.out.Close())
		if h.release != nil {
			h.release()
		}
	})
	return h.closeErr
}

func (h *http2Conn) CloseConn() error {
	return h.Conn.Close()
}

func (h *http2Conn) CloseWrite() error {
	return h.in.Close()
}

func (h *http2Conn) CloseRead() error {
	return h.out.Close()
}
