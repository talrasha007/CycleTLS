package cycletls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
	http2 "github.com/Danny-Dasilva/fhttp/http2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")
var globalClientSessionCache = utls.NewLRUClientSessionCache(16384)

type closeTransportOnBodyClose struct {
	io.ReadCloser
	closeTransport func() error
	once           sync.Once
	closeErr       error
}

func (b *closeTransportOnBodyClose) Close() error {
	bodyErr := b.ReadCloser.Close()
	b.once.Do(func() {
		b.closeErr = b.closeTransport()
	})
	return errors.Join(bodyErr, b.closeErr)
}

type roundTripper struct {
	sync.Mutex

	TotalRequests int64

	// TLS fingerprinting options
	PaddingExtension         *utls.UtlsPaddingExtension
	EnableClientSessionCache bool
	SignatureAlgorithms      string
	JA3                      string
	JA4r                     string // JA4 raw format with explicit cipher/extension values
	HTTP2Fingerprint         string
	QUICFingerprint          string
	USpec                    *uquic.QUICSpec // UQuic QUIC specification for HTTP3 fingerprinting
	DisableGrease            bool

	// Browser identification
	UserAgent   string
	HeaderOrder []string

	// Connection options
	TLSConfig          *utls.Config
	InsecureSkipVerify bool
	Cookies            []Cookie

	ForceTLS12 bool
	ForceHTTP1 bool
	ForceHTTP3 bool
	RequestIP  string

	// TLS 1.3 specific options
	TLS13AutoRetry bool

	// Caching
	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper
	resolvedIPs       map[string]string
	resolvedIPsMu     sync.RWMutex

	dialer proxy.ContextDialer
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Apply cookies to the request
	for _, properties := range rt.Cookies {
		cookie := &http.Cookie{
			Name:       properties.Name,
			Value:      properties.Value,
			Path:       properties.Path,
			Domain:     properties.Domain,
			Expires:    properties.JSONExpires.Time,
			RawExpires: properties.RawExpires,
			MaxAge:     properties.MaxAge,
			HttpOnly:   properties.HTTPOnly,
			Secure:     properties.Secure,
			Raw:        properties.Raw,
			Unparsed:   properties.Unparsed,
		}
		req.AddCookie(cookie)
	}

	// Apply user agent
	req.Header.Set("User-Agent", rt.UserAgent)

	// Apply header order if specified (for regular headers, not pseudo-headers)
	if len(rt.HeaderOrder) > 0 {
		req.Header = ConvertHttpHeader(MarshalHeader(req.Header, rt.HeaderOrder))

		// Note: rt.HeaderOrder contains regular headers like "cache-control", "accept", etc.
		// Do NOT overwrite http.PHeaderOrderKey which contains pseudo-headers like ":method", ":path"
		// The pseudo-header order is already set correctly in index.go based on UserAgent parsing
	}

	// Get address for dialing
	addr := rt.getDialTLSAddr(req)

	// HTTP/3 transports own QUIC sockets and must remain alive until the caller
	// closes the response body. makeHTTP3Request binds that close to the body.
	if rt.ForceHTTP3 {
		return rt.makeHTTP3Request(req)
	}

	// Use cached transport if available, otherwise create a new one
	cached, err := rt.GetCached(req, addr)
	if err != nil {
		return nil, err
	}

	// Perform the request
	// rt.TotalRequests++
	return cached.RoundTrip(req)
}

func (rt *roundTripper) GetCached(req *http.Request, addr string) (http.RoundTripper, error) {
	rt.Lock()
	defer rt.Unlock()

	cacheAddr := rt.getDialAddr(addr)
	if cached, ok := rt.cachedTransports[cacheAddr]; ok {
		return cached, nil
	}

	if err := rt.getTransport(req, addr); err != nil {
		return nil, err
	}

	// Perform the request
	return rt.cachedTransports[cacheAddr], nil
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		// Allow connection reuse by removing DisableKeepAlives
		rt.cachedTransports[rt.getDialAddr(addr)] = &http.Transport{
			DialContext: rt.dialContext,
		}
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	// Establish TLS connection
	_, err := rt.dialTLSImpl(req.Context(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
		// Expected behavior - transport has been cached
	case nil:
		// Should never happen
		panic("dialTLS returned no error when determining cached transports")
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	defer rt.Unlock()

	return rt.dialTLSImpl(ctx, network, addr)
}

func (rt *roundTripper) dialTLSImpl(ctx context.Context, network, addr string) (net.Conn, error) {
	dialAddr := rt.getDialAddr(addr)

	// Return cached connection if available
	if conn := rt.cachedConnections[dialAddr]; conn != nil {
		return conn, nil
	}

	// Establish raw connection
	rawConn, err := rt.dialer.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}
	keepConn := false
	defer func() {
		if !keepConn {
			_ = rawConn.Close()
		}
	}()
	rt.recordResolvedIP(addr, rawConn)

	// Extract host from address
	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	var spec *utls.ClientHelloSpec
	var proactivelyUpgraded bool // Track if we proactively upgraded TLS 1.2 to 1.3

	// Determine which fingerprint to use
	if rt.QUICFingerprint != "" {
		// Use QUIC fingerprint
		spec, err = QUICStringToSpec(rt.QUICFingerprint, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		if err != nil {
			return nil, err
		}
	} else if rt.JA3 != "" {
		// Check if we should proactively upgrade TLS 1.2 to TLS 1.3
		if rt.TLS13AutoRetry && strings.HasPrefix(rt.JA3, "771,") {
			// Use TLS 1.3 compatible spec to avoid retry cycle
			spec, err = StringToTLS13CompatibleSpec(rt.JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
			proactivelyUpgraded = true
		} else {
			// Use original JA3 fingerprint
			spec, err = StringToSpec(rt.JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		}
		if err != nil {
			return nil, err
		}
	} else if rt.JA4r != "" {
		// Use JA4r (raw) fingerprint
		spec, err = JA4RStringToSpec(rt.JA4r, rt.UserAgent, rt.ForceHTTP1, rt.DisableGrease, host)
		if err != nil {
			return nil, err
		}
	} else {
		// Default to Chrome fingerprint
		spec, err = StringToSpec(DefaultChrome_JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		if err != nil {
			return nil, err
		}
	}

	var clientSessionCache utls.ClientSessionCache
	if rt.EnableClientSessionCache {
		clientSessionCache = globalClientSessionCache
	}

	// Create TLS client
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: rt.InsecureSkipVerify,
		ClientSessionCache: clientSessionCache,
	}, utls.HelloCustom)

	// Apply TLS fingerprint
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, err
	}

	// Perform TLS handshake
	if err = conn.Handshake(); err != nil {
		_ = conn.Close()

		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			// Check if TLS 1.3 retry is enabled
			if rt.TLS13AutoRetry {
				// Automatically retry with TLS 1.3 compatible curves
				return rt.retryWithTLS13CompatibleCurves(ctx, network, addr, host)
			}
			return nil, fmt.Errorf("conn.Handshake() error for TLS 1.3 (retry disabled): %+v", err)
		}

		// If we proactively upgraded to TLS 1.3 and it failed, try falling back to original TLS 1.2 JA3
		if proactivelyUpgraded && rt.JA3 != "" {
			return rt.retryWithOriginalTLS12JA3(ctx, network, addr, host)
		}

		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	// If transport already exists, return connection
	if rt.cachedTransports[dialAddr] != nil {
		keepConn = true
		return conn, nil
	}

	// Create appropriate transport based on negotiated protocol
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// HTTP/2 transport
		parsedUserAgent := parseUserAgent(rt.UserAgent)

		// Use HTTP/2 fingerprint if specified
		var http2Transport http2.Transport
		if rt.HTTP2Fingerprint != "" {
			// Parse and apply HTTP/2 fingerprint
			h2Fingerprint, err := NewHTTP2Fingerprint(rt.HTTP2Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HTTP/2 fingerprint: %v", err)
			}

			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			// Apply HTTP/2 fingerprint settings
			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[dialAddr] = &http2Transport
	default:
		// HTTP/1.x transport - configure to avoid idle channel errors
		rt.cachedTransports[dialAddr] = &http.Transport{
			DialTLSContext:    rt.dialTLS,
			DisableKeepAlives: true, // Disable keep-alives to prevent idle channel errors
		}
	}

	// Cache the connection for future use
	rt.cachedConnections[dialAddr] = conn
	keepConn = true

	return nil, errProtocolNegotiated
}

// retryWithTLS13CompatibleCurves retries the TLS connection with TLS 1.3 compatible curves
func (rt *roundTripper) retryWithTLS13CompatibleCurves(ctx context.Context, network, addr, host string) (net.Conn, error) {
	dialAddr := rt.getDialAddr(addr)

	// Establish raw connection for retry
	rawConn, err := rt.dialer.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}
	keepConn := false
	defer func() {
		if !keepConn {
			_ = rawConn.Close()
		}
	}()
	rt.recordResolvedIP(addr, rawConn)

	var spec *utls.ClientHelloSpec

	// Use TLS 1.3 compatible spec based on the original fingerprint type
	if rt.QUICFingerprint != "" {
		// For QUIC, we'll use the original spec but this could be enhanced
		spec, err = QUICStringToSpec(rt.QUICFingerprint, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC spec for TLS 1.3 retry: %v", err)
		}
	} else if rt.JA3 != "" {
		// Use TLS 1.3 compatible JA3 spec
		spec, err = StringToTLS13CompatibleSpec(rt.JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS 1.3 compatible JA3 spec: %v", err)
		}
	} else if rt.JA4r != "" {
		// For JA4r, we'll use a fallback to default Chrome with TLS 1.3 compatible curves
		spec, err = StringToTLS13CompatibleSpec(DefaultChrome_JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS 1.3 compatible JA4 fallback spec: %v", err)
		}
	} else {
		// Default to TLS 1.3 compatible Chrome fingerprint
		spec, err = StringToTLS13CompatibleSpec(DefaultChrome_JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS 1.3 compatible default spec: %v", err)
		}
	}

	// Create TLS client for retry
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: rt.InsecureSkipVerify,
	}, utls.HelloCustom)

	// Apply TLS 1.3 compatible fingerprint
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("failed to apply TLS 1.3 compatible preset: %v", err)
	}

	// Perform TLS handshake for retry
	if err = conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("TLS 1.3 compatible handshake failed: %+v", err)
	}

	// Create appropriate transport based on negotiated protocol
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// HTTP/2 transport
		parsedUserAgent := parseUserAgent(rt.UserAgent)

		var http2Transport http2.Transport
		if rt.HTTP2Fingerprint != "" {
			h2Fingerprint, err := NewHTTP2Fingerprint(rt.HTTP2Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HTTP/2 fingerprint for TLS 1.3 retry: %v", err)
			}

			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[dialAddr] = &http2Transport
	default:
		// HTTP/1.x transport
		rt.cachedTransports[dialAddr] = &http.Transport{
			DialTLSContext:    rt.dialTLS,
			DisableKeepAlives: true,
		}
	}

	// Cache the successful TLS 1.3 connection
	rt.cachedConnections[dialAddr] = conn
	keepConn = true

	return nil, errProtocolNegotiated
}

// retryWithOriginalTLS12JA3 retries the TLS connection with the original TLS 1.2 JA3
func (rt *roundTripper) retryWithOriginalTLS12JA3(ctx context.Context, network, addr, host string) (net.Conn, error) {
	dialAddr := rt.getDialAddr(addr)

	// Establish raw connection for fallback to original TLS 1.2 JA3
	rawConn, err := rt.dialer.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}
	keepConn := false
	defer func() {
		if !keepConn {
			_ = rawConn.Close()
		}
	}()
	rt.recordResolvedIP(addr, rawConn)

	// Use original TLS 1.2 JA3 spec (no upgrade)
	spec, err := StringToSpec(rt.JA3, rt.ForceTLS12, rt.UserAgent, rt.ForceHTTP1, rt.SignatureAlgorithms, rt.PaddingExtension)
	if err != nil {
		return nil, fmt.Errorf("failed to create original TLS 1.2 JA3 spec: %v", err)
	}

	// Create TLS client for fallback
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: rt.InsecureSkipVerify,
	}, utls.HelloCustom)

	// Apply original TLS 1.2 fingerprint
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("failed to apply original TLS 1.2 preset: %v", err)
	}

	// Perform TLS handshake for fallback
	if err = conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("original TLS 1.2 handshake failed: %+v", err)
	}

	// Create appropriate transport based on negotiated protocol
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// HTTP/2 transport
		parsedUserAgent := parseUserAgent(rt.UserAgent)

		var http2Transport http2.Transport
		if rt.HTTP2Fingerprint != "" {
			h2Fingerprint, err := NewHTTP2Fingerprint(rt.HTTP2Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HTTP/2 fingerprint for TLS 1.2 fallback: %v", err)
			}

			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[dialAddr] = &http2Transport
	default:
		// HTTP/1.x transport
		rt.cachedTransports[dialAddr] = &http.Transport{
			DialTLSContext:    rt.dialTLS,
			DisableKeepAlives: true,
		}
	}

	// Cache the successful TLS 1.2 fallback connection
	rt.cachedConnections[dialAddr] = conn
	keepConn = true

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *utls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

func (rt *roundTripper) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := rt.dialer.DialContext(ctx, network, rt.getDialAddr(addr))
	if err != nil {
		return nil, err
	}
	rt.recordResolvedIP(addr, conn)
	return conn, nil
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // Default HTTPS port
}

func (rt *roundTripper) getDialAddr(addr string) string {
	if rt.RequestIP == "" {
		return addr
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(rt.RequestIP, port)
}

func (rt *roundTripper) recordResolvedIP(addr string, conn net.Conn) {
	if conn == nil || !rt.canRecordResolvedIP() {
		return
	}

	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return
	}

	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return
	}

	rt.setResolvedIP(addr, ip.String())
}

func (rt *roundTripper) setResolvedIP(addr, ip string) {
	if addr == "" || ip == "" {
		return
	}

	rt.resolvedIPsMu.Lock()
	rt.resolvedIPs[addr] = ip
	rt.resolvedIPsMu.Unlock()
}

func (rt *roundTripper) ResolvedIP(addr string) string {
	rt.resolvedIPsMu.RLock()
	defer rt.resolvedIPsMu.RUnlock()
	return rt.resolvedIPs[addr]
}

func (rt *roundTripper) canRecordResolvedIP() bool {
	switch rt.dialer.(type) {
	case *connectDialer, *SocksDialer:
		return false
	default:
		return true
	}
}

// CloseIdleConnections closes connections that have been idle for too long
// If selectedAddr is provided, only close connections not matching this address
func (rt *roundTripper) CloseIdleConnections(selectedAddr ...string) {
	rt.Lock()
	defer rt.Unlock()

	// If we have a specific address to keep, only close other connections
	if len(selectedAddr) > 0 && selectedAddr[0] != "" {
		addr := selectedAddr[0]
		// Keep the connection for the provided address, close others
		for connAddr, conn := range rt.cachedConnections {
			if connAddr != addr {
				_ = conn.Close()
				delete(rt.cachedConnections, connAddr)
				delete(rt.cachedTransports, connAddr)
			}
		}
	} else {
		// No address specified, close all connections (original behavior)
		for addr, conn := range rt.cachedConnections {
			_ = conn.Close()
			delete(rt.cachedConnections, addr)
			delete(rt.cachedTransports, addr)
		}

		if dialer, ok := rt.dialer.(interface{ CloseIdleConnections() }); ok {
			dialer.CloseIdleConnections()
		}
	}
}

func newRoundTripper(browser Browser, dialer ...proxy.ContextDialer) http.RoundTripper {
	var contextDialer proxy.ContextDialer
	if len(dialer) > 0 {
		contextDialer = dialer[0]
	} else {
		contextDialer = proxy.Direct
	}

	return newRoundTripperWithIP(browser, contextDialer, "")
}

func newRoundTripperWithIP(browser Browser, contextDialer proxy.ContextDialer, requestIP string) http.RoundTripper {
	return &roundTripper{
		dialer:                   contextDialer,
		EnableClientSessionCache: browser.EnableClientSessionCache,
		SignatureAlgorithms:      browser.SignatureAlgorithms,
		PaddingExtension:         browser.PaddingExtension,
		JA3:                      browser.JA3,
		JA4r:                     browser.JA4r,
		HTTP2Fingerprint:         browser.HTTP2Fingerprint,
		QUICFingerprint:          browser.QUICFingerprint,
		USpec:                    browser.USpec, // Add USpec field initialization
		DisableGrease:            browser.DisableGrease,
		UserAgent:                browser.UserAgent,
		HeaderOrder:              browser.HeaderOrder,
		TLSConfig:                browser.TLSConfig,
		Cookies:                  browser.Cookies,
		cachedTransports:         make(map[string]http.RoundTripper),
		cachedConnections:        make(map[string]net.Conn),
		resolvedIPs:              make(map[string]string),
		InsecureSkipVerify:       browser.InsecureSkipVerify,
		ForceTLS12:               browser.ForceTLS12,
		ForceHTTP1:               browser.ForceHTTP1,
		ForceHTTP3:               browser.ForceHTTP3,
		RequestIP:                requestIP,

		// TLS 1.3 specific options
		TLS13AutoRetry: browser.TLS13AutoRetry,
	}
}

// makeHTTP3Request performs an HTTP/3 request and ties transport cleanup to the response body.
func (rt *roundTripper) makeHTTP3Request(req *http.Request) (*http.Response, error) {
	tlsConfig := ConvertUtlsConfig(rt.TLSConfig)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}

	// A transport is created per request, so it must be closed with the body.
	roundTripper := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout:           30 * time.Second,
			MaxIdleTimeout:                 90 * time.Second,
			KeepAlivePeriod:                15 * time.Second,
			InitialStreamReceiveWindow:     512 * 1024,      // 512 KB
			MaxStreamReceiveWindow:         2 * 1024 * 1024, // 2 MB
			InitialConnectionReceiveWindow: 1024 * 1024,     // 1 MB
			MaxConnectionReceiveWindow:     4 * 1024 * 1024, // 4 MB
			MaxIncomingStreams:             100,
			MaxIncomingUniStreams:          100,
			EnableDatagrams:                false,
			DisablePathMTUDiscovery:        false,
			Allow0RTT:                      false,
		},
	}

	// Convert fhttp.Request to net/http.Request
	stdReq := &stdhttp.Request{
		Method:           req.Method,
		URL:              req.URL,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           ConvertFhttpHeader(req.Header),
		Body:             req.Body,
		GetBody:          req.GetBody,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            req.Close,
		Host:             req.Host,
		Form:             req.Form,
		PostForm:         req.PostForm,
		MultipartForm:    req.MultipartForm,
		Trailer:          ConvertFhttpHeader(req.Trailer),
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       req.RequestURI,
		TLS:              nil,
		Cancel:           req.Cancel,
		Response:         nil,
	}

	// Use the RoundTripper to make the request
	stdResp, err := roundTripper.RoundTrip(stdReq)
	if err != nil {
		_ = roundTripper.Close()
		return nil, err
	}
	stdResp.Body = &closeTransportOnBodyClose{
		ReadCloser:     stdResp.Body,
		closeTransport: roundTripper.Close,
	}

	// Convert back to fhttp.Response
	return &http.Response{
		Status:           stdResp.Status,
		StatusCode:       stdResp.StatusCode,
		Proto:            stdResp.Proto,
		ProtoMajor:       stdResp.ProtoMajor,
		ProtoMinor:       stdResp.ProtoMinor,
		Header:           ConvertHttpHeader(stdResp.Header),
		Body:             stdResp.Body,
		ContentLength:    stdResp.ContentLength,
		TransferEncoding: stdResp.TransferEncoding,
		Close:            stdResp.Close,
		Uncompressed:     stdResp.Uncompressed,
		Trailer:          ConvertHttpHeader(stdResp.Trailer),
		Request:          req,
		TLS:              nil,
	}, nil
}

// Default JA3 fingerprint for Chrome
const DefaultChrome_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
