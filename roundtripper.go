package cycletls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
	http2 "github.com/Danny-Dasilva/fhttp/http2"
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/idna"
	"golang.org/x/net/proxy"
)

var errProtocolNegotiated = errors.New("protocol negotiated")
var globalClientSessionCache = utls.NewLRUClientSessionCache(16384)

type roundTripper struct {
	contextMutex

	poolEntry      *ClientPoolEntry // immutable after publication in the client registry
	closed         bool
	http3Transport *HTTP3RoundTripper

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

type requestSettingsKey struct{}

type requestSettings struct {
	userAgent   string
	cookies     []Cookie
	headerOrder []string
}

// Keep per-request defaults out of the shared transport. The value also follows
// redirects and SSE requests without mutating a shared client or its settings.
func withRequestSettings(ctx context.Context, browser Browser) context.Context {
	settings := requestSettings{
		userAgent:   browser.UserAgent,
		cookies:     append([]Cookie(nil), browser.Cookies...),
		headerOrder: append([]string(nil), browser.HeaderOrder...),
	}
	for i := range settings.cookies {
		settings.cookies[i].Unparsed = append([]string(nil), settings.cookies[i].Unparsed...)
	}
	return context.WithValue(ctx, requestSettingsKey{}, settings)
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	settings, ok := req.Context().Value(requestSettingsKey{}).(requestSettings)
	if !ok {
		// Standalone NewTransport clients retain their configured defaults.
		settings = requestSettings{userAgent: rt.UserAgent, cookies: rt.Cookies, headerOrder: rt.HeaderOrder}
	}
	// Apply cookies to the request
	for _, properties := range settings.cookies {
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
	req.Header.Set("User-Agent", settings.userAgent)

	// Apply header order if specified (for regular headers, not pseudo-headers)
	if len(settings.headerOrder) > 0 {
		order := make([]string, len(settings.headerOrder))
		for i, name := range settings.headerOrder {
			order[i] = strings.ToLower(name)
		}
		// Go maps have no insertion order; fhttp consumes this metadata on wire.
		req.Header[http.HeaderOrderKey] = order

		// HeaderOrder contains regular headers like "cache-control", "accept", etc.
		// Do NOT overwrite http.PHeaderOrderKey which contains pseudo-headers like ":method", ":path"
		// The pseudo-header order is already set correctly in index.go based on UserAgent parsing
	}

	// Get address for dialing
	addr := rt.getDialTLSAddr(req)

	if rt.ForceHTTP3 {
		return rt.roundTripHTTP3(req)
	}

	// Use cached transport if available, otherwise create a new one
	cached, err := rt.GetCached(req, addr)
	if err != nil {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}

	// Perform the request
	// rt.TotalRequests++
	return cached.RoundTrip(req)
}

func (rt *roundTripper) GetCached(req *http.Request, addr string) (http.RoundTripper, error) {
	if err := rt.LockContext(req.Context()); err != nil {
		return nil, err
	}
	defer rt.Unlock()
	if rt.closed {
		return nil, net.ErrClosed
	}

	// TLS identity is the logical origin, even when several origins share an
	// explicit RequestIP. A negotiated socket must not migrate between SNIs.
	cacheAddr := addr
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
		rt.cachedTransports[addr] = &http.Transport{
			DialContext:     rt.dialContext,
			IdleConnTimeout: 90 * time.Second,
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
	if err := rt.LockContext(ctx); err != nil {
		return nil, err
	}
	defer rt.Unlock()
	if rt.closed {
		return nil, net.ErrClosed
	}

	return rt.dialTLSImpl(ctx, network, addr)
}

func (rt *roundTripper) dialTLSImpl(ctx context.Context, network, addr string) (net.Conn, error) {
	dialAddr := rt.getDialAddr(addr)

	// Return cached connection if available
	if conn := rt.cachedConnections[addr]; conn != nil {
		delete(rt.cachedConnections, addr)
		return conn, nil
	}

	// Establish raw connection
	rawConn, err := rt.dialer.DialContext(ctx, network, dialAddr)
	if err != nil {
		return nil, err
	}
	rt.recordResolvedIP(addr, rawConn)
	owned := true
	defer func() {
		if owned {
			_ = rawConn.Close()
		}
	}()

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
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

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
	if rt.cachedTransports[addr] != nil {
		owned = false
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
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			// Apply HTTP/2 fingerprint settings
			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[addr] = newContextHTTP2Transport(&http2Transport, rt.dialTLS)
	default:
		// The transport owns the connection after the first dial callback.
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext:  rt.dialTLS,
			IdleConnTimeout: 90 * time.Second,
		}
	}

	// Cache the connection for future use
	rt.cachedConnections[addr] = conn
	owned = false

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
	rt.recordResolvedIP(addr, rawConn)
	owned := true
	defer func() {
		if owned {
			_ = rawConn.Close()
		}
	}()

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
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("TLS 1.3 compatible handshake failed: %+v", err)
	}
	if rt.cachedTransports[addr] != nil {
		owned = false
		return conn, nil
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
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[addr] = newContextHTTP2Transport(&http2Transport, rt.dialTLS)
	default:
		// HTTP/1.x transport
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext:  rt.dialTLS,
			IdleConnTimeout: 90 * time.Second,
		}
	}

	// Cache the successful TLS 1.3 connection
	rt.cachedConnections[addr] = conn
	owned = false

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
	rt.recordResolvedIP(addr, rawConn)
	owned := true
	defer func() {
		if owned {
			_ = rawConn.Close()
		}
	}()

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
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("original TLS 1.2 handshake failed: %+v", err)
	}
	if rt.cachedTransports[addr] != nil {
		owned = false
		return conn, nil
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
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[addr] = newContextHTTP2Transport(&http2Transport, rt.dialTLS)
	default:
		// HTTP/1.x transport
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext:  rt.dialTLS,
			IdleConnTimeout: 90 * time.Second,
		}
	}

	// Cache the successful TLS 1.2 fallback connection
	rt.cachedConnections[addr] = conn
	owned = false

	return nil, errProtocolNegotiated
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
	port := req.URL.Port()
	if port == "" {
		port = "443"
		if strings.EqualFold(req.URL.Scheme, "http") {
			port = "80"
		}
	}
	host := req.URL.Hostname()
	if ascii, err := idna.ToASCII(host); err == nil {
		host = ascii
	}
	return net.JoinHostPort(host, port)
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

// CloseIdleConnections implements the optional http.RoundTripper cleanup hook.
func (rt *roundTripper) CloseIdleConnections() {
	rt.closeIdleConnectionsExcept("")
}

// Close disposes a retired transport generation. The shared client registry
// waits until every acquired request has released its response before calling.
func (rt *roundTripper) Close() error {
	rt.Lock()
	if rt.closed {
		rt.Unlock()
		return nil
	}
	rt.closed = true
	conns, transports, h3 := rt.cachedConnections, rt.cachedTransports, rt.http3Transport
	rt.cachedConnections = make(map[string]net.Conn)
	rt.cachedTransports = make(map[string]http.RoundTripper)
	rt.Unlock()
	var closeErr error
	for _, conn := range conns {
		closeErr = errors.Join(closeErr, conn.Close())
	}
	for _, tr := range transports {
		if closer, ok := tr.(interface{ Close() error }); ok {
			closeErr = errors.Join(closeErr, closer.Close())
		} else if closer, ok := tr.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
	if h3 != nil {
		closeErr = errors.Join(closeErr, h3.Close())
	}
	if d, ok := rt.dialer.(interface{ CloseIdleConnections() }); ok {
		d.CloseIdleConnections()
	}
	return closeErr
}

func (rt *roundTripper) closeIdleConnectionsExcept(selectedAddr string) {
	rt.Lock()
	defer rt.Unlock()
	keep := ""
	if selectedAddr != "" {
		keep = selectedAddr
	}
	for addr, conn := range rt.cachedConnections {
		if addr != keep {
			_ = conn.Close()
			delete(rt.cachedConnections, addr)
		}
	}
	for addr := range rt.cachedTransports {
		if addr != keep {
			rt.closeCachedTransport(addr)
		}
	}
	// Retain transports so connections still in use remain owned and can be
	// cleaned up on a subsequent call after their responses are closed.
	if keep == "" {
		if rt.http3Transport != nil {
			rt.http3Transport.CloseIdleConnections()
		}
		if d, ok := rt.dialer.(interface{ CloseIdleConnections() }); ok {
			d.CloseIdleConnections()
		}
	}
}

// closeCachedTransport releases connections held inside a cached transport's
// own pool; dropping the map entry alone would strand them until GC.
func (rt *roundTripper) closeCachedTransport(addr string) {
	if t, ok := rt.cachedTransports[addr].(interface{ CloseIdleConnections() }); ok {
		t.CloseIdleConnections()
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
	// Published transports own their configuration snapshots.
	browser.HeaderOrder = append([]string(nil), browser.HeaderOrder...)
	browser.Cookies = append([]Cookie(nil), browser.Cookies...)
	for i := range browser.Cookies {
		browser.Cookies[i].Unparsed = append([]string(nil), browser.Cookies[i].Unparsed...)
	}
	if browser.TLSConfig != nil {
		browser.TLSConfig = browser.TLSConfig.Clone()
	}
	if browser.PaddingExtension != nil {
		padding := *browser.PaddingExtension
		browser.PaddingExtension = &padding
	}
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

// Default JA3 fingerprint for Chrome
const DefaultChrome_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
