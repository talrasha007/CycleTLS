package cycletls

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	fhttp "github.com/Danny-Dasilva/fhttp"

	"github.com/gorilla/websocket"
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// ClientPoolEntry represents a cached client with metadata
type ClientPoolEntry struct {
	Clients     []*fhttp.Client
	CreatedAt   time.Time
	LastUsed    time.Time
	key         string
	active      int
	requests    int64
	maxRequests int64
	retired     bool
}

// Global client pool with metadata
var (
	advancedClientPool      = make(map[string]*ClientPoolEntry)
	advancedClientPoolMutex = sync.RWMutex{}
)

type Browser struct {
	// TLS fingerprinting options
	EnableClientSessionCache bool
	PaddingExtension         *utls.UtlsPaddingExtension
	SignatureAlgorithms      string
	ShuffleExtensions        bool
	JA3                      string
	JA4r                     string // JA4 raw format with explicit cipher/extension values
	HTTP2Fingerprint         string
	QUICFingerprint          string
	USpec                    *uquic.QUICSpec // UQuic QUIC specification for HTTP3 fingerprinting
	DisableGrease            bool

	// Browser identification
	UserAgent string

	// Connection options
	Cookies            []Cookie
	InsecureSkipVerify bool
	ForceTLS12         bool
	ForceHTTP1         bool
	ForceHTTP3         bool

	// TLS 1.3 specific options
	TLS13AutoRetry bool

	// Ordered HTTP header fields
	HeaderOrder []string

	// TLS configuration
	TLSConfig *utls.Config

	// HTTP client
	client *fhttp.Client
}

// Protocol represents the HTTP protocol version
type Protocol string

const (
	// ProtocolHTTP1 represents HTTP/1.1
	ProtocolHTTP1 Protocol = "http1"

	// ProtocolHTTP2 represents HTTP/2
	ProtocolHTTP2 Protocol = "http2"

	// ProtocolHTTP3 represents HTTP/3
	ProtocolHTTP3 Protocol = "http3"

	// ProtocolWebSocket represents WebSocket protocol
	ProtocolWebSocket Protocol = "websocket"

	// ProtocolSSE represents Server-Sent Events
	ProtocolSSE Protocol = "sse"
)

var disabledRedirect = func(req *fhttp.Request, via []*fhttp.Request) error {
	return fhttp.ErrUseLastResponse
}

func clientBuilder(browser Browser, dialer proxy.ContextDialer, timeout int, disableRedirect bool, requestIP string) *fhttp.Client {
	//if timeout is not set in call default to 15
	if timeout == 0 {
		timeout = 15
	}
	client := &fhttp.Client{
		Transport: newRoundTripperWithIP(browser, dialer, requestIP),
		Timeout:   time.Duration(timeout) * time.Second,
	}
	//if disableRedirect is set to true httpclient will not redirect
	if disableRedirect {
		client.CheckRedirect = disabledRedirect
	}
	return client
}

// NewTransport creates a new HTTP client transport that modifies HTTPS requests
// to imitiate a specific JA3 hash and User-Agent.
// # Example Usage
// import (
//
//	"github.com/Danny-Dasilva/CycleTLS/cycletls"
//	http "github.com/Danny-Dasilva/fhttp" // note this is a drop-in replacement for net/http
//
// )
//
// ja3 := "771,52393-52392-52244-52243-49195-49199-49196-49200-49171-49172-156-157-47-53-10,65281-0-23-35-13-5-18-16-30032-11-10,29-23-24,0"
// ua := "Chrome Version 57.0.2987.110 (64-bit) Linux"
//
//	cycleClient := &http.Client{
//		Transport:     cycletls.NewTransport(ja3, ua),
//	}
//
// cycleClient.Get("https://tls.peet.ws/")
func NewTransport(ja3 string, useragent string) fhttp.RoundTripper {
	return newRoundTripper(Browser{
		JA3:       ja3,
		UserAgent: useragent,
	})
}

// NewTransportWithJA4 creates a new HTTP client transport that modifies HTTPS requests
// using JA4 fingerprinting.
func NewTransportWithJA4(ja4 string, useragent string) fhttp.RoundTripper {
	return newRoundTripper(Browser{
		JA4r:      ja4,
		UserAgent: useragent,
	})
}

// NewTransportWithHTTP2Fingerprint creates a new HTTP client transport with HTTP/2 fingerprinting
func NewTransportWithHTTP2Fingerprint(http2fp string, useragent string) fhttp.RoundTripper {
	return newRoundTripper(Browser{
		HTTP2Fingerprint: http2fp,
		UserAgent:        useragent,
	})
}

// NewTransportWithProxy creates a new HTTP client transport that modifies HTTPS requests
// to imitiate a specific JA3 hash and User-Agent, optionally specifying a proxy via proxy.ContextDialer.
func NewTransportWithProxy(ja3 string, useragent string, proxy proxy.ContextDialer) fhttp.RoundTripper {
	return newRoundTripper(Browser{
		JA3:       ja3,
		UserAgent: useragent,
	}, proxy)
}

// generateClientKey creates a unique key for client pooling based on browser configuration
func generateClientKey(browser Browser, timeout int, disableRedirect bool, meta string, proxyURL string, requestIP string) string {
	// Include connection settings. Request headers are applied per request.
	// Pointer-based extension
	// callbacks/configs use identity: distinct custom configurations must never
	// accidentally share. Metadata namespaces a pool; it cannot override TLS.
	if timeout == 0 {
		timeout = 15
	}
	config := browser
	config.client = nil
	config.UserAgent = ""
	config.Cookies = nil
	config.HeaderOrder = nil
	configStr := fmt.Sprintf("%#v|timeout:%d|redirect:%t|meta:%q|proxy:%q|ip:%q", config, timeout, disableRedirect, meta, proxyURL, requestIP)
	hash := sha256.Sum256([]byte(configStr))
	return fmt.Sprintf("%x", hash[:])
}

// getOrCreateClient retrieves a client from the pool or creates a new one
func getOrCreateClient(browser Browser, maxTotalReq int, timeout int, disableRedirect bool, userAgent string, enableConnectionReuse bool, meta string, proxyURL ...string) (*fhttp.Client, error) {
	proxy, requestIP := parseConnectionOptions(proxyURL...)

	// If connection reuse is disabled, always create a new client
	if !enableConnectionReuse {
		return createNewClient(browser, timeout, disableRedirect, userAgent, proxy, requestIP)
	}

	if maxTotalReq < 0 {
		maxTotalReq = 0
	}
	clientKey := fmt.Sprintf("%s:%d", generateClientKey(browser, timeout, disableRedirect, meta, proxy, requestIP), maxTotalReq)
	startClientPoolJanitor()
	var oldClient *fhttp.Client
	advancedClientPoolMutex.Lock()
	if entry, exists := advancedClientPool[clientKey]; exists {
		if entry.maxRequests == 0 || entry.requests < entry.maxRequests {
			entry.active++
			entry.requests++
			entry.LastUsed = time.Now()
			client := entry.Clients[0]
			advancedClientPoolMutex.Unlock()
			return client, nil
		}
		entry.retired = true
		delete(advancedClientPool, clientKey)
		if entry.active == 0 {
			oldClient = entry.Clients[0]
		}
	}
	client, err := createNewClient(browser, timeout, disableRedirect, userAgent, proxy, requestIP)
	if err == nil {
		now := time.Now()
		entry := &ClientPoolEntry{Clients: []*fhttp.Client{client}, CreatedAt: now, LastUsed: now, key: clientKey, active: 1, requests: 1, maxRequests: int64(maxTotalReq)}
		client.Transport.(*roundTripper).poolEntry = entry
		advancedClientPool[clientKey] = entry
	}
	advancedClientPoolMutex.Unlock()
	if oldClient != nil {
		closeClientTransport(oldClient)
	}
	return client, err
}

// releaseClient ends one acquisition, not one TCP/QUIC stream. All callers
// must close the response body before release, including errors and SSE.
func releaseClient(client *fhttp.Client) {
	rt, ok := client.Transport.(*roundTripper)
	if !ok {
		client.CloseIdleConnections()
		return
	}
	entry := rt.poolEntry
	if entry == nil {
		_ = rt.Close()
		return
	}
	advancedClientPoolMutex.Lock()
	entry.active--
	entry.LastUsed = time.Now()
	if entry.maxRequests > 0 && entry.requests >= entry.maxRequests {
		entry.retired = true
		if advancedClientPool[entry.key] == entry {
			delete(advancedClientPool, entry.key)
		}
	}
	closeNow := entry.retired && entry.active == 0
	advancedClientPoolMutex.Unlock()
	if closeNow {
		_ = rt.Close()
	}
}

func closeClientTransport(client *fhttp.Client) {
	if closer, ok := client.Transport.(interface{ Close() error }); ok {
		_ = closer.Close()
	} else {
		client.CloseIdleConnections()
	}
}

// createNewClient creates a new HTTP client (internal function)
func createNewClient(browser Browser, timeout int, disableRedirect bool, userAgent string, proxyURL ...string) (*fhttp.Client, error) {
	proxyURLValue, requestIP := parseConnectionOptions(proxyURL...)
	var dialer proxy.ContextDialer
	if proxyURLValue != "" {
		var err error
		dialer, err = newConnectDialer(proxyURLValue, userAgent)
		if err != nil {
			return &fhttp.Client{
				Timeout:       time.Duration(timeout) * time.Second,
				CheckRedirect: disabledRedirect,
			}, err
		}
	} else {
		if requestIP != "" && net.ParseIP(requestIP) == nil {
			return nil, fmt.Errorf("invalid request IP: %s", requestIP)
		}
		dialer = proxy.Direct
	}

	// The registry key has already captured the caller's original options.
	// Resolve random policies only when constructing a new generation.
	return clientBuilder(resolveBrowserFingerprint(browser), dialer, timeout, disableRedirect, requestIP), nil
}

// cleanupClientPool removes old unused clients from the pool
func CleanupClientPool(maxAge time.Duration) {
	var closing []*fhttp.Client
	advancedClientPoolMutex.Lock()
	now := time.Now()
	for key, entry := range advancedClientPool {
		if entry.active == 0 && now.Sub(entry.LastUsed) > maxAge {
			entry.retired = true
			closing = append(closing, entry.Clients...)
			delete(advancedClientPool, key)
		}
	}
	advancedClientPoolMutex.Unlock()
	for _, client := range closing {
		closeClientTransport(client)
	}
}

// clearAllConnections clears all connections from the pool for test isolation
func clearAllConnections() {
	var closing []*fhttp.Client
	advancedClientPoolMutex.Lock()
	for _, entry := range advancedClientPool {
		entry.retired = true
		if entry.active == 0 {
			closing = append(closing, entry.Clients...)
		}
	}
	advancedClientPool = make(map[string]*ClientPoolEntry)
	advancedClientPoolMutex.Unlock()
	for _, client := range closing {
		closeClientTransport(client)
	}
}

// newClientWithReuse creates a new http client with configurable connection reuse
func newClientWithReuse(browser Browser, maxTotalReq int, timeout int, disableRedirect bool, UserAgent string, enableConnectionReuse bool, meta string, proxyURL ...string) (*fhttp.Client, error) {
	return getOrCreateClient(browser, maxTotalReq, timeout, disableRedirect, UserAgent, enableConnectionReuse, meta, proxyURL...)
}

// clientPoolJanitorOnce guards the lazy start of the background cleaner that
// evicts idle pooled clients, keeping advancedClientPool bounded over time.
var clientPoolJanitorOnce sync.Once

func startClientPoolJanitor() {
	clientPoolJanitorOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				CleanupClientPool(10 * time.Minute)
			}
		}()
	})
}

func parseConnectionOptions(values ...string) (proxyURL string, requestIP string) {
	if len(values) > 0 {
		proxyURL = values[0]
	}
	if len(values) > 1 && proxyURL == "" {
		requestIP = values[1]
	}
	return proxyURL, requestIP
}

// WebSocketConnect establishes a WebSocket connection
func (browser Browser) WebSocketConnect(ctx context.Context, urlStr string) (*websocket.Conn, *fhttp.Response, error) {
	// Create TLS config from browser settings
	tlsConfig := &utls.Config{
		InsecureSkipVerify: browser.InsecureSkipVerify,
	}

	// Create http headers directly
	httpHeaders := make(fhttp.Header)
	httpHeaders.Set("User-Agent", browser.UserAgent)

	// Convert headers and create WebSocket client
	convertedHeaders := ConvertFhttpHeader(httpHeaders)
	wsClient := NewWebSocketClient(tlsConfig, convertedHeaders)

	// Connect and return
	conn, resp, err := wsClient.ConnectContext(ctx, urlStr)
	if err != nil {
		return nil, nil, err
	}

	// Convert response to fhttp.Response
	fhttpResp := &fhttp.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         resp.Proto,
		ProtoMajor:    resp.ProtoMajor,
		ProtoMinor:    resp.ProtoMinor,
		Body:          resp.Body,
		ContentLength: resp.ContentLength,
	}

	// Convert headers
	fhttpHeaders := make(fhttp.Header)
	for k, v := range resp.Header {
		fhttpHeaders[k] = v
	}
	fhttpResp.Header = fhttpHeaders

	// Convert request if present
	if resp.Request != nil {
		fhttpReq := &fhttp.Request{
			Method: resp.Request.Method,
			URL:    resp.Request.URL,
			Proto:  resp.Request.Proto,
			Header: fhttpHeaders,
			Body:   resp.Request.Body,
		}
		fhttpResp.Request = fhttpReq
	}

	return conn, fhttpResp, nil
}

// SSEConnect establishes an SSE connection
func (browser Browser) SSEConnect(ctx context.Context, urlStr string) (*SSEResponse, error) {
	// Create HTTP client with connection reuse enabled
	httpClient, err := newClientWithReuse(browser, 0, 30, false, browser.UserAgent, true, "")
	if err != nil {
		return nil, err
	}

	// Create headers from browser settings
	headers := make(fhttp.Header)
	headers.Set("User-Agent", browser.UserAgent)

	// Create SSE client
	sseClient := NewSSEClient(httpClient, headers)

	// Connect to SSE endpoint
	resp, err := sseClient.Connect(withRequestSettings(ctx, browser), urlStr)
	if err != nil {
		releaseClient(httpClient)
		return nil, err
	}
	resp.onClose = func() { releaseClient(httpClient) }
	return resp, nil
}
