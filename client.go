package cycletls

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	fhttp "github.com/Danny-Dasilva/fhttp"

	"github.com/gorilla/websocket"
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// Global client pool for connection reuse
var (
	clientPool      = make(map[string]fhttp.Client)
	clientPoolMutex = sync.RWMutex{}
)

// ClientPoolEntry represents a cached client with metadata
type ClientPoolEntry struct {
	Clients   []fhttp.Client
	CreatedAt time.Time
	LastUsed  time.Time
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

func clientBuilder(browser Browser, dialer proxy.ContextDialer, timeout int, disableRedirect bool) fhttp.Client {
	//if timeout is not set in call default to 15
	if timeout == 0 {
		timeout = 15
	}
	client := fhttp.Client{
		Transport: newRoundTripper(browser, dialer),
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
func generateClientKey(browser Browser, timeout int, disableRedirect bool, meta string, proxyURL string) string {
	// Create cookie signature for the key
	cookieStr := ""
	for _, cookie := range browser.Cookies {
		cookieStr += fmt.Sprintf("|cookie:%s=%s", cookie.Name, cookie.Value)
	}

	// Create a hash of the configuration that affects connection behavior
	ua := browser.UserAgent
	ja3 := browser.JA3
	ja4r := browser.JA4r

	if len(meta) > 0 {
		ua = meta
		ja3 = meta
		ja4r = meta
	}

	configStr := fmt.Sprintf("ja3:%s|ja4r:%s|http2:%s|quic:%s|ua:%s|proxy:%s|timeout:%d|redirect:%t|skipverify:%t|forcehttp1:%t|forcehttp3:%t%s",
		ja3,
		ja4r,
		browser.HTTP2Fingerprint,
		browser.QUICFingerprint,
		ua,
		proxyURL,
		timeout,
		disableRedirect,
		browser.InsecureSkipVerify,
		browser.ForceHTTP1,
		browser.ForceHTTP3,
		cookieStr,
	)

	// Generate SHA256 hash for the key
	hash := sha256.Sum256([]byte(configStr))
	return fmt.Sprintf("%x", hash[:16]) // Use first 16 bytes for shorter key
}

// getOrCreateClient retrieves a client from the pool or creates a new one
func getOrCreateClient(browser Browser, maxTotalReq int, timeout int, disableRedirect bool, userAgent string, enableConnectionReuse bool, meta string, proxyURL ...string) (fhttp.Client, error) {
	// If connection reuse is disabled, always create a new client
	if !enableConnectionReuse {
		return createNewClient(browser, timeout, disableRedirect, userAgent, proxyURL...)
	}

	proxy := ""
	if len(proxyURL) > 0 {
		proxy = proxyURL[0]
	}

	clientKey := generateClientKey(browser, timeout, disableRedirect, meta, proxy)

	// Try to get existing client from pool
	advancedClientPoolMutex.Lock()
	defer advancedClientPoolMutex.Unlock()
	if entry, exists := advancedClientPool[clientKey]; exists {
		// Update last used time
		entry.LastUsed = time.Now()

		for i := 0; i < len(entry.Clients); i++ {
			client := entry.Clients[i]
			if transport, ok := client.Transport.(*roundTripper); ok {
				if maxTotalReq > 0 && transport.TotalRequests < int64(maxTotalReq) {
					if i > 0 {
						entry.Clients = entry.Clients[i:]
					}

					transport.TotalRequests++
					return client, nil
				} else if maxTotalReq <= 0 {
					entry.Clients = entry.Clients[1:]

					transport.TotalRequests++
					return client, nil
				}
			}
		}

		// No available client, fall through to create a new one
		entry.Clients = []fhttp.Client{}
	}

	// Create new client
	client, err := createNewClient(browser, timeout, disableRedirect, userAgent, proxyURL...)
	if err != nil {
		return fhttp.Client{}, err
	}

	// Add new entry to pool
	if maxTotalReq > 0 {
		advancedClientPool[clientKey] = &ClientPoolEntry{
			Clients:   []fhttp.Client{client},
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
		}
	}

	return client, nil
}

// createNewClient creates a new HTTP client (internal function)
func createNewClient(browser Browser, timeout int, disableRedirect bool, userAgent string, proxyURL ...string) (fhttp.Client, error) {
	var dialer proxy.ContextDialer
	if len(proxyURL) > 0 && len(proxyURL[0]) > 0 {
		var err error
		dialer, err = newConnectDialer(proxyURL[0], userAgent)
		if err != nil {
			return fhttp.Client{
				Timeout:       time.Duration(timeout) * time.Second,
				CheckRedirect: disabledRedirect,
			}, err
		}
	} else {
		dialer = proxy.Direct
	}

	return clientBuilder(browser, dialer, timeout, disableRedirect), nil
}

// cleanupClientPool removes old unused clients from the pool
func CleanupClientPool(maxAge time.Duration) {
	advancedClientPoolMutex.Lock()
	defer advancedClientPoolMutex.Unlock()

	now := time.Now()
	for key, entry := range advancedClientPool {
		if now.Sub(entry.LastUsed) > maxAge {
			go func() {
				for _, client := range entry.Clients {
					if transport, ok := client.Transport.(*roundTripper); ok {
						transport.CloseIdleConnections()
					}
				}
			}()
			delete(advancedClientPool, key)
		}
	}
}

// clearAllConnections clears all connections from the pool for test isolation
func clearAllConnections() {
	advancedClientPoolMutex.Lock()
	defer advancedClientPoolMutex.Unlock()

	// Close all connections in the pool before clearing
	for _, entry := range advancedClientPool {
		for _, client := range entry.Clients {
			if transport, ok := client.Transport.(*roundTripper); ok {
				transport.CloseIdleConnections()
			}
		}
	}

	// Clear the entire pool
	advancedClientPool = make(map[string]*ClientPoolEntry)
}

// newClientWithReuse creates a new http client with configurable connection reuse
func newClientWithReuse(browser Browser, maxTotalReq int, timeout int, disableRedirect bool, UserAgent string, enableConnectionReuse bool, meta string, proxyURL ...string) (fhttp.Client, error) {
	return getOrCreateClient(browser, maxTotalReq, timeout, disableRedirect, UserAgent, enableConnectionReuse, meta, proxyURL...)
}

func pushBackClientToPool(maxIdle int, client fhttp.Client, browser Browser, timeout int, disableRedirect bool, meta string, proxyURL string) {
	clientKey := generateClientKey(browser, timeout, disableRedirect, meta, proxyURL)

	advancedClientPoolMutex.Lock()
	defer advancedClientPoolMutex.Unlock()

	entry, exists := advancedClientPool[clientKey]
	if !exists {
		entry = &ClientPoolEntry{
			Clients:   []fhttp.Client{},
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
		}
		advancedClientPool[clientKey] = entry
	}

	for i := 0; i < len(entry.Clients); i++ {
		if entry.Clients[i].Transport == client.Transport {
			// Client already in pool, no need to add
			return
		}
	}

	if len(entry.Clients) < maxIdle {
		entry.Clients = append(entry.Clients, client)
		entry.LastUsed = time.Now()
	} else {
		if transport, ok := client.Transport.(*roundTripper); ok {
			transport.CloseIdleConnections()
		}
	}
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
	conn, resp, err := wsClient.Connect(urlStr)
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
	sseClient := NewSSEClient(&httpClient, headers)

	// Connect to SSE endpoint
	return sseClient.Connect(ctx, urlStr)
}
