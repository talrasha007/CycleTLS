package cycletls

import (
	"context"
	"errors"
	utls "github.com/refraction-networking/utls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketClient represents a client for WebSocket connections
type WebSocketClient struct {
	// Dialer is the websocket dialer
	Dialer *websocket.Dialer

	// HTTP client for WebSocket handshake
	HTTPClient *http.Client

	// Headers to be included in the WebSocket handshake
	Headers http.Header
}

// NewWebSocketClient creates a new WebSocket client
func NewWebSocketClient(tlsConfig *utls.Config, headers http.Header) *WebSocketClient {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       ConvertUtlsConfig(tlsConfig),
	}

	client := &http.Client{
		Transport: transport,
	}

	// Convert TLS config but ensure HTTP/1.1 for WebSocket
	tlsConf := ConvertUtlsConfig(tlsConfig)
	if tlsConf != nil {
		// WebSocket requires HTTP/1.1, so remove HTTP/2 protocols
		tlsConf.NextProtos = []string{"http/1.1"}
	}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		TLSClientConfig:  tlsConf,
	}

	return &WebSocketClient{
		Dialer:     dialer,
		HTTPClient: client,
		Headers:    headers,
	}
}

// Connect establishes a WebSocket connection
func (wsc *WebSocketClient) Connect(urlStr string) (*websocket.Conn, *http.Response, error) {
	return wsc.ConnectContext(context.Background(), urlStr)
}

// ConnectContext applies cancellation to the opening handshake.
func (wsc *WebSocketClient) ConnectContext(ctx context.Context, urlStr string) (*websocket.Conn, *http.Response, error) {
	// Parse the URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}

	// Determine the scheme for WebSocket
	var scheme string
	switch u.Scheme {
	case "http":
		scheme = "ws"
	case "https":
		scheme = "wss"
	case "ws", "wss":
		scheme = u.Scheme
	default:
		// Default to ws
		scheme = "ws"
	}

	// Create a new URL with the WebSocket scheme
	wsURL := url.URL{
		Scheme:   scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	// Gorilla applies Context to dialing, but the HTTP upgrade itself uses
	// blocking I/O. Close that socket on cancellation until the upgrade ends.
	dialer := *wsc.Dialer
	stop := func() bool { return true }
	defer func() { stop() }()
	watchDial := func(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
		return func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dial(dialCtx, network, addr)
			if err == nil {
				stop = context.AfterFunc(ctx, func() { _ = conn.Close() })
			}
			return conn, err
		}
	}
	dial := dialer.NetDialContext
	if dial == nil {
		if dialer.NetDial != nil {
			dial = func(_ context.Context, network, addr string) (net.Conn, error) {
				return wsc.Dialer.NetDial(network, addr)
			}
		} else {
			dial = (&net.Dialer{}).DialContext
		}
	}
	dialer.NetDialContext = watchDial(dial)
	if dialer.NetDialTLSContext != nil {
		dialer.NetDialTLSContext = watchDial(dialer.NetDialTLSContext)
	}
	conn, resp, err := dialer.DialContext(ctx, wsURL.String(), wsc.Headers)
	if !stop() || ctx.Err() != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, resp, ctx.Err()
	}
	if err != nil {
		return nil, resp, err
	}

	return conn, resp, nil
}

// WebSocketResponse represents a response from a WebSocket connection
type WebSocketResponse struct {
	// Conn is the WebSocket connection
	Conn *websocket.Conn

	// Response is the HTTP response from the WebSocket handshake
	Response *http.Response
}

// Close closes the WebSocket connection
func (wsr *WebSocketResponse) Close() error {
	if wsr.Conn != nil {
		// Send close message
		err := wsr.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		return errors.Join(err, wsr.Conn.Close())
	}
	return nil
}

// Send sends a message over the WebSocket connection
func (wsr *WebSocketResponse) Send(messageType int, data []byte) error {
	return wsr.Conn.WriteMessage(messageType, data)
}

// Receive receives a message from the WebSocket connection
func (wsr *WebSocketResponse) Receive() (int, []byte, error) {
	return wsr.Conn.ReadMessage()
}
