package cycletls

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	http "github.com/Danny-Dasilva/fhttp"
)

// RequestOptions contains values for one request; none are retained by Client.
// Callers must not mutate maps or slices while the request is running.
type RequestOptions struct {
	Headers     map[string]string
	UserAgent   string
	HeaderOrder []string
	Cookies     []Cookie
	Body        string
	BodyBytes   []byte
}

// Client owns an independent transport and is safe for concurrent requests.
// It must not be copied after first use. Call Close when finished; garbage
// collection alone does not release persistent connections.
type Client struct {
	httpClient *http.Client
	options    Options
	browser    Browser
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	requests   sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
}

// NewClient snapshots options and creates a private, persistent client.
// HTTP2 requests to the same origin reuse an available connection and wait
// for stream capacity. A peer GOAWAY or an unusable connection requires a new
// connection. HTTP1 does not provide the same single-connection guarantee.
//
// Unlike Init, this client does not participate in the global client pool.
// EnableConnectionReuse, MaxTotalRequests, MaxIdleClients and Meta have no
// effect: ownership lasts until Close, without request-count rotation.
// RAND fingerprints are resolved once per client. Connection settings, timeout
// and response body limits remain immutable. Headers, UserAgent, HeaderOrder,
// Cookies and Body/BodyBytes must be supplied through RequestOptions in Do.
func NewClient(options Options) (*Client, error) {
	if len(options.Headers) > 0 || options.UserAgent != "" || len(options.HeaderOrder) > 0 ||
		len(options.Cookies) > 0 || options.Body != "" || len(options.BodyBytes) > 0 || options.OrderAsProvided {
		return nil, fmt.Errorf("NewClient accepts connection settings only: pass headers, UserAgent, HeaderOrder, cookies and body in Do RequestOptions")
	}
	if options.PaddingExtension != nil {
		padding := *options.PaddingExtension
		options.PaddingExtension = &padding
	}
	browser := browserFromOptions(options)
	httpClient, err := createNewClient(browser, options.Timeout, options.DisableRedirect, "", options.Proxy, options.IP, options.LocalIP)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{httpClient: httpClient, options: options, browser: browser, ctx: ctx, cancel: cancel}, nil
}

// Do sends a request with optional per-request headers, cookies and body. The response
// body is consumed according to MaxResponseBodySize and closed before return.
// Response and network-error encoding otherwise match CycleTLS.Do.
func (c *Client) Do(url, method string, request ...RequestOptions) (Response, error) {
	return c.DoContext(context.Background(), url, method, request...)
}

// DoContext also honors the caller's cancellation. Cancellation of one request
// does not close the shared connection or cancel peers. After Close, it returns
// net.ErrClosed. Cancellation while the request is active returns ctx.Err().
func (c *Client) DoContext(ctx context.Context, url, method string, request ...RequestOptions) (Response, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Response{}, net.ErrClosed
	}
	c.requests.Add(1)
	c.mu.Unlock()
	defer c.requests.Done()
	requestCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()
	if len(request) > 1 {
		return Response{}, fmt.Errorf("Do accepts at most one RequestOptions value")
	}
	options := c.options
	browser := c.browser
	if len(request) == 1 {
		r := request[0]
		for name, value := range r.Headers {
			if strings.EqualFold(name, "Connection") {
				for _, token := range strings.Split(value, ",") {
					if strings.EqualFold(strings.TrimSpace(token), "close") {
						return Response{}, fmt.Errorf("Client requires persistent connections: Connection: close is not supported")
					}
				}
			}
			if r.UserAgent == "" && strings.EqualFold(name, "User-Agent") {
				r.UserAgent = value
			}
		}
		options.Headers = r.Headers
		options.UserAgent = r.UserAgent
		options.HeaderOrder = r.HeaderOrder
		options.Cookies = r.Cookies
		options.Body = r.Body
		options.BodyBytes = r.BodyBytes
		browser.UserAgent = r.UserAgent
		browser.HeaderOrder = r.HeaderOrder
		browser.Cookies = r.Cookies
	}
	response, err := doClientRequest(requestCtx, c.httpClient, browser, url, options, method)
	if requestCtx.Err() != nil {
		return response, requestCtx.Err()
	}
	return response, err
}

// Close permanently stops this client. It cancels pending requests, waits for
// their response bodies to be released, then closes its transport and sockets.
// It is safe to call concurrently and repeatedly, and never closes other clients.
// Do not call Close synchronously from TLSHandshakeDone: the callback is part
// of a request Close must wait for. Use go c.Close() from such a callback.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancel()
		c.mu.Unlock()
		c.requests.Wait()
		c.closeErr = c.httpClient.Transport.(*roundTripper).Close()
	})
	return c.closeErr
}
