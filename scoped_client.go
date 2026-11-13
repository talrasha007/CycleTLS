package cycletls

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"

	http "github.com/Danny-Dasilva/fhttp"
)

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
// RAND fingerprints are resolved once per client. Request defaults, including
// headers, cookies, body and timeout, come from options and remain immutable.
func NewClient(options Options) (*Client, error) {
	for name, value := range options.Headers {
		if strings.EqualFold(name, "Connection") {
			for _, token := range strings.Split(value, ",") {
				if strings.EqualFold(strings.TrimSpace(token), "close") {
					return nil, fmt.Errorf("NewClient requires persistent connections: Connection: close is not supported")
				}
			}
		}
	}
	options.Headers = maps.Clone(options.Headers)
	options.HeaderOrder = slices.Clone(options.HeaderOrder)
	options.BodyBytes = slices.Clone(options.BodyBytes)
	options.Cookies = slices.Clone(options.Cookies)
	for i := range options.Cookies {
		options.Cookies[i].Unparsed = slices.Clone(options.Cookies[i].Unparsed)
	}
	if options.PaddingExtension != nil {
		padding := *options.PaddingExtension
		options.PaddingExtension = &padding
	}
	browser := browserFromOptions(options)
	httpClient, err := createNewClient(browser, options.Timeout, options.DisableRedirect, options.UserAgent, options.Proxy, options.IP, options.LocalIP)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{httpClient: httpClient, options: options, browser: browser, ctx: ctx, cancel: cancel}, nil
}

// Do sends a request using the constructor's immutable defaults. The response
// body is consumed according to MaxResponseBodySize and closed before return.
// Response and network-error encoding otherwise match CycleTLS.Do.
func (c *Client) Do(url, method string) (Response, error) {
	return c.DoContext(context.Background(), url, method)
}

// DoContext also honors the caller's cancellation. Cancellation of one request
// does not close the shared connection or cancel peers. After Close, it returns
// net.ErrClosed. Cancellation while the request is active returns ctx.Err().
func (c *Client) DoContext(ctx context.Context, url, method string) (Response, error) {
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
	response, err := doClientRequest(requestCtx, c.httpClient, c.browser, url, c.options, method)
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
