package cycletls

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestLocalIPResponseAndReuse(t *testing.T) {
	for _, mode := range []string{"http", "https", "h2"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, r.RemoteAddr)
			}))
			if mode == "http" {
				s.Start()
			} else {
				s.EnableHTTP2 = mode == "h2"
				s.StartTLS()
			}
			defer s.Close()
			c := Init()
			defer c.Close()
			opts := Options{EnableConnectionReuse: true, InsecureSkipVerify: true, ForceHTTP1: mode != "h2", MaxResponseBodySize: -1, Timeout: 5}
			// Exercise the public JSON option and response field as well as Go callers.
			if err := json.Unmarshal([]byte(`{"localIp":"127.0.0.1"}`), &opts); err != nil {
				t.Fatal(err)
			}
			var peer string
			for i := 0; i < 2; i++ {
				r, err := c.Do(s.URL, opts, "GET")
				if err != nil || r.Status != 200 {
					t.Fatalf("request: %+v %v", r, err)
				}
				data, _ := json.Marshal(r)
				var fields map[string]any
				json.Unmarshal(data, &fields)
				host, _, _ := net.SplitHostPort(r.Body)
				if fields["localIp"] != host {
					t.Fatalf("localIp=%v, actual peer=%s", fields["localIp"], r.Body)
				}
				if i > 0 && r.Body != peer {
					t.Fatalf("connection not reused: %s -> %s", peer, r.Body)
				}
				peer = r.Body
			}
		})
	}
}

func TestLocalIPPoolUsesCIDRPolicy(t *testing.T) {
	t.Cleanup(clearAllConnections)
	get := func(source string) *roundTripper {
		c, err := newClientWithReuse(Browser{}, 0, 5, false, "", true, t.Name(), "", "", source)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { releaseClient(c) })
		return c.Transport.(*roundTripper)
	}
	a := get("2001:db8::1234/64")
	if a != get("2001:db8::/64") {
		t.Fatal("equivalent CIDRs did not share a client")
	}
	if a == get("2001:db8:1::/64") {
		t.Fatal("different source CIDRs shared a client")
	}
	if a == get("2001:db8::1") {
		t.Fatal("fixed source IP shared a CIDR client")
	}
}

func TestLocalIPCIDRRandomAddresses(t *testing.T) {
	for _, cidr := range []string{"2001:db8::/64", "2001:db8:ab00::/73", "::/0", "::1/128"} {
		prefix := netip.MustParsePrefix(cidr)
		d := &localIPDialer{source: cidr}
		seen := make(map[string]bool)
		for i := 0; i < 64; i++ {
			addr, err := d.localAddr()
			if err != nil {
				t.Fatal(err)
			}
			ip, ok := netip.AddrFromSlice(addr.IP)
			if !ok || !prefix.Contains(ip) || addr.Port != 0 {
				t.Fatalf("%s generated %v", cidr, addr)
			}
			seen[ip.String()] = true
		}
		if prefix.Bits() < 128 && len(seen) < 2 {
			t.Fatalf("%s never changed addresses", cidr)
		}
	}
}

func TestLocalIPIPv6CIDRConnection(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.RemoteAddr) }))
	s.Listener.Close()
	s.Listener = l
	s.Start()
	defer s.Close()
	c := Init()
	defer c.Close()
	r, err := c.Do(s.URL, Options{LocalIP: "::1/128", Timeout: 5, MaxResponseBodySize: -1}, "GET")
	if err != nil || r.Status != 200 || r.LocalIP != "::1" {
		t.Fatalf("response=%+v err=%v", r, err)
	}
	ip, _, _ := net.SplitHostPort(r.Body)
	if ip != r.LocalIP {
		t.Fatalf("actual peer=%q localIp=%q", ip, r.LocalIP)
	}
}

func TestLocalIPBindingFailure(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("request used another source IP") }))
	defer s.Close()
	c := Init()
	defer c.Close()
	r, err := c.Do(s.URL, Options{LocalIP: "192.0.2.99", Timeout: 2}, "GET")
	if err == nil && r.Status == 200 {
		t.Fatal("unavailable source IP silently bypassed")
	}
	if r.LocalIP != "" {
		t.Fatalf("failed connection reports localIp=%q", r.LocalIP)
	}
}

func TestLocalIPRedirectAndConcurrentOrigins(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	v6 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ipv6") }))
	v6.Listener.Close()
	v6.Listener = l
	v6.Start()
	defer v6.Close()
	v4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, v6.URL, 302)
			return
		}
		io.WriteString(w, "ipv4")
	}))
	defer v4.Close()
	c := Init()
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u, want := v4.URL, "127.0.0.1"
			if i%2 == 0 {
				u, want = v4.URL+"/redirect", "::1"
			}
			r, err := c.Do(u, Options{EnableConnectionReuse: true, Timeout: 5, MaxResponseBodySize: -1}, "GET")
			if err != nil || r.Status != 200 || r.LocalIP != want {
				t.Errorf("response=%+v err=%v want=%s", r, err, want)
			}
		}(i)
	}
	wg.Wait()
}

// The proxy uses IPv6 while the destination uses IPv4. The source policy must
// apply to the proxy connection, and the response must report that connection.
func TestLocalIPProxyConnection(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	for _, scheme := range []string{"http", "socks4", "socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			l, err := net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Skipf("IPv6 loopback unavailable: %v", err)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := l.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				var target string
				if scheme == "http" {
					req, readErr := http.ReadRequest(bufio.NewReader(conn))
					if readErr != nil {
						t.Error(readErr)
						return
					}
					target = req.Host
				} else {
					target, err = readSOCKSRequestTarget(conn, scheme)
					if err != nil {
						t.Error(err)
						return
					}
				}
				upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				defer upstream.Close()
				switch scheme {
				case "http":
					io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
				case "socks4":
					conn.Write([]byte{0, 90, 0, 0, 0, 0, 0, 0})
				default:
					conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				}
				copied := make(chan struct{})
				go func() { defer close(copied); io.Copy(upstream, conn); upstream.Close() }()
				io.Copy(conn, upstream)
				conn.Close()
				<-copied
			}()
			c := Init()
			failed, err := c.Do(origin.URL, Options{Proxy: scheme + "://" + l.Addr().String(), LocalIP: "2001:db8::99", Timeout: 2}, "GET")
			if err == nil && failed.Status == 200 {
				t.Error("proxy connection bypassed unavailable source IP")
			}
			r, err := c.Do(origin.URL, Options{Proxy: scheme + "://" + l.Addr().String(), LocalIP: "::1/128", Timeout: 5, MaxResponseBodySize: -1}, "GET")
			c.Close()
			l.Close()
			<-done
			if err != nil || r.Status != 200 || r.Body != "ok" || r.LocalIP != "::1" {
				t.Fatalf("response=%+v err=%v", r, err)
			}
		})
	}
}

func TestLocalIPHTTP3IgnoresPolicyAndPoolKey(t *testing.T) {
	s := startSharedH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	c := Init()
	defer c.Close()
	for _, source := range []string{"bad-ip", "2001:db8::/64"} {
		r, err := c.Do(s.url, Options{ForceHTTP3: true, LocalIP: source, InsecureSkipVerify: true, EnableConnectionReuse: true, Timeout: 5, MaxResponseBodySize: -1}, "GET")
		if err != nil || r.Status != 200 || r.LocalIP != "" {
			t.Fatalf("HTTP3 response=%+v err=%v", r, err)
		}
	}
	if s.connections.Load() != 1 {
		t.Fatalf("ignored policies split HTTP3 pool: %d connections", s.connections.Load())
	}
}

func TestLocalIPDialContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := (&localIPDialer{source: "::1/128"}).DialContext(ctx, "tcp", "[::1]:80")
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("canceled dial succeeded")
	}
}

func TestLocalIPValidationAndHTTP3Ignore(t *testing.T) {
	for _, source := range []string{"bad-ip", "192.0.2.0/24", "2001:db8::/129"} {
		c, err := createNewClient(Browser{}, 5, false, "", "", "", source)
		if err == nil {
			closeClientTransport(c)
			t.Errorf("accepted invalid localIp %q", source)
		}
		c, err = createNewClient(Browser{ForceHTTP3: true}, 5, false, "", "", "", source)
		if err != nil {
			t.Errorf("HTTP3 must ignore localIp: %v", err)
		} else {
			closeClientTransport(c)
		}
	}
}
