package cycletls

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestCreateNewClientSetsRequestIPForDirectConnections(t *testing.T) {
	client, err := createNewClient(Browser{}, 15, false, "", "", "127.0.0.1")
	if err != nil {
		t.Fatalf("createNewClient returned error: %v", err)
	}

	transport, ok := client.Transport.(*roundTripper)
	if !ok {
		t.Fatalf("transport type = %T, want *roundTripper", client.Transport)
	}
	if transport.RequestIP != "127.0.0.1" {
		t.Fatalf("RequestIP = %q, want %q", transport.RequestIP, "127.0.0.1")
	}
}

func TestCreateNewClientSetsRequestIPWhenProxyIsSet(t *testing.T) {
	client, err := createNewClient(Browser{}, 15, false, "", "http://127.0.0.1:8080", "127.0.0.1")
	if err != nil {
		t.Fatalf("createNewClient returned error: %v", err)
	}

	transport, ok := client.Transport.(*roundTripper)
	if !ok {
		t.Fatalf("transport type = %T, want *roundTripper", client.Transport)
	}
	if transport.RequestIP != "127.0.0.1" {
		t.Fatalf("RequestIP = %q, want 127.0.0.1", transport.RequestIP)
	}
}

func TestCreateNewClientRejectsInvalidRequestIPWhenProxyIsSet(t *testing.T) {
	_, err := createNewClient(Browser{}, 15, false, "", "http://127.0.0.1:8080", "not-an-ip")
	if err == nil {
		t.Fatal("expected invalid request IP error")
	}
}

// A .invalid hostname must reach the local origin through the proxy using IP,
// while the origin still sees the URL hostname in HTTP Host and TLS SNI.
func TestProxyRequestIPPreservesHostAndSNI(t *testing.T) {
	for _, proxyMode := range []string{"http", "https", "https-h2"} {
		for _, scheme := range []string{"http", "https"} {
			t.Run(proxyMode+"/"+scheme, func(t *testing.T) {
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sni := ""
					if r.TLS != nil {
						sni = r.TLS.ServerName
					}
					io.WriteString(w, r.Host+"|"+sni)
				}))
				if scheme == "https" {
					origin.StartTLS()
				} else {
					origin.Start()
				}
				defer origin.Close()
				target := origin.Listener.Addr().String()
				_, port, _ := net.SplitHostPort(target)
				authority := "origin.invalid:" + port
				proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "CONNECT" || r.Host != target {
						t.Errorf("proxy received %s %s, want CONNECT %s", r.Method, r.Host, target)
						http.Error(w, "unexpected target", 502)
						return
					}
					upstream, err := net.Dial("tcp", r.Host)
					if err != nil {
						t.Error(err)
						http.Error(w, "dial failed", 502)
						return
					}
					defer upstream.Close()
					if r.ProtoMajor == 2 {
						w.WriteHeader(200)
						w.(http.Flusher).Flush()
						forwarded := make(chan struct{})
						go func() {
							defer close(forwarded)
							io.Copy(upstream, r.Body)
							upstream.Close()
						}()
						io.Copy(flushingHTTP2ProxyWriter{w}, upstream)
						r.Body.Close()
						<-forwarded
						return
					}
					conn, buffered, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					if _, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
						t.Error(err)
						return
					}
					forwarded := make(chan struct{})
					go func() {
						defer close(forwarded)
						io.Copy(upstream, buffered)
						upstream.Close()
					}()
					io.Copy(conn, upstream)
					conn.Close()
					<-forwarded
				}))
				if proxyMode == "http" {
					proxyServer.Start()
				} else {
					proxyServer.EnableHTTP2 = proxyMode == "https-h2"
					proxyServer.StartTLS()
				}
				defer proxyServer.Close()
				client, err := createNewClient(Browser{InsecureSkipVerify: true}, 5, false, "", proxyServer.URL, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				defer closeClientTransport(client)
				resp, err := client.Get(scheme + "://" + authority + "/")
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				want := authority + "|"
				if scheme == "https" {
					want += "origin.invalid"
				}
				if err != nil || resp.StatusCode != 200 || string(body) != want {
					t.Fatalf("status=%d body=%q err=%v, want %q", resp.StatusCode, body, err, want)
				}
			})
		}
	}
}

func TestCreateNewClientRejectsInvalidRequestIPForDirectConnections(t *testing.T) {
	_, err := createNewClient(Browser{}, 15, false, "", "", "not-an-ip")
	if err == nil {
		t.Fatal("expected invalid request IP error")
	}
}

func TestRoundTripperGetDialAddrUsesRequestIPPortOnly(t *testing.T) {
	rt := &roundTripper{RequestIP: "2001:db8::1"}
	got := rt.getDialAddr("example.com:8443")
	want := "[2001:db8::1]:8443"
	if got != want {
		t.Fatalf("getDialAddr() = %q, want %q", got, want)
	}
}

func TestSOCKSProxyReceivesRequestIP(t *testing.T) {
	for _, scheme := range []string{"socks4", "socks5", "socks5h"} {
		for _, ip := range []string{"127.0.0.1", "2001:db8::1"} {
			if scheme == "socks4" && ip == "2001:db8::1" {
				continue // SOCKS4 supports IPv4 only.
			}
			t.Run(scheme+"/"+ip, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				target := make(chan string, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						target <- err.Error()
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					addr, err := readSOCKSRequestTarget(conn, scheme)
					if err != nil {
						target <- err.Error()
						return
					}
					target <- addr
					// Reject after inspecting the wire request; no upstream DNS or
					// connection is needed to verify the destination address.
					if scheme == "socks4" {
						conn.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
					} else {
						conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					}
				}()
				client, err := createNewClient(Browser{}, 5, false, "", scheme+"://"+listener.Addr().String(), ip)
				if err != nil {
					t.Fatal(err)
				}
				defer closeClientTransport(client)
				if resp, err := client.Get("http://origin.invalid:8443/"); err == nil {
					resp.Body.Close()
					t.Fatal("expected SOCKS rejection")
				}
				select {
				case got := <-target:
					want := "127.0.0.1:8443"
					if ip == "2001:db8::1" {
						want = "[2001:db8::1]:8443"
					}
					if got != want {
						t.Fatalf("SOCKS target=%q, want %q", got, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("proxy received no connection")
				}
			})
		}
	}
}

func readSOCKSRequestTarget(conn net.Conn, scheme string) (string, error) {
	if scheme == "socks4" {
		var request [8]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			return "", err
		}
		if _, err := bufio.NewReader(conn).ReadBytes(0); err != nil {
			return "", err
		}
		return net.JoinHostPort(net.IP(request[4:]).String(), strconv.Itoa(int(request[2])<<8|int(request[3]))), nil
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return "", err
	}
	if _, err := io.CopyN(io.Discard, conn, int64(greeting[1])); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return "", err
	}
	var size int
	switch request[3] {
	case 1:
		size = net.IPv4len
	case 4:
		size = net.IPv6len
	default:
		return "", fmt.Errorf("SOCKS address type=%d, want an IP literal", request[3])
	}
	address := make([]byte, size+2)
	if _, err := io.ReadFull(conn, address); err != nil {
		return "", err
	}
	return net.JoinHostPort(net.IP(address[:size]).String(), strconv.Itoa(int(address[size])<<8|int(address[size+1]))), nil
}
