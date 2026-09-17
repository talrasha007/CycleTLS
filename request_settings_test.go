package cycletls

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedRequestHeaderOrderOnWire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		for i := 0; i < 3; i++ {
			var raw strings.Builder
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
				raw.WriteString(line)
			}
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", raw.Len(), raw.String())
		}
	}()
	c := Init()
	defer c.Close()
	for i, order := range [][]string{{"x-first", "x-second"}, {"x-second", "x-first"}, {"x-first", "x-second"}} {
		r, err := c.Do("http://"+listener.Addr().String(), Options{EnableConnectionReuse: true, ForceHTTP1: true, HeaderOrder: order, Headers: map[string]string{"X-First": "one", "X-Second": "two"}, MaxResponseBodySize: -1, Timeout: 5}, "GET")
		if err != nil || r.Status != 200 {
			t.Fatalf("request %d: %v %+v", i, err, r)
		}
		raw := strings.ToLower(r.Body)
		first, second := strings.Index(raw, order[0]+":"), strings.Index(raw, order[1]+":")
		if first < 0 || second < 0 || first >= second {
			t.Fatalf("request %d header order wrong: %s", i, r.Body)
		}
	}
	<-done
}

func TestSharedSSERequestSettings(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run(fmt.Sprintf("async=%t", async), func(t *testing.T) {
			clearAllConnections()
			defer clearAllConnections()
			var connections atomic.Int32
			s := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				id := r.URL.Query().Get("id")
				if r.UserAgent() != "agent-"+id || r.Header.Get("Cookie") != "session="+id {
					t.Errorf("SSE %s has UA=%q Cookie=%q", id, r.UserAgent(), r.Header.Get("Cookie"))
				}
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprintf(w, "data: %s\n\n", id)
			}))
			s.EnableHTTP2 = true
			s.Config.ConnState = func(_ net.Conn, state stdhttp.ConnState) {
				if state == stdhttp.StateNew {
					connections.Add(1)
				}
			}
			s.StartTLS()
			defer s.Close()
			var wg sync.WaitGroup
			for i := 0; i < 64; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					id := fmt.Sprint(i)
					browser := Browser{InsecureSkipVerify: true, UserAgent: "agent-" + id, Cookies: []Cookie{{Name: "session", Value: id}}, HeaderOrder: []string{"cookie", "user-agent"}}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if async {
						req := dispatchSSERequest(cycleTLSRequest{RequestID: "settings-sse-" + id, Options: Options{URL: s.URL + "/?id=" + id, EnableConnectionReuse: true, InsecureSkipVerify: true, UserAgent: browser.UserAgent, Cookies: browser.Cookies, HeaderOrder: browser.HeaderOrder}}, ctx)
						out := make(chan []byte)
						done := make(chan struct{})
						go func() {
							for range out {
							}
							close(done)
						}()
						dispatchSSEAsync(req, out)
						close(out)
						<-done
						return
					}
					r, err := browser.SSEConnect(ctx, s.URL+"/?id="+id)
					if err != nil {
						t.Error(err)
						return
					}
					defer r.Close()
					body, err := io.ReadAll(r.Response.Body)
					if err != nil || string(body) != "data: "+id+"\n\n" {
						t.Errorf("SSE %s body=%q err=%v", id, body, err)
					}
				}(i)
			}
			wg.Wait()
			if n := connections.Load(); n != 1 {
				t.Fatalf("SSE requests opened %d connections, want 1", n)
			}
		})
	}
}
