# Selecting a local source IP

`Options.LocalIP` (JSON `localIp`) binds outgoing HTTP/1 and HTTP/2 TCP
connections to a fixed IPv4 or IPv6 address, or a random address from an IPv6
CIDR. The existing `Options.IP` still selects the remote destination address.

```go
resp, err := client.Do("https://example.com", cycletls.Options{
    LocalIP: "2001:db8:1234::/64", // or a fixed local IPv4/IPv6 address
    EnableConnectionReuse: true,
    Timeout: 15,
    MaxResponseBodySize: -1,
}, "GET")
if err != nil {
    return err
}
fmt.Println(resp.LocalIP) // JSON: localIp; actual local IP, without the port
```

The example prefix is for documentation; replace it with your own subnet.
The machine's network configuration must permit binding and routing the selected
source address. Supplying a CIDR does not assign addresses to network interfaces
or enable binding to unassigned addresses. Binding failures use the existing
request error handling; there is no fallback to an arbitrary source IP. Invalid
source values return a client construction error. IPv4 CIDRs are rejected.

CIDRs are masked to their network prefix before pooling. For example,
`2001:db8::1234/64` and `2001:db8::/64` share the same source policy. The client
pool key includes this policy along with the existing connection settings, never
the randomly selected address. Different source policies use separate clients.
Each new TCP connection samples the host bits using cryptographic randomness;
reusing a connection keeps its original address. A `/128` always selects its
single address. Disable connection reuse to request a new connection each time.

`CycleTLS.Do` returns the local IP of the connection actually used for the final
response, including reused connections and redirects. Concurrent requests retain
their own connection's address. This is also populated when `LocalIP` is unset.
Requests without a successful TCP response leave the field empty.

With HTTP, HTTPS, SOCKS4, or SOCKS5 proxies, the source policy binds the TCP
connection to the proxy, and the response reports that connection's local IP.
An IPv6 source therefore requires an IPv6-reachable proxy, even if the target is
IPv4. HTTP/3 ignores `LocalIP` entirely, including validation and pooling, and
returns an empty `Response.LocalIP`.

The response field belongs to the Go `Response` and its JSON representation.
The asynchronous binary streaming protocol and separate WebSocket API are
unchanged.
