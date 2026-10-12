# Observing successful TCP TLS handshakes

`Options.TLSHandshakeDone` is an optional Go-only callback on synchronous `CycleTLS.Do` requests. It runs immediately after `HandshakeContext` succeeds, before HTTP negotiation and HTTP requests, including the TLS 1.3 compatible and original TLS 1.2 fallback paths. It is not serialized to JSON.

```go
var handshake atomic.Bool
response, err := client.Do("https://impressions.onelink.me/8Dt1", cycletls.Options{
    IP: "203.0.113.10", // replace with the candidate IP
    Ja3: "RAND",
    SignatureAlgorithms: "RAND",
    Timeout: 10,
    DisableRedirect: true,
    EnableConnectionReuse: false,
    TLSHandshakeDone: func() { handshake.Store(true) },
}, "GET")
// handshake.Load() may be true even if HTTP subsequently fails.
// A transport failure may be represented by a synthetic response with nil
// Headers and nil err; do not infer TLS success from err alone.
_ = response
_ = err
```

The callback is carried in the request context rather than shared client or pool configuration, so reconnecting a pooled client notifies the request that initiated the handshake. Reusing an already negotiated connection performs no handshake and sends no notification. Use `EnableConnectionReuse: false` for one handshake per candidate. Callbacks may run concurrently on separate requests and must return promptly. This observer does not report QUIC handshakes, JSON/async requests, or unsuccessful handshakes. Certificate verification behavior remains controlled by `InsecureSkipVerify`.

The `IP` option retains its existing semantics: it overrides the dial target only for direct connections; with `Proxy` set it is ignored. SNI and HTTP authority continue to use the URL hostname. This change does not add proxy target-IP support.
