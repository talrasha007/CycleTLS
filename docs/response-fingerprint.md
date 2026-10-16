# Returning and replaying TLS fingerprints

`CycleTLS.Do` returns `Response.Ja3` and `Response.SignatureAlgorithms` (JSON
`ja3` and `signatureAlgorithms`). These describe the actual ClientHello of the
TCP TLS connection used for the response, including randomization, extension
ordering, and any successful TLS retry or fallback. Reused connections report
their original handshake fingerprint. Concurrent requests retain their own
connection's values.

`Ja3` is the full comma-separated JA3 string, not its MD5 hash. It excludes
GREASE values, as standard JA3 does. `SignatureAlgorithms` contains the ordered,
comma-separated hexadecimal IDs from the `signature_algorithms` extension.
Omitted wire extensions, including optional padding, are omitted from the JA3.

```go
opts := cycletls.Options{
    Ja3: "RAND",
    SignatureAlgorithms: "RAND",
    ShuffleExtensions: true,
    EnableConnectionReuse: true,
    MaxResponseBodySize: -1,
}
resp, err := client.Do(url, opts, "GET")
if err != nil {
    return err
}
if resp.Ja3 == "" {
    return fmt.Errorf("no TCP TLS fingerprint available: status %d", resp.Status)
}

opts.Ja3 = resp.Ja3
opts.SignatureAlgorithms = resp.SignatureAlgorithms
opts.ShuffleExtensions = false
opts.TLS13AutoRetry = false // avoid rewriting the returned explicit JA3
next, err := client.Do(url, opts, "GET")
```

Keep the other TLS options and destination hostname consistent when replaying:
JA3 and signature algorithms alone do not describe every TLS handshake setting.
They do not contain GREASE values, session tickets, PSK material, or HelloRetryRequest
cookies; session resumption and retry cookies still depend on session/server state.
An explicit returned fingerprint has its own client-pool key; it does not select
the pool entry originally configured with `RAND`.

Plain HTTP and HTTP/3 (which uses a separate QUIC TLS implementation) leave these
fields empty. Request failures without a TLS response and existing error paths
that return an empty `Response`, such as response-body read errors, also leave
them empty. If TLS omits the signature
algorithms extension, `SignatureAlgorithms` is empty. These fields belong to the
Go `Response` and its JSON representation; the asynchronous binary streaming
protocol is unchanged.
