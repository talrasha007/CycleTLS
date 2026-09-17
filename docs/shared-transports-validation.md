# Shared transport validation

Validated on 2026-09-17 with Go 1.26.2, Windows/amd64, Intel Core i7-12700KF.
All network tests use local TLS/HTTP2 or real QUIC/HTTP3 servers.

## Behavior

- Set `Options.EnableConnectionReuse = true` to share compatible clients across
  concurrent synchronous, asynchronous and SSE requests. Disabled reuse still
  creates and closes a dedicated transport for each acquisition.
- Keys include fingerprint, TLS policy, proxy, request IP and client policy.
  UserAgent, Cookies and HeaderOrder are excluded and applied from an immutable
  per-request context in synchronous, asynchronous and SSE paths. `Meta` is an
  additional namespace, not a compatibility override.
- Pool keys use the original fingerprint options: `Ja3="RAND"` and
  `SignatureAlgorithms="RAND"` remain literal policies in the key. Random values
  and extension shuffling are resolved once when a new transport generation is
  created, including when reuse is disabled. Reuse keeps that generation's
  fingerprint; reaching `MaxTotalRequests` creates a new generation and resolves
  the policies again. `ShuffleExtensions` itself participates in the key.
- A reused connection retains its negotiated fingerprint. User-Agent can affect
  default handshake construction on initial connection creation; changing its
  request header does not renegotiate TLS. Use explicit fingerprint settings or
  distinct Meta values when separate connection fingerprints are required.
- Each acquisition holds a reference until its response closes. Clearing or
  rotating the pool retires the generation; its active responses finish before
  the transport closes. Individual failures do not dispose other requests' sockets.
- `MaxTotalRequests` counts acquisitions per generation, including failures;
  zero is unlimited. `MaxIdleClients` remains accepted for compatibility, but
  the registry now retains one current shared client per compatible configuration.
- HTTP2 waits for server stream capacity on the shared connection. HTTP3 retains
  its transport and releases individual streams on body completion/close.
- Configure standalone transports before their first request. Close standalone
  transports explicitly after use; close response bodies as usual.

## Concurrency and lifecycle coverage

| Scenario | Load and assertions |
| --- | --- |
| Public HTTP2 client | 128 workers, 2,048 distinct responses, exactly one TCP connection; former exclusive checkout opened 128 in the same regression |
| HTTP2 stream limits | 1,024 requests per case, 128/256 workers, server limits 1/8/256; one connection, payload integrity, each GET/POST handled exactly once |
| HTTP3 implementations | Four transport variants, each 128 overlapping streams and 1,024 distinct responses; one QUIC connection per variant |
| Public HTTP3 client | 128 workers, 1,024 requests; one connection, logical Host/SNI and actual resolved IP preserved |
| Registry retirement | 128 workers, 1,024 requests while clearing the pool; separately a 31-acquisition limit produces exactly 34 generations |
| Async ownership | 128 requests per protocol, half canceled; no remaining registry references or active-request registrations |

Additional regressions cover partial bodies, idle cleanup during live responses,
queued cancellation, GOAWAY, full close during setup/streaming, cold-dial owner
cancellation, cancellation across different origins, malformed requests and early
request-body cleanup. Real HTTP2 CONNECT tests cover setup cancellation, initial
tunnels, reconnection and preservation of peer streams after owner cancellation.
Same-IP origins retain separate SNI, including internationalized domain names.
Request-setting regressions additionally cover 64 concurrent distinct user agents
and cookies sharing one HTTP2 connection, empty values after populated requests,
HTTP2/HTTP3 asynchronous isolation, both SSE entry points, and alternating HTTP1
header order observed directly on the wire.

Final combined verification passed:

```powershell
go test -race . ./tests/unit -count=3 -timeout=120s
go vet ./...
go test ./... -run '^$'
git diff --check
```

The combined race run completed in 12.919 seconds for the root package. The full
HTTP3 test set also passed 30 consecutive race-enabled repetitions (21.413 seconds),
including over 153,600 requests in the main concurrency cases. External-site
integration tests were compiled, not executed.

## Local benchmarks

```powershell
go test . -run '^$' -bench 'BenchmarkCycleTLSSharedHTTP2|BenchmarkHTTP3SharedTransport' -benchmem -benchtime=2s -count=3 -cpu=8
```

Median of three runs:

| Benchmark | ns/op | B/op | allocations/op |
| --- | ---: | ---: | ---: |
| CycleTLS HTTP2, reuse disabled | 279,322 | 128,683 | 1,204 |
| CycleTLS HTTP2, shared reuse enabled | 43,336 | 17,205 | 125 |
| Standalone shared HTTP3 | 19,459 | 14,903 | 209 |

HTTP2 shared reuse took about 1/6.4 of the time and allocated about 87% fewer
bytes than disabled reuse. HTTP3 retained exactly one QUIC connection in each
benchmark run. These are loopback measurements, not production throughput or a
benchmark comparison against the old exclusive pool.

HTTP3 proxy support remains unavailable and is rejected instead of silently
bypassing the proxy. Native UQuic fingerprint application remains the existing
standard HTTP3 fallback; this change does not add that capability.
