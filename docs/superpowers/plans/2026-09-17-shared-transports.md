# Shared HTTP/2 and HTTP/3 transports

## Scope and design

Implement the user's requested shared transports and high-concurrency verification.
Keep public request options and protocol fingerprints, while replacing exclusive
client checkout with a shared generation owned by the configuration registry.

- Acquiring a compatible client increments its active request count. Completion
  releases that count, including request creation errors, cancellation, and SSE.
- Maximum request counts rotate generations. Cleanup retires a generation and
  closes it only after its active requests have completed.
- Keys include actual fingerprint, proxy/IP, TLS and client policy. UserAgent,
  Cookies and HeaderOrder are request-local and excluded per the user's follow-up.
  Metadata cannot override connection compatibility.
- HTTP/3 transport instances retain their QUIC transport across requests.
  Response close releases the stream, while explicit transport close disposes
  shared connection/socket resources. Remove the unused preliminary QUIC dial.
- Transport settings are fixed on first use; mutable slices/configs are copied
  when the shared transport is created.

## Work and verification

1. Add failing registry tests: 128 concurrent HTTP/2 callers, 2,048 distinct
   responses, one compatible TCP connection; incompatible configuration keys.
2. Implement registry leases and update synchronous, asynchronous and SSE owners.
   Verify disabled reuse, generation rollover, pool cleanup during active work,
   and configuration isolation.
3. Implement persistent HTTP/3 instances with local real QUIC tests, cancellation
   isolation, active response protection and deterministic close.
4. Stress HTTP/2 stream limits and concurrent cancellation using a local server.
   Add wrapper changes only where tests show a race or excessive connections.
5. Run local tests under the race detector, bounded repeated concurrency cases,
   and benchmarks. Record actual request/concurrency/connection counts; do not
   infer production throughput from loopback measurements.

Commands:

```powershell
go test -race . ./tests/unit -count=1 -timeout=120s
go vet ./...
go test ./... -run '^$'
go test . -run '^$' -bench 'SharedHTTP' -benchmem -benchtime=2s
```

No dependency on external integration-test endpoints is required.
