# 独立客户端：NewClient

`cycletls.NewClient(opts)` 创建独立客户端，不使用全局 Client 池。

```go
cli, err := cycletls.NewClient(cycletls.Options{
    Ja3:                 "RAND",
    SignatureAlgorithms: "RAND",
    Timeout:             15,
    MaxResponseBodySize:  -1,
    UserAgent:           "my-client",
})
if err != nil {
    return err
}
defer cli.Close()

resp, err := cli.Do("https://example.com/api", "GET")
if err != nil {
    return err
}
fmt.Println(resp.Status, resp.Body)
```

也可使用 `cli.DoContext(ctx, url, method)` 为单次请求设置取消或截止时间。
同一个实例支持多个 goroutine 并发调用。

## 连接复用

- 同一实例、同一域名与端口，HTTP/2 连接可接收请求时复用同一条连接。
- 服务端并发流名额用完后排队等待，不因为流数达到上限而另开连接。
- 服务端 GOAWAY、主动断开或网络失败后，需要重连；旧连接上的已有流可能仍在结束。
- 不同实例独立拥有连接，`Close()` 不影响其他实例或 `Init()` 的全局池。
- 全局池清理也不会关闭该实例的连接。
- 构造时解析一次 `RAND`，同一实例后续连接沿用该配置。
- `EnableConnectionReuse`、`MaxTotalRequests`、`MaxIdleClients`、`Meta`
  不控制该接口；它始终复用，不按请求次数轮换。需要全局池及次数轮换时继续使用 `Init()`。
- HTTP/2 保证要求服务端实际协商 HTTP/2；HTTP/1.1 回退可能建立多条并发连接。
- 显式的 `Connection: close` 默认请求头会在构造时被拒绝。

## 配置与返回值

构造参数是实例的固定默认配置，包括 Headers、Cookies、Body/BodyBytes、HeaderOrder、
代理、IP、LocalIP、指纹、超时和响应体大小限制。map、slice 等会复制，后续修改传入参数
不会改变实例。当前接口每次调用只接收 URL、方法和可选的 context。

返回值沿用 `CycleTLS.Do` 的 `Response`，包括指纹、IP、响应头和正文。普通网络错误仍
沿用原有的 `Response.Status/Body` 表达方式；不要仅检查 Go `error`。调用方 context 取消
或超时会返回相应 context 错误；关闭后再请求返回 `net.ErrClosed`。

`MaxResponseBodySize` 沿用原接口：负数读取完整正文，正数限制读取大小，零不读取正文。
响应体始终在方法返回前关闭，调用方不需要额外关闭 Body。

## 资源回收

必须调用 `Close()`，推荐构造成功后立即 `defer cli.Close()`。GC 不会代替显式关闭持久连接。

`Close()` 可并发和重复调用：先禁止新请求并取消本实例的在途请求，等待请求结束及响应体
关闭，然后关闭 Transport、连接及代理资源。它是永久关闭，不支持重新启用。

`TLSHandshakeDone` 是同步回调，必须及时返回。不要在该回调内同步调用本实例的 `Close()`，
否则会等待包含自身回调的请求；需要从回调触发关闭时使用 `go cli.Close()`。

## 回归验证

`scoped_client_test.go` 覆盖：

- 128 并发、1,024 次 HTTP/2 请求，服务端并发流上限为 8，仍只有一条连接；即使传入
  `MaxTotalRequests=2` 或 `EnableConnectionReuse=false` 也不轮换。
- 两个独立实例与全局池之间的连接及关闭隔离。
- 响应头、正文、流名额等待和 TLS 握手期间关闭；多个 goroutine 同时 Close。
- 单次 deadline 不影响其他请求；连接失败后正常重建。
- 参数快照、反复创建/关闭 32 次、连接与 goroutine 回收。

```powershell
go test -race . -run '^TestScopedClient' -count=5 -timeout=90s
```
