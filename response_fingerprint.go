package cycletls

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	http "github.com/Danny-Dasilva/fhttp"
	"github.com/Danny-Dasilva/fhttp/httptrace"
	utls "github.com/refraction-networking/utls"
)

type tlsFingerprint struct {
	ja3                 string
	signatureAlgorithms string
}

type tlsFingerprintKey struct{}

// Capture the connection selected for this request, including retries and reuse.
// A transport-wide "last fingerprint" would mix concurrent requests/origins.
func roundTripWithFingerprint(transport http.RoundTripper, req *http.Request) (*http.Response, error) {
	var mu sync.Mutex
	var fingerprint tlsFingerprint
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			var f tlsFingerprint
			if conn, ok := info.Conn.(*utls.UConn); ok && conn.HandshakeState.Hello != nil {
				f = fingerprintFromClientHello(conn.HandshakeState.Hello.Raw)
			}
			mu.Lock()
			fingerprint = f
			mu.Unlock()
		},
	})
	req = req.WithContext(ctx)
	resp, err := transport.RoundTrip(req)
	if resp != nil {
		mu.Lock()
		f := fingerprint
		mu.Unlock()
		if resp.Request == nil {
			resp.Request = req
		}
		resp.Request = resp.Request.WithContext(context.WithValue(resp.Request.Context(), tlsFingerprintKey{}, f))
	}
	return resp, err
}

func responseTLSFingerprint(resp *http.Response) tlsFingerprint {
	if resp == nil || resp.Request == nil {
		return tlsFingerprint{}
	}
	f, _ := resp.Request.Context().Value(tlsFingerprintKey{}).(tlsFingerprint)
	return f
}

// JA3 is the ClientHello's legacy version and ordered wire lists, excluding
// GREASE. Read the serialized hello so omitted SNI, padding, PSK, and TLS retry
// adjustments are reflected rather than merely echoing the input options.
func fingerprintFromClientHello(raw []byte) tlsFingerprint {
	hello := utls.UnmarshalClientHello(raw)
	if hello == nil {
		return tlsFingerprint{}
	}
	var ciphers, extensions, groups, points, signatures []string
	decimal := func(v uint16) string { return strconv.Itoa(int(v)) }
	isGrease := func(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) }
	for _, v := range hello.CipherSuites {
		if !isGrease(v) {
			ciphers = append(ciphers, decimal(v))
		}
	}
	// Skip the handshake header, legacy version, random, session ID, ciphers,
	// and compression methods. UnmarshalClientHello has validated their lengths.
	offset := 4 + 2 + 32 + 1 + len(hello.SessionId) + 2 + 2*len(hello.CipherSuites) + 1 + len(hello.CompressionMethods)
	if offset+2 <= len(raw) {
		data := raw[offset+2:]
		for len(data) >= 4 {
			id := binary.BigEndian.Uint16(data[:2])
			size := int(binary.BigEndian.Uint16(data[2:4]))
			if size > len(data)-4 {
				return tlsFingerprint{}
			}
			if !isGrease(id) {
				extensions = append(extensions, decimal(id))
			}
			data = data[4+size:]
		}
	}
	for _, v := range hello.SupportedCurves {
		if !isGrease(uint16(v)) {
			groups = append(groups, decimal(uint16(v)))
		}
	}
	for _, v := range hello.SupportedPoints {
		points = append(points, decimal(uint16(v)))
	}
	for _, v := range hello.SupportedSignatureAlgorithms {
		signatures = append(signatures, fmt.Sprintf("%04x", uint16(v)))
	}
	return tlsFingerprint{
		ja3:                 fmt.Sprintf("%d,%s,%s,%s,%s", hello.Vers, strings.Join(ciphers, "-"), strings.Join(extensions, "-"), strings.Join(groups, "-"), strings.Join(points, "-")),
		signatureAlgorithms: strings.Join(signatures, ","),
	}
}
