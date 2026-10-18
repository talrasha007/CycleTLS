package cycletls

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"

	http "github.com/Danny-Dasilva/fhttp"
)

// Pool by the source policy, never by the address sampled for a connection.
func normalizeLocalIP(value string, http3 bool) (string, error) {
	if value == "" || http3 {
		return "", nil
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.Unmap().String(), nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is6() && !prefix.Addr().Is4In6() {
		return prefix.Masked().String(), nil
	}
	return "", fmt.Errorf("invalid local IP %q: expected an IP address or IPv6 CIDR", value)
}

type localIPDialer struct{ source string }

func (d *localIPDialer) localAddr() (*net.TCPAddr, error) {
	if prefix, err := netip.ParsePrefix(d.source); err == nil {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		addr := prefix.Masked().Addr().As16()
		for bit := prefix.Bits(); bit < 128; bit++ {
			addr[bit/8] |= random[bit/8] & (1 << (7 - uint(bit%8)))
		}
		return &net.TCPAddr{IP: net.IP(addr[:])}, nil
	}
	ip, err := netip.ParseAddr(d.source)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: net.IP(ip.AsSlice()), Zone: ip.Zone()}, nil
}

func (d *localIPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	local, err := d.localAddr()
	if err != nil {
		return nil, err
	}
	return (&net.Dialer{LocalAddr: local}).DialContext(ctx, network, addr)
}

func (d *localIPDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

type localIPKey struct{}

func responseLocalIP(resp *http.Response) string {
	if resp == nil || resp.Request == nil {
		return ""
	}
	ip, _ := resp.Request.Context().Value(localIPKey{}).(string)
	return ip
}
