package cycletls

import "testing"

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

func TestCreateNewClientIgnoresRequestIPWhenProxyIsSet(t *testing.T) {
	client, err := createNewClient(Browser{}, 15, false, "", "http://127.0.0.1:8080", "not-an-ip")
	if err != nil {
		t.Fatalf("createNewClient returned error: %v", err)
	}

	transport, ok := client.Transport.(*roundTripper)
	if !ok {
		t.Fatalf("transport type = %T, want *roundTripper", client.Transport)
	}
	if transport.RequestIP != "" {
		t.Fatalf("RequestIP = %q, want empty when proxy is set", transport.RequestIP)
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
