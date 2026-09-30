package netpolicy

import (
	"errors"
	"net"
	"testing"
)

func TestClassifyIP(t *testing.T) {
	cases := []struct {
		ip   string
		want NetworkClass
	}{
		{"8.8.8.8", ClassPublic},
		{"2606:4700::1111", ClassPublic},
		{"127.0.0.1", ClassLoopback},
		{"127.8.8.8", ClassLoopback},
		{"::1", ClassLoopback},
		{"10.0.0.1", ClassPrivate},
		{"172.16.5.5", ClassPrivate},
		{"192.168.1.1", ClassPrivate},
		{"100.64.0.1", ClassPrivate}, // CGNAT
		{"fd12::1", ClassPrivate},    // ULA
		{"169.254.169.254", ClassForbidden},
		{"169.254.0.1", ClassForbidden},
		{"fe80::1", ClassForbidden},
		{"0.0.0.0", ClassForbidden},
		{"0.1.2.3", ClassForbidden},
		{"::", ClassForbidden},
		{"224.0.0.1", ClassForbidden},
		{"ff02::1", ClassForbidden},
		{"::ffff:169.254.169.254", ClassForbidden}, // IPv4-mapped metadata
		{"::ffff:10.0.0.1", ClassPrivate},          // IPv4-mapped private
		{"::ffff:127.0.0.1", ClassLoopback},
		{"::127.0.0.1", ClassForbidden},        // IPv4-compatible (deprecated) refused outright
		{"::169.254.169.254", ClassForbidden},  //
		{"64:ff9b::a9fe:a9fe", ClassForbidden}, // NAT64-wrapped metadata
		{"64:ff9b::a00:1", ClassPrivate},       // NAT64-wrapped 10.0.0.1
		{"64:ff9b::808:808", ClassPublic},      // NAT64-wrapped 8.8.8.8
		{"2002:0a00:0001::", ClassPrivate},     // 6to4-wrapped 10.0.0.1
		{"2002:a9fe:a9fe::", ClassForbidden},   // 6to4-wrapped metadata
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) failed", tc.ip)
			}
			if got := ClassifyIP(ip); got != tc.want {
				t.Fatalf("ClassifyIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
	if got := ClassifyIP(nil); got != ClassForbidden {
		t.Fatalf("ClassifyIP(nil) = %v, want forbidden", got)
	}
}

func TestDialPolicyAllows(t *testing.T) {
	cases := []struct {
		name   string
		policy DialPolicy
		class  NetworkClass
		want   bool
	}{
		{"zero/public", DialPolicy{}, ClassPublic, true},
		{"zero/loopback", DialPolicy{}, ClassLoopback, false},
		{"zero/private", DialPolicy{}, ClassPrivate, false},
		{"zero/forbidden", DialPolicy{}, ClassForbidden, false},
		{"loopback/loopback", DialPolicy{AllowLoopback: true}, ClassLoopback, true},
		{"loopback/private", DialPolicy{AllowLoopback: true}, ClassPrivate, false},
		{"private/private", DialPolicy{AllowPrivate: true}, ClassPrivate, true},
		{"all/forbidden", DialPolicy{AllowLoopback: true, AllowPrivate: true}, ClassForbidden, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.policy.Allows(tc.class); got != tc.want {
				t.Fatalf("Allows(%v) = %t, want %t", tc.class, got, tc.want)
			}
		})
	}
}

func TestCheckDialAddress(t *testing.T) {
	cases := []struct {
		name    string
		policy  DialPolicy
		address string
		wantErr bool
	}{
		{"public ok", DialPolicy{}, "8.8.8.8:443", false},
		{"metadata refused", DialPolicy{AllowLoopback: true, AllowPrivate: true}, "169.254.169.254:80", true},
		{"private refused by default", DialPolicy{}, "10.1.2.3:8080", true},
		{"private unlocked", DialPolicy{AllowPrivate: true}, "10.1.2.3:8080", false},
		{"loopback refused by default", DialPolicy{}, "127.0.0.1:8820", true},
		{"loopback unlocked", DialPolicy{AllowLoopback: true}, "[::1]:8820", false},
		{"ipv4-mapped metadata refused", DialPolicy{AllowPrivate: true}, "[::ffff:169.254.169.254]:80", true},
		{"hostname is not a literal", DialPolicy{}, "example.com:443", true},
		{"unparseable", DialPolicy{}, "no-port", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.CheckDialAddress(tc.address)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckDialAddress(%q) err = %v, wantErr %t", tc.address, err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrDialRefused) {
				t.Fatalf("refusal does not wrap ErrDialRefused: %v", err)
			}
		})
	}
}

func TestControlHook(t *testing.T) {
	hook := DialPolicy{}.Control()
	if err := hook("udp", "8.8.8.8:53", nil); err == nil || !errors.Is(err, ErrDialRefused) {
		t.Fatalf("udp accepted: %v", err)
	}
	if err := hook("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("tcp public refused: %v", err)
	}
	if err := hook("tcp4", "169.254.169.254:80", nil); err == nil {
		t.Fatal("metadata accepted through the hook")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"localhost": true, "LOCALHOST": true, " localhost ": true, "127.0.0.1": true, "::1": true, //nolint:gocritic // the padded key is the case under test: IsLoopbackHost trims
		"127.0.0.1.evil.example": false, "example.com": false, "10.0.0.1": false, "": false,
	}
	for host, want := range cases {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %t, want %t", host, got, want)
		}
	}
}
