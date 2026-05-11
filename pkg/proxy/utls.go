package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// vkHostIPs is a host→IP map populated by the main app right before
// startVPNTunnel. It lets the extension dial VK API endpoints without
// depending on a working DNS resolver during the bootstrap window.
//
// What actually fails / works in the extension (verified empirically
// 2026-05-11 via dns-probe in build 86 for `privacy-cs.mail.ru`):
//
//   - **Pre-bootstrap window** (extension started, setTunnelNetworkSettings
//     NOT yet called — i.e., before TUN exists with the dns=1.1.1.1
//     config). All resolver paths fail: cgo getaddrinfo returns "no
//     such host" because iOS hasn't wired up the per-process resolver
//     context for the extension yet; pure-Go resolver hits [::1]:53
//     "connection refused" (no /etc/resolv.conf); SCDynamicStore is
//     explicitly unavailable on iOS. This is the window where we MUST
//     use pre-resolved IPs — and it's exactly when our deferred-
//     setTunnelNetworkSettings architecture is doing VK API calls for
//     bootstrap, so pre-resolution is structurally required.
//
//   - **Post-bootstrap window** (TUN up with dns=1.1.1.1 configured).
//     cgo getaddrinfo WORKS — resolves via mDNSResponder XPC which uses
//     the tunnel DNS server, packets to 1.1.1.1 route through TUN → WG →
//     server → 1.1.1.1 and back. The pure-Go resolver still fails (still
//     no /etc/resolv.conf). So `net.DefaultResolver.LookupHost` and
//     `net.Dialer.Dial` work for arbitrary hosts in this window.
//
// Why `vk_host_ips` is still useful even post-bootstrap:
//
//   - Latency: tunnel-routed DNS adds ~50-200ms vs direct in-process
//     lookup. For hot-path hosts (api.vk.ru hit per cred-fetch) that
//     matters; for one-off pings (privacy-cs.mail.ru) it doesn't.
//
//   - Resilience: if tunnel is broken mid-session, pre-resolved IPs
//     are the ONLY DNS we have. The main-app pre-resolves before
//     handing config to extension, so the IPs survive tunnel outages.
//
//   - Whitelist networks: the deployment target is networks that allow
//     VK + a few other resources but block public DNS. In pre-bootstrap
//     we have no way to reach 1.1.1.1 directly; only after the tunnel
//     is up does the DNS query travel encapsulated through WG, exempt
//     from the whitelist's blocking.
//
// The main-app process, in contrast, has a fully-populated network
// context the whole time — its standard CFHost / getaddrinfo resolves
// through whichever DNS the system is currently using (DHCP / carrier),
// which is by definition reachable in the user's environment. So we
// let it resolve VK hosts there, pass the IPs through providerConfig,
// and the extension dials by IP for the bootstrap-critical hosts while
// keeping the original hostname in TLS SNI / Host headers.
var (
	vkHostIPsMu sync.RWMutex
	vkHostIPs   = make(map[string][]string) // host (no port) → list of IPs (all A-records)
)

// SetVKHostIPs replaces the host→[]IP map. Called from bridge.go's
// wgStartVKBootstrap when proxyConfig is unmarshalled.
func SetVKHostIPs(m map[string][]string) {
	vkHostIPsMu.Lock()
	defer vkHostIPsMu.Unlock()
	vkHostIPs = make(map[string][]string, len(m))
	for h, ips := range m {
		cp := make([]string, len(ips))
		copy(cp, ips)
		vkHostIPs[h] = cp
	}
}

// resolvedVKHostIPs returns the pre-resolved IPs for host, or nil if the
// host wasn't pre-resolved by the main app.
func resolvedVKHostIPs(host string) []string {
	vkHostIPsMu.RLock()
	defer vkHostIPsMu.RUnlock()
	return vkHostIPs[host]
}

// chromeRoundTripper routes requests through HTTP/2 or HTTP/1.1 based
// on what the server negotiates via ALPN. Uses uTLS to mimic Chrome's
// TLS fingerprint for both protocols.
type chromeRoundTripper struct {
	h2 *http2.Transport // HTTP/2 transport (Chrome ALPN: h2, http/1.1)
	h1 *http.Transport  // HTTP/1.1 fallback (Chrome ALPN forced to http/1.1)
}

// newChromeTransport creates an http.RoundTripper that uses uTLS to mimic
// Chrome's TLS fingerprint and supports HTTP/2.
//
// How it works:
//  1. Tries HTTP/2 first — dials with Chrome ALPN (h2, http/1.1),
//     verifies h2 was negotiated, uses http2.Transport for framing.
//  2. Falls back to HTTP/1.1 — if h2 negotiation fails (server doesn't
//     support h2), re-dials with ALPN forced to http/1.1 only,
//     uses standard http.Transport.
//
// This gives us:
//   - Chrome JA3 fingerprint (cipher suites, extensions, key shares)
//   - Proper h2 protocol when server supports it (VK does)
//   - Automatic fallback for h1-only servers
func newChromeTransport() http.RoundTripper {
	rt := &chromeRoundTripper{}

	rt.h2 = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, err := dialChromeTLS(ctx, network, addr, false)
			if err != nil {
				return nil, err
			}
			proto := conn.ConnectionState().NegotiatedProtocol
			if proto != "h2" {
				_ = conn.Close()
				return nil, fmt.Errorf("utls: server %s negotiated %q, not h2", addr, proto)
			}
			return conn, nil
		},
	}

	rt.h1 = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialChromeTLS(ctx, network, addr, true)
			if err != nil {
				return nil, err
			}
			return conn, nil
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConnsPerHost: 5,
	}

	return rt
}

func (rt *chromeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.h2.RoundTrip(req)
	if err == nil {
		return resp, nil
	}
	// h2 failed — fall back to h1 (re-dials with http/1.1-only ALPN)
	log.Printf("utls: h2 failed for %s: %v — falling back to h1", req.URL.Host, err)
	return rt.h1.RoundTrip(req)
}

// dialChromeTLS establishes a TLS connection using uTLS with Chrome's
// ClientHello fingerprint.
//
// If forceH1 is true, ALPN is overridden to only advertise http/1.1
// (for use with Go's http.Transport which can't handle h2 frames).
// If forceH1 is false, ALPN keeps Chrome's default: ["h2", "http/1.1"].
func dialChromeTLS(ctx context.Context, network, addr string, forceH1 bool) (*utls.UConn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host:port %q: %w", addr, err)
	}

	// Build the list of dial addresses. If the main app pre-resolved
	// this host, walk all A-records in order — first reachable IP wins.
	// Otherwise just dial the original addr (lets system DNS try; will
	// usually fail in the extension, but this is consistent fallback
	// behavior rather than a hidden silent path).
	var dialAddrs []string
	if ips := resolvedVKHostIPs(host); len(ips) > 0 {
		for _, ip := range ips {
			dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
		}
	} else {
		dialAddrs = []string{addr}
	}

	dialer := &net.Dialer{
		// Per-IP connect timeout — short enough that walking 4-5 IPs
		// stays well under the outer request budget.
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var rawConn net.Conn
	var lastErr error
	for _, da := range dialAddrs {
		rawConn, err = dialer.DialContext(ctx, network, da)
		if err == nil {
			break
		}
		log.Printf("utls: dial %s (%s) failed: %v — trying next IP", da, host, err)
		lastErr = err
		rawConn = nil
	}
	if rawConn == nil {
		return nil, fmt.Errorf("dial %s: all %d IPs failed, last error: %w", host, len(dialAddrs), lastErr)
	}

	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("get Chrome spec: %w", err)
	}

	if forceH1 {
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = []string{"http/1.1"}
				spec.Extensions[i] = alpn
				break
			}
		}
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{
		ServerName: host,
	}, utls.HelloCustom)

	if err := tlsConn.ApplyPreset(&spec); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("apply Chrome spec: %w", err)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake with %s: %w", host, err)
	}

	return tlsConn, nil
}
