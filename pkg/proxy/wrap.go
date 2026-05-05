// SPDX-License-Identifier: MIT

package proxy

// Optional WRAP layer for the DTLS-over-TURN data path.
//
// Background: VK's TURN relays run a payload classifier that detects
// DTLS+WireGuard traffic patterns inside ChannelData and tags the
// destination (peer_ip, peer_port) endpoint, after which all traffic
// to that endpoint is throttled to ~9 KB/s per allocation. Tagging
// is triggered within minutes of the first real DTLS+WG client
// connecting; a fresh endpoint stays clean only as long as
// recognisable DTLS bytes never reach it.
//
// This file adds a thin obfuscation layer between the wire (TURN
// ChannelData payload) and the DTLS layer. Each UDP datagram on
// the wire becomes:
//
//   [12-byte random nonce] [ChaCha20-XOR(key, nonce, dtls_record_bytes)]
//
// The classifier sees pseudo-random bytes for the entire payload —
// no DTLS magic byte (0x14-0x17) at any fixed offset, no recognisable
// handshake structure. ChaCha20 with no auth tag (XOR-stream only) —
// integrity is provided by the DTLS layer underneath, we only need
// confidentiality / unrecognisability here. ~1% bandwidth overhead.
//
// Activated by Config.UseWrap. Server side must run with the matching
// -wrap and -wrap-key flags from the upstream cacggghp/vk-turn-proxy
// PR. Without -wrap on the server, plain DTLS bytes would be XOR'd by
// the server-side wrap layer and produce garbage from the DTLS state
// machine's perspective; the handshake fails. So the typical deployment
// is to bind a fresh port on the server for the WRAP-enabled listener
// and leave the existing port serving legacy clients.

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
)

const (
	// wrapNonceLen is the per-packet nonce length in bytes. ChaCha20
	// requires 12 bytes. Prepended to every wire packet.
	wrapNonceLen = 12

	// wrapKeyLen is the ChaCha20 key length in bytes (256-bit).
	wrapKeyLen = 32
)

// wrapPacket builds the wire bytes for one packet:
//
//	[12-byte random nonce] [ChaCha20-XOR(key, nonce, payload)]
//
// Returns a freshly-allocated slice; caller is free to retain it.
// `payload` is consumed by-value (bytes are read but the underlying
// array is not modified).
func wrapPacket(key, payload []byte) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	out := make([]byte, wrapNonceLen+len(payload))
	if _, err := rand.Read(out[:wrapNonceLen]); err != nil {
		return nil, fmt.Errorf("wrap: nonce gen: %w", err)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, out[:wrapNonceLen])
	if err != nil {
		return nil, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(out[wrapNonceLen:], payload)
	return out, nil
}

// unwrapPacket parses wire bytes laid out by wrapPacket and writes the
// recovered plaintext into `dst`. Returns the plaintext length (which
// equals len(wire) - wrapNonceLen on success). Errors on short packets
// (no nonce) or undersized dst buffer.
func unwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(wire) < wrapNonceLen {
		return 0, errors.New("wrap: short packet (no nonce)")
	}
	nonce := wire[:wrapNonceLen]
	ciphertext := wire[wrapNonceLen:]
	if len(ciphertext) > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return 0, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(dst[:len(ciphertext)], ciphertext)
	return len(ciphertext), nil
}
