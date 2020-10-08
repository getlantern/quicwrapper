package quicwrapper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// this is a version negotiation packet header
var verHeader = []byte{
	// long header flag on
	0x80,
	// version is set to uint32(0) to identify
	// a negotiation packet.
	0x00, 0x00, 0x00, 0x00,
	// no source or destination connection ids
	// are given.
	0x00, 0x00,
}

// IsQUICUp tests if there is an IETF-QUIC-like-server running on at an address.
//
// an error is returned if a quic-like server cannot be reached at the
// address provided. Otherwise, nil is returned.
//
// The test is accomplished by sending a quic-like version negotiation packet
// and checking for a quic-like-packet in response. Does not check compatibility,
// just that a quic-like packet is elicited.
func ScanQUIC(ctx context.Context, addr string) error {
	conn, rAddr, err := DialUDPNetx(addr)
	if err != nil {
		return err
	}

	if t, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(t); err != nil {
			return err
		}
	}

	// a version negotiation packet of at least length 1200
	// is sent.  All versions advertised are grease versions
	// (0x0a0a0a0a)
	probe := bytes.Repeat([]byte{0x0a}, 1207)
	copy(probe, verHeader)
	_, err = conn.WriteTo(probe, rAddr)
	if err != nil {
		return err
	}

	hdr := make([]byte, 1280)
	n, _, err := conn.ReadFrom(hdr)
	if err != nil {
		return err
	}
	if n < 6 {
		return fmt.Errorf("short quic response: %d", n)
	}
	hdr = hdr[:n]

	// this is a quick and dirty test for something that appears to be
	// an ietf-like long header QUIC packet with a valid version
	version := binary.BigEndian.Uint32(hdr[1:5])
	// long header bit = 1, fixed bit = 0
	if hdr[0]&0x80 != 0x80 {
		return fmt.Errorf("long header bit is not set: %v", hex.EncodeToString(hdr))
	}
	// check the fixed bit if we somehow got something other than a
	// negotiation back ...
	if version != 0 && hdr[0]&0x40 != 0x00 {
		return fmt.Errorf("fixed bit is not set: %v", hex.EncodeToString(hdr))
	}

	// dest connection id len < 20
	if hdr[5] > 0x14 {
		return fmt.Errorf("conn id too long: %v", hex.EncodeToString(hdr))
	}
	// version negotiation or ietf version id
	if version != 0 && version&0xff0000 != 0xff0000 {
		return fmt.Errorf("unexpected version: %d (%v)", version, hex.EncodeToString(hdr))
	}

	log.Debugf("reponse was %v", hex.EncodeToString(hdr))

	return nil
}
