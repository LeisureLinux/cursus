// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/X-VPN/Talaria/client/platform"
)

// memoryTun is a platform.Tun that carries IP packets through in-memory
// channels. It lets cursus verify the encrypted transport, auth, keepalive and
// packet loops without root privileges or OS configuration.
type memoryTun struct {
	inbound   chan []byte
	outbound  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	mtu       int
}

func newMemoryTun(queue int, mtu int) *memoryTun {
	return &memoryTun{
		inbound:  make(chan []byte, queue),
		outbound: make(chan []byte, queue),
		closed:   make(chan struct{}),
		mtu:      mtu,
	}
}

func (t *memoryTun) Read(p []byte) (int, error) {
	select {
	case packet := <-t.inbound:
		if len(packet) > len(p) {
			return 0, io.ErrShortBuffer
		}
		return copy(p, packet), nil
	case <-t.closed:
		return 0, io.ErrClosedPipe
	}
}

func (t *memoryTun) ReadPacketOffset(buf []byte, offset int) (int, error) {
	if offset < 0 || offset > len(buf) {
		return 0, io.ErrShortBuffer
	}
	return t.Read(buf[offset:])
}

func (t *memoryTun) Write(p []byte) (int, error) {
	return t.WriteContext(context.Background(), p)
}

func (t *memoryTun) WriteContext(ctx context.Context, p []byte) (int, error) {
	packet := append([]byte(nil), p...)
	select {
	case t.outbound <- packet:
		return len(p), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-t.closed:
		return 0, io.ErrClosedPipe
	}
}

func (t *memoryTun) WritePacketOffset(ctx context.Context, buf []byte, offset, length int) (int, error) {
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return 0, io.ErrShortBuffer
	}
	return t.WriteContext(ctx, buf[offset:offset+length])
}

func (t *memoryTun) Close() error {
	t.closeOnce.Do(func() { close(t.closed) })
	return nil
}

func (t *memoryTun) Inject(packet []byte) error {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case t.inbound <- copyOfPacket:
		return nil
	case <-t.closed:
		return io.ErrClosedPipe
	}
}

func (t *memoryTun) ReadOutput(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-t.outbound:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, io.ErrClosedPipe
	}
}

type memoryTunProvider struct{ tun *memoryTun }

func (p memoryTunProvider) Establish(context.Context, platform.TunConfig) (platform.Tun, error) {
	if p.tun == nil {
		return nil, errors.New("memory TUN is nil")
	}
	return p.tun, nil
}

// buildIPv4Packet creates a valid IPv4 packet with an ICMP or UDP payload.
// The TUN handler parses and rewrites the IP header, so checksums must be valid.
func buildIPv4Packet(src, dst net.IP, protocol byte, payload []byte) ([]byte, error) {
	src4, dst4 := src.To4(), dst.To4()
	if src4 == nil || dst4 == nil {
		return nil, errors.New("IPv4 addresses required")
	}
	headerLen := 20
	var transport []byte
	switch protocol {
	case 17: // UDP
		transport = make([]byte, 8, 8+len(payload))
		binary.BigEndian.PutUint16(transport[0:2], 12345)
		binary.BigEndian.PutUint16(transport[2:4], 53)
		binary.BigEndian.PutUint16(transport[4:6], uint16(8+len(payload)))
		transport = append(transport, payload...)
	case 1: // ICMP echo request
		transport = make([]byte, 8, 8+len(payload))
		transport[0] = 8
		transport = append(transport, payload...)
	default:
		return nil, fmt.Errorf("unsupported protocol %d", protocol)
	}
	total := headerLen + len(transport)
	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	binary.BigEndian.PutUint16(packet[4:6], 0x1234)
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], src4)
	copy(packet[16:20], dst4)
	copy(packet[headerLen:], transport)
	writeIPv4Checksum(packet)
	if protocol == 17 {
		writeUDPChecksum(packet, headerLen)
	} else {
		writeICMPChecksum(packet[headerLen:])
	}
	return packet, nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func writeIPv4Checksum(packet []byte) {
	headerLen := int(packet[0]&0x0f) * 4
	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:headerLen]))
}

func writeUDPChecksum(packet []byte, headerLen int) {
	udp := packet[headerLen:]
	binary.BigEndian.PutUint16(udp[6:8], 0)
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], packet[12:16])
	copy(pseudo[4:8], packet[16:20])
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	binary.BigEndian.PutUint16(udp[6:8], checksum(pseudo))
}

func writeICMPChecksum(icmp []byte) {
	binary.BigEndian.PutUint16(icmp[2:4], 0)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
}
