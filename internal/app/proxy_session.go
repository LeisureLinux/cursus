// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/LeisureLinux/cursus/internal/config"
	"github.com/X-VPN/Talaria/client/dataplane"
	"github.com/X-VPN/Talaria/protocol/vpnpacket"
	coretransport "github.com/X-VPN/Talaria/transport"
	"github.com/X-VPN/Talaria/transport/socks5tls"
)

// proxySession owns the TalariaTCP control connection and its granted data
// credential. It exposes DialStream, which opens one SOCKS5 CONNECT stream per
// TCP flow on the server; the server applies its target policy and dials out.
type proxySession struct {
	transport *socks5tls.Client
	control   net.Conn
	mu        sync.Mutex
	clientID  uint64
	seq       uint32
	closed    bool
}

// resilientDialStream wraps a live proxy session and transparently rebuilds
// it when the control session dies (idle timeout, network flap, server
// restart). The local listeners stay bound; only the backing session changes.
type resilientDialStream struct {
	ctx       context.Context
	cfg       config.Config
	tlsConfig *tls.Config

	mu      sync.Mutex
	session *proxySession
}

func newResilientDialStream(ctx context.Context, cfg config.Config, tlsConfig *tls.Config) (*resilientDialStream, error) {
	r := &resilientDialStream{ctx: ctx, cfg: cfg, tlsConfig: tlsConfig}
	session, err := newProxySession(ctx, cfg, tlsConfig)
	if err != nil {
		return nil, err
	}
	r.session = session
	return r, nil
}

func (r *resilientDialStream) dial(ctx context.Context, target coretransport.Destination) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		r.mu.Lock()
		session := r.session
		r.mu.Unlock()
		if session == nil {
			return nil, errors.New("cursus proxy session is closed")
		}
		conn, err := session.transport.DialStream(ctx, target)
		if err == nil {
			return conn, nil
		}
		// Rebuild at most once per request. A fresh control session fixes
		// expired grants and stale server-side idles.
		if attempt == 1 || !r.rebuild(session) {
			return nil, err
		}
	}
	return nil, errors.New("cursus proxy session unavailable")
}

func (r *resilientDialStream) rebuild(old *proxySession) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session != old {
		return true // another request already rebuilt it
	}
	if r.ctx.Err() != nil {
		return false
	}
	old.close()
	session, err := newProxySession(r.ctx, r.cfg, r.tlsConfig)
	if err != nil {
		fmt.Printf("[cursus-proxy] reconnect failed: %v\n", err)
		r.session = nil
		return false
	}
	r.session = session
	fmt.Println("[cursus-proxy] control session rebuilt")
	return true
}

func (r *resilientDialStream) close() {
	r.mu.Lock()
	session := r.session
	r.session = nil
	r.mu.Unlock()
	if session != nil {
		session.close()
	}
}

func newProxySession(ctx context.Context, cfg config.Config, tlsConfig *tls.Config) (*proxySession, error) {
	transport, err := socks5tls.NewClient(socks5tls.ClientConfig{
		Address:      net.JoinHostPort(cfg.Client.ServerIP, uint16String(cfg.Client.ServerPort)),
		TLSConfig:    tlsConfig,
		WireIdentity: cfg.Identity,
		WireSecret:   []byte(cfg.WireSecret),
	})
	if err != nil {
		return nil, fmt.Errorf("create TalariaTCP transport: %w", err)
	}
	control, err := transport.DialControl(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("dial control: %w", err)
	}
	grant, err := authenticateProxyControl(ctx, control, cfg)
	if err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, err
	}
	defer clear(grant.DataToken[:])
	if err := transport.Activate(ctx, grant); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("activate data credential: %w", err)
	}
	session := &proxySession{transport: transport, control: control, clientID: grant.ClientID}
	go session.keepAlive()
	return session, nil
}

// authenticateProxyControl performs the three-frame control handshake that
// Talaria's ServeControlConn expects: AuthRequest -> AuthSuccess,
// SessionGrant, SessionReady. It uses only public wire primitives.
func authenticateProxyControl(ctx context.Context, conn net.Conn, cfg config.Config) (coretransport.SessionGrant, error) {
	codec := dataplane.WireCodec{}
	authRaw, err := codec.Encode(&vpnpacket.VpnPacket{
		Cmd:     vpnpacket.CmdAuthRequest,
		Id:      cfg.Client.ClientID,
		Sk:      cfg.Client.SecretKey,
		Version: 1,
	})
	if err != nil {
		return coretransport.SessionGrant{}, err
	}
	defer clear(authRaw)
	deadline := time.Now().Add(15 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return coretransport.SessionGrant{}, err
	}
	defer conn.SetDeadline(time.Time{})
	if err := writeFrame(conn, authRaw); err != nil {
		return coretransport.SessionGrant{}, err
	}
	clear(authRaw)
	buf := make([]byte, 2048)
	packet, err := readPacket(conn, buf, codec)
	if err != nil {
		return coretransport.SessionGrant{}, err
	}
	if packet.Cmd == vpnpacket.CmdErr {
		return coretransport.SessionGrant{}, fmt.Errorf("auth rejected: %s", packet.ErrorMessage)
	}
	if packet.Cmd != vpnpacket.CmdAuthSuccess {
		return coretransport.SessionGrant{}, fmt.Errorf("unexpected auth response cmd=%d", packet.Cmd)
	}
	clientID := packet.NewClientId
	packet, err = readPacket(conn, buf, codec)
	if err != nil {
		return coretransport.SessionGrant{}, err
	}
	if packet.Cmd == vpnpacket.CmdErr {
		return coretransport.SessionGrant{}, fmt.Errorf("session rejected: %s", packet.ErrorMessage)
	}
	if packet.Cmd != vpnpacket.CmdSessionGrant {
		return coretransport.SessionGrant{}, fmt.Errorf("unexpected grant cmd=%d", packet.Cmd)
	}
	if packet.ClientId != clientID || len(packet.SessionDataToken) != coretransport.DataTokenSize {
		return coretransport.SessionGrant{}, errors.New("invalid session grant")
	}
	grant := coretransport.SessionGrant{
		SessionRef: coretransport.SessionRef{ClientID: clientID, Generation: packet.SessionGeneration},
	}
	if packet.SessionExpiresAt > 0 {
		grant.ExpiresAt = time.Unix(packet.SessionExpiresAt, 0)
	}
	copy(grant.DataToken[:], packet.SessionDataToken)
	clear(packet.SessionDataToken)
	packet, err = readPacket(conn, buf, codec)
	if err != nil {
		return coretransport.SessionGrant{}, err
	}
	if packet.Cmd == vpnpacket.CmdErr {
		return coretransport.SessionGrant{}, fmt.Errorf("session setup failed: %s", packet.ErrorMessage)
	}
	if packet.Cmd != vpnpacket.CmdSessionReady || packet.ClientId != grant.ClientID {
		return coretransport.SessionGrant{}, errors.New("unexpected session ready")
	}
	return grant, nil
}

func readPacket(conn net.Conn, buf []byte, codec dataplane.WireCodec) (*vpnpacket.VpnPacket, error) {
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n == 0 || n > len(buf) {
		return nil, errors.New("invalid control frame size")
	}
	packet, _, err := codec.Decode(buf[:n])
	return packet, err
}

func writeFrame(conn net.Conn, frame []byte) error {
	n, err := conn.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

// keepAlive sends a control-frame ping well inside the server's 2-minute idle
// timeout, and drains the replies. The control connection must stay alive for
// DialStream to keep working; data streams do not refresh it.
func (s *proxySession) keepAlive() {
	codec := dataplane.WireCodec{}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	buf := make([]byte, 2048)
	for range ticker.C {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.seq++
		raw, err := codec.Encode(&vpnpacket.VpnPacket{
			Cmd:         vpnpacket.CmdKeepAlive,
			ClientId:    s.clientID,
			KeepAliveId: s.seq,
			SendTime:    time.Now().UnixNano(),
			IsPing:      true,
		})
		if err == nil {
			err = writeFrame(s.control, raw)
		}
		if err == nil {
			// Read the echoed keepalive reply with a short deadline so a dead
			// peer cannot block the loop forever.
			_ = s.control.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = s.control.Read(buf)
			_ = s.control.SetReadDeadline(time.Time{})
		}
		s.mu.Unlock()
		if err != nil {
			fmt.Printf("[cursus-proxy] control keepalive failed: %v\n", err)
			return
		}
	}
}

func (s *proxySession) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	if s.control != nil {
		_ = s.control.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
}

func uint16String(v uint16) string { return strconv.Itoa(int(v)) }
