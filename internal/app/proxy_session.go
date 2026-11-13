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
	proxy     *localProxy
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
	session := &proxySession{transport: transport, control: control}
	session.proxy = newLocalProxy(transport.DialStream)
	if err := session.proxy.start(cfg); err != nil {
		session.close()
		return nil, err
	}
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

func (s *proxySession) wait(ctx context.Context) {
	// The control connection must stay open for the life of the session; close
	// it when the process is shutting down. Data streams are independent.
	<-ctx.Done()
}

func (s *proxySession) close() {
	if s == nil {
		return
	}
	if s.proxy != nil {
		s.proxy.close()
	}
	if s.control != nil {
		_ = s.control.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
}

func uint16String(v uint16) string { return strconv.Itoa(int(v)) }
