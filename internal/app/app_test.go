// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/LeisureLinux/cursus/internal/config"
	"github.com/X-VPN/Talaria"
	"github.com/X-VPN/Talaria/client"
	clientdefaults "github.com/X-VPN/Talaria/client/defaults"
	"github.com/X-VPN/Talaria/server"
)

func testConfig(t *testing.T, protocol string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Protocol = protocol
	cfg.Mode = "server"
	cfg.Server.ListenHost = "127.0.0.1"
	cfg.Server.UDPPort = 0
	cfg.Server.TCPPort = 0
	cfg.Server.ManageRouting = false
	cfg.TUN.Mode = "echo"
	cfg.TUN.EchoTarget = "1.1.1.1"
	cfg.TUN.EchoPayload = "cursus-round-trip"
	cfg.TLS.CAFile = filepath.Join(t.TempDir(), "echo-ca.pem")
	cfg.WireSecret = "cursus-test-wire-secret-32-bytes-minimum"
	cfg.Identity = "test.example.com"
	cfg.Client.ServerIP = "192.0.2.10" // RFC 5737 TEST-NET-1, not a placeholder
	cfg.Server.Auth.SecretKey = "cursus-test-auth-secret"
	cfg.Client.SecretKey = "cursus-test-auth-secret"
	return cfg
}

// TestEndToEnd drives the real Talaria transport through cursus config,
// certificates and in-memory TUN, for both protocols.
func TestEndToEnd(t *testing.T) {
	for _, protocol := range []string{"TalariaUDP", "TalariaTCP"} {
		t.Run(protocol, func(t *testing.T) { testEndToEnd(t, protocol) })
	}
}

func testEndToEnd(t *testing.T, protocol string) {
	cfg := testConfig(t, protocol)
	certPEM, keyPEM, err := loadServerCertificate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := server.NewReferenceTargetPolicy(server.ReferenceTargetPolicyConfig{AllowPrivateTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	srvConfig := server.Config{
		Protocol: client.Protocol(cfg.Protocol),
		Host:     cfg.Server.ListenHost,
		Port:     int(cfg.ActivePort()),
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		Auth: server.StaticAuthProvider{
			ClientID: cfg.Server.Auth.ClientID, SecretKey: cfg.Server.Auth.SecretKey,
			AssignedClientID: cfg.Server.Auth.AssignedClientID, Version: cfg.Server.Auth.Version,
		},
		PacketHandler: server.EchoPacketHandler{},
		TargetPolicy:  policy,
	}
	if cfg.Protocol == "TalariaTCP" {
		srvConfig.TalariaTCPWireSecret = cfg.WireSecret
		srvConfig.TalariaTCPWireIdentity = cfg.Identity
	} else {
		srvConfig.TalariaUDPWireSecret = cfg.WireSecret
		srvConfig.TalariaUDPWireIdentity = cfg.Identity
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv, err := talaria.StartServer(ctx, srvConfig)
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()
	_, portText, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Client.ServerIP = "127.0.0.1"
	cfg.Client.ServerPort = uint16(port64)

	tlsConfig, err := clientTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tun := newMemoryTun(8, cfg.TUN.MTU())
	opt := clientdefaults.ClientOptions{TLSConfig: tlsConfig, Domain: cfg.Identity}
	if cfg.Protocol == "TalariaTCP" {
		opt.TalariaTCPWireSecret = cfg.WireSecret
		opt.TalariaTCPWireIdentity = cfg.Identity
	} else {
		opt.TalariaUDPWireSecret = cfg.WireSecret
		opt.TalariaUDPWireIdentity = cfg.Identity
	}
	sess, err := talaria.NewClient(client.Config{
		Protocol: client.Protocol(cfg.Protocol), ClientID: cfg.Client.ClientID,
		SecretKey: cfg.Client.SecretKey, EntranceIP: cfg.Client.EntranceIP,
		ExitIP: cfg.Client.ExitIP, ServerIP: cfg.Client.ServerIP,
		Domain: cfg.Identity, ServerPort: cfg.Client.ServerPort,
		MTU: cfg.TUN.MTU(), AuthTimeout: 10 * time.Second,
	}, memoryTunProvider{tun: tun}, opt)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Start(ctx); err != nil {
		t.Fatalf("start client: %v", err)
	}
	packet, err := buildIPv4Packet(net.ParseIP(cfg.Client.EntranceIP),
		net.ParseIP(cfg.TUN.EchoTarget), 1, []byte(cfg.TUN.EchoPayload))
	if err != nil {
		t.Fatal(err)
	}
	if err := tun.Inject(packet); err != nil {
		t.Fatal(err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, 8*time.Second)
	defer readCancel()
	reply, err := tun.ReadOutput(readCtx)
	if err != nil {
		t.Fatalf("no echo reply: %v", err)
	}
	if !bytes.Equal(reply, packet) {
		t.Fatalf("reply mismatch:\n got %x\nwant %x", reply, packet)
	}
	_ = sess.Close()
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("session did not stop")
	}
	_ = srv.Close()
}

func TestConfigValidation(t *testing.T) {
	cfg := config.Default()
	cfg.WireSecret = "short"
	if err := cfg.Validate("server"); err == nil {
		t.Fatal("short wire_secret was accepted")
	}
	cfg.WireSecret = "0123456789abcdef0123456789abcdef"
	cfg.Identity = "vpn.example.com"
	cfg.Client.ServerIP = "203.0.113.1"
	if err := cfg.Validate("server"); err == nil {
		t.Fatal("placeholder identity/server_ip was accepted")
	}
	cfg.Identity = "test.example.com"
	cfg.Client.ServerIP = "192.0.2.10"
	if err := cfg.Validate("client"); err == nil {
		t.Fatal("server config accepted as client")
	}
	if err := cfg.Validate("server"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestProxyConfigValidation(t *testing.T) {
	base := testConfig(t, "TalariaTCP")
	base.Mode = "client"
	base.Client.Proxy.Enabled = false
	base.Client.Proxy.SOCKS5Port = 1080
	base.Client.Proxy.HTTPPort = 8080
	if err := base.Validate("client"); err != nil {
		t.Fatalf("valid TCP TUN client rejected: %v", err)
	}
	base.Client.Proxy.Enabled = true
	if err := base.Validate("client"); err != nil {
		t.Fatalf("valid TCP proxy client rejected: %v", err)
	}
	udp := testConfig(t, "TalariaUDP")
	udp.Mode = "client"
	udp.Client.Proxy.Enabled = true
	if err := udp.Validate("client"); err == nil {
		t.Fatal("TalariaUDP + proxy.enabled was accepted")
	}
	base.Client.Proxy.SOCKS5Port = 0
	base.Client.Proxy.HTTPPort = 0
	if err := base.Validate("client"); err == nil {
		t.Fatal("proxy without any listener port was accepted")
	}
}
