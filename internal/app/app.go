// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package app wires the Talaria library into the cursus server and client
// processes. It owns YAML config, certificate loading, TUN devices, routing,
// process lifecycle and observability; Talaria owns the VPN data path.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LeisureLinux/cursus/internal/config"
	"github.com/X-VPN/Talaria"
	"github.com/X-VPN/Talaria/client"
	clientdefaults "github.com/X-VPN/Talaria/client/defaults"
	"github.com/X-VPN/Talaria/client/platform"
	"github.com/X-VPN/Talaria/server"
)

// Run starts the cursus process and blocks until ctx is canceled.
func Run(ctx context.Context, role string, cfg config.Config) error {
	if err := cfg.Validate(role); err != nil {
		return err
	}
	if role == "server" {
		return runServer(ctx, cfg)
	}
	return runClient(ctx, cfg)
}

func runServer(ctx context.Context, cfg config.Config) error {
	certPEM, keyPEM, err := loadServerCertificate(cfg)
	if err != nil {
		return err
	}
	policy, err := server.NewReferenceTargetPolicy(server.ReferenceTargetPolicyConfig{
		AllowPrivateTargets: cfg.Server.AllowPrivate,
	})
	if err != nil {
		return err
	}
	// ONE process serves BOTH protocols. Talaria's server.Config carries a
	// single Protocol, so we start two Server objects with independent ports
	// and virtual-IP pools. They share the same certificate, auth provider,
	// target policy and packet handler.
	type instance struct {
		protocol client.Protocol
		port     uint16
		vip      string
		base     string
		tunName  string
	}
	instances := []instance{
		{client.ProtocolTalariaUDP, cfg.Server.UDPPort, cfg.Server.VirtualPrefix, cfg.Server.VirtualBase, cfg.TUN.ServerName},
		{client.ProtocolTalariaTCP, cfg.Server.TCPPort, cfg.Server.VirtualPrefixTCP, cfg.Server.VirtualBaseTCP, cfg.TUN.ServerNameTCP},
	}
	var servers []*server.Server
	for _, inst := range instances {
		instCfg := cfg
		instCfg.Protocol = string(inst.protocol)
		instCfg.Server.VirtualPrefix = inst.vip
		instCfg.Server.VirtualBase = inst.base
		instCfg.TUN.ServerName = inst.tunName
		handler, cleanup, err := buildPacketHandler(instCfg, policy)
		if err != nil {
			for _, s := range servers {
				_ = s.Close()
			}
			return err
		}
		srvConfig := server.Config{
			Protocol: inst.protocol,
			Host:     cfg.Server.ListenHost,
			Port:     int(inst.port),
			CertPEM:  certPEM,
			KeyPEM:   keyPEM,
			Auth: server.StaticAuthProvider{
				ClientID:         cfg.Server.Auth.ClientID,
				SecretKey:        cfg.Server.Auth.SecretKey,
				AssignedClientID: cfg.Server.Auth.AssignedClientID,
				Version:          cfg.Server.Auth.Version,
			},
			PacketHandler: handler,
			TargetPolicy:  policy,
			ErrorLog: func(scope string, err error) {
				if err == nil || errors.Is(err, context.Canceled) ||
					errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
					return
				}
				fmt.Printf("[cursus-server:%s] %v\n", scope, err)
			},
		}
		if inst.protocol == client.ProtocolTalariaTCP {
			srvConfig.TalariaTCPWireSecret = cfg.WireSecret
			srvConfig.TalariaTCPWireIdentity = cfg.Identity
		} else {
			srvConfig.TalariaUDPWireSecret = cfg.WireSecret
			srvConfig.TalariaUDPWireIdentity = cfg.Identity
		}
		srv, err := talaria.StartServer(ctx, srvConfig)
		if err != nil {
			cleanup()
			for _, s := range servers {
				_ = s.Close()
			}
			return fmt.Errorf("start %s server: %w", inst.protocol, err)
		}
		servers = append(servers, srv)
		// cleanup is called by the handler's Close via Server.Close; ensure it
		// also runs if this instance is shut down directly.
		_ = cleanup
		fmt.Printf("[cursus-server] %-11s listening on %s\n", inst.protocol, srv.Addr())
	}
	defer func() {
		for _, srv := range servers {
			_ = srv.Close()
		}
	}()
	printServerBanner(cfg)
	if cfg.TUN.Mode == "tun" {
		printRoutingCommands(cfg)
	}
	fmt.Println("[cursus-server] ready; Ctrl-C to stop")
	<-ctx.Done()
	fmt.Println("\n[cursus-server] shutting down")
	for _, srv := range servers {
		_ = srv.Close()
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Wait(waitCtx); err != nil {
			fmt.Printf("[cursus-server] wait: %v\n", err)
		}
	}
	return nil
}

func runClient(ctx context.Context, cfg config.Config) error {
	if cfg.Client.Proxy.Enabled {
		return runProxyClient(ctx, cfg)
	}
	tlsConfig, err := clientTLS(cfg)
	if err != nil {
		return err
	}
	provider, echoTun, cleanup, err := buildTunProvider(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	opt := clientdefaults.ClientOptions{
		TLSConfig: tlsConfig,
		Domain:    cfg.Identity,
		Events:    &eventLogger{},
		Stats:     &statsLogger{verbose: cfg.Log.Verbose},
	}
	if cfg.Protocol == "TalariaTCP" {
		opt.TalariaTCPWireSecret = cfg.WireSecret
		opt.TalariaTCPWireIdentity = cfg.Identity
	} else {
		opt.TalariaUDPWireSecret = cfg.WireSecret
		opt.TalariaUDPWireIdentity = cfg.Identity
	}
	clientCfg := client.Config{
		Protocol:          client.Protocol(cfg.Protocol),
		ClientID:          cfg.Client.ClientID,
		SecretKey:         cfg.Client.SecretKey,
		EntranceIP:        cfg.Client.EntranceIP,
		ExitIP:            cfg.Client.ExitIP,
		ServerIP:          cfg.Client.ServerIP,
		Domain:            cfg.Identity,
		ServerPort:        cfg.Client.ServerPort,
		MTU:               cfg.TUN.MTU(),
		AuthTimeout:       10 * time.Second,
		KeepAliveDuration: 30 * time.Second,
	}
	sess, err := talaria.NewClient(clientCfg, provider, opt)
	if err != nil {
		return fmt.Errorf("new Talaria client: %w", err)
	}
	if err := sess.Start(ctx); err != nil {
		_ = sess.Close()
		return fmt.Errorf("start Talaria client: %w", err)
	}
	defer sess.Close()
	printClientBanner(cfg, sess.LocalAddr(), sess.State())
	if cfg.TUN.Mode == "echo" && echoTun != nil {
		go runEchoProbe(ctx, cfg, echoTun)
	} else {
		printClientRoutes(cfg)
	}
	<-ctx.Done()
	fmt.Println("\n[cursus-client] shutting down")
	_ = sess.Close()
	select {
	case <-sess.Done():
	case <-time.After(3 * time.Second):
		fmt.Println("[cursus-client] session did not stop within 3s")
	}
	if err := sess.Err(); err != nil {
		fmt.Printf("[cursus-client] session ended: %v\n", err)
	}
	return nil
}

func buildPacketHandler(cfg config.Config, policy server.TargetPolicy) (server.PacketHandler, func(), error) {
	if cfg.TUN.Mode == "echo" {
		return server.EchoPacketHandler{}, func() {}, nil
	}
	return buildTunPacketHandler(cfg, policy)
}

func buildTunProvider(cfg config.Config) (platform.TunProvider, *memoryTun, func(), error) {
	if cfg.TUN.Mode == "echo" {
		tun := newMemoryTun(64, cfg.TUN.MTU())
		return memoryTunProvider{tun: tun}, tun, func() { _ = tun.Close() }, nil
	}
	provider, cleanup, err := buildLinuxTunProvider(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	typed, ok := provider.(platform.TunProvider)
	if !ok {
		return nil, nil, nil, errors.New("TUN provider does not implement platform.TunProvider")
	}
	return typed, nil, cleanup, nil
}

func runEchoProbe(ctx context.Context, cfg config.Config, tun *memoryTun) {
	target := net.ParseIP(cfg.TUN.EchoTarget)
	if target == nil {
		fmt.Printf("[echo] invalid tun.echo_target %q\n", cfg.TUN.EchoTarget)
		return
	}
	packet, err := buildIPv4Packet(net.ParseIP(cfg.Client.EntranceIP), target, 1, []byte(cfg.TUN.EchoPayload))
	if err != nil {
		fmt.Printf("[echo] build packet: %v\n", err)
		return
	}
	interval := time.Duration(cfg.TUN.ProbeSeconds) * time.Second
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := tun.Inject(packet); err != nil {
			return
		}
		readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		reply, err := tun.ReadOutput(readCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("[echo] no reply: %v\n", err)
		} else {
			fmt.Printf("[echo] round trip %d bytes via %s\n", len(reply), cfg.ProtocolLabel())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func printServerBanner(cfg config.Config) {
	fmt.Println("=== cursus-server (one process, both protocols) ===")
	fmt.Printf("  UDP listener    %s\n", net.JoinHostPort(cfg.Server.ListenHost, strconv.Itoa(int(cfg.Server.UDPPort))))
	fmt.Printf("  TCP listener    %s\n", net.JoinHostPort(cfg.Server.ListenHost, strconv.Itoa(int(cfg.Server.TCPPort))))
	fmt.Printf("  TLS SNI         %s (public certificate, system trust)\n", cfg.Identity)
	fmt.Printf("  cert            %s\n", cfg.Server.CertFile)
	fmt.Printf("  mode            %s\n", cfg.TUN.Mode)
	fmt.Printf("  auth client     %s\n", cfg.Server.Auth.ClientID)
}

func printClientBanner(cfg config.Config, local string, state client.State) {
	fmt.Println("=== cursus-client ===")
	fmt.Printf("  protocol        %s (%s)\n", cfg.Protocol, cfg.ClientProtocolLabel())
	fmt.Printf("  server          %s\n", cfg.DialAddress())
	fmt.Printf("  TLS SNI         %s\n", cfg.Identity)
	fmt.Printf("  local address   %s\n", local)
	fmt.Printf("  state           %s\n", state)
	fmt.Printf("  mode            %s\n", cfg.TUN.Mode)
}

func printClientRoutes(cfg config.Config) {
	fmt.Println("\n[client] 把目标网段加入 TUN（需要 root/CAP_NET_ADMIN）：")
	for _, route := range cfg.Client.Routes {
		fmt.Printf("  sudo ip route add %s dev %s\n", route, cfg.TUN.ClientName)
	}
}

type eventLogger struct{}

func (eventLogger) OnStateChange(_ context.Context, state client.State) {
	fmt.Printf("[event] state -> %s\n", state)
}
func (eventLogger) OnConnectStage(_ context.Context, stage string, fields map[string]string) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+fields[k])
	}
	if len(parts) == 0 {
		fmt.Printf("[event] stage: %s\n", stage)
		return
	}
	fmt.Printf("[event] stage: %s (%s)\n", stage, strings.Join(parts, ", "))
}
func (eventLogger) OnError(_ context.Context, err error) {
	fmt.Printf("[event] error: %v\n", err)
}

type statsLogger struct {
	verbose  bool
	upload   atomic.Int64
	download atomic.Int64
}

func (s *statsLogger) OnUploadBytes(_ context.Context, n int) {
	s.upload.Add(int64(n))
	if s.verbose {
		fmt.Printf("[stats] upload %d bytes\n", n)
	}
}
func (s *statsLogger) OnDownloadBytes(_ context.Context, n int) {
	s.download.Add(int64(n))
	if s.verbose {
		fmt.Printf("[stats] download %d bytes\n", n)
	}
}
func (s *statsLogger) OnTunRead(_ context.Context, _ int)  {}
func (s *statsLogger) OnTunWrite(_ context.Context, _ int) {}

func printFirewallSummary(cfg config.Config) {
	fmt.Printf("UDP %d / TCP %d\n", cfg.Server.UDPPort, cfg.Server.TCPPort)
}

// runProxyClient exposes local HTTP/SOCKS5 listeners backed by TalariaTCP
// streams. No TUN device is created, so no CAP_NET_ADMIN is needed.
func runProxyClient(ctx context.Context, cfg config.Config) error {
	tlsConfig, err := clientTLS(cfg)
	if err != nil {
		return err
	}
	session, err := newProxySession(ctx, cfg, tlsConfig)
	if err != nil {
		return err
	}
	defer session.close()
	fmt.Println("=== cursus-client (LAN proxy) ===")
	fmt.Printf("  protocol        %s\n", cfg.Protocol)
	fmt.Printf("  server          %s\n", cfg.DialAddress())
	fmt.Printf("  TLS SNI         %s\n", cfg.Identity)
	fmt.Printf("  SOCKS5          %s\n", net.JoinHostPort(cfg.Client.Proxy.ListenHost, strconv.Itoa(int(cfg.Client.Proxy.SOCKS5Port))))
	if cfg.Client.Proxy.HTTPPort > 0 {
		fmt.Printf("  HTTP proxy      %s\n", net.JoinHostPort(cfg.Client.Proxy.ListenHost, strconv.Itoa(int(cfg.Client.Proxy.HTTPPort))))
	}
	fmt.Println("\nLAN devices: set their HTTP/SOCKS5 proxy to this host's IP; no gateway change needed.")
	<-ctx.Done()
	fmt.Println("\n[cursus-client] shutting down")
	return nil
}
