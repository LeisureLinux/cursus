// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package app

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/LeisureLinux/cursus/internal/config"
	"github.com/X-VPN/Talaria/server"
)

// routingManager installs reversible host networking changes. Rules are
// expressed in nftables syntax; deploy on hosts with nft available.
type routingManager struct {
	mu       sync.Mutex
	added    bool
	table    string
	wan      string
	prefix   string
	tunName  string
	previous string
}

// nftTableName derives a unique table name per TUN interface, so the UDP and
// TCP cursus instances can run on the same host without overwriting each
// other's rules or deleting them on shutdown.
func nftTableName(tunName string) string {
	var b strings.Builder
	b.WriteString("cursus_")
	for _, r := range tunName {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func newRoutingManager(cfg config.Config) (*routingManager, error) {
	prefix, err := netip.ParsePrefix(cfg.Server.VirtualPrefix)
	if err != nil || !prefix.Addr().Is4() {
		return nil, errors.New("server.virtual_prefix must be an IPv4 CIDR")
	}
	return &routingManager{
		table:   nftTableName(cfg.TUN.ServerName),
		wan:     cfg.Server.WANInterface,
		prefix:  prefix.Masked().String(),
		tunName: cfg.TUN.ServerName,
	}, nil
}

// nftRule is the minimal ruleset: IPv4 forwarding + source NAT for the VIP
// pool. It lives in a dedicated table so cleanup never touches host rules.
func (m *routingManager) nftRuleset() string {
	return fmt.Sprintf(`table ip %s {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr %s oifname "%s" masquerade
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "%s" oifname "%s" accept
    iifname "%s" oifname "%s" ct state related,established accept
  }
}
`, m.table, m.prefix, m.wan, m.tunName, m.wan, m.wan, m.tunName)
}

func (m *routingManager) apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.added {
		return nil
	}
	// Preserve the previous sysctl value so shutdown does not clobber an
	// already-enabled router.
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		m.previous = strings.TrimSpace(string(raw))
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	if err := m.feedRuleset(); err != nil {
		m.restoreForwarding()
		return err
	}
	m.added = true
	return nil
}

func (m *routingManager) feedRuleset() error {
	// runCommand cannot feed stdin; use a temp file in /var/tmp (remote temp
	// files must live in /var/tmp, never /tmp).
	f, err := os.CreateTemp("/var/tmp", "cursus-nft-")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	w := bufio.NewWriter(f)
	if _, err := w.WriteString(m.nftRuleset()); err != nil {
		_ = f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := runCommand("nft", "-f", path); err != nil {
		return fmt.Errorf("nft ruleset: %w", err)
	}
	return nil
}

func (m *routingManager) restoreForwarding() {
	if m.previous == "" {
		return
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(m.previous+"\n"), 0o644)
}

func (m *routingManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.added {
		return
	}
	_, _ = runCommand("nft", "delete", "table", "ip", m.table)
	// Only restore ip_forward when no other cursus TUN is still alive.
	if !otherCursusTunExists(m.tunName) {
		m.restoreForwarding()
	}
	m.added = false
}

// buildTunPacketHandler creates the library's built-in TUN forwarding handler,
// plus the host-level routing/NAT it needs.
func buildTunPacketHandler(cfg config.Config, policy server.TargetPolicy) (server.PacketHandler, func(), error) {
	base, err := netip.ParseAddr(cfg.Server.VirtualBase)
	if err != nil || !base.Is4() {
		return nil, nil, errors.New("server.virtual_base must be IPv4")
	}
	prefix, err := netip.ParsePrefix(cfg.Server.VirtualPrefix)
	if err != nil || !prefix.Addr().Is4() {
		return nil, nil, errors.New("server.virtual_prefix must be an IPv4 CIDR")
	}
	prefix = prefix.Masked()
	if !prefix.Contains(base) {
		return nil, nil, errors.New("server.virtual_base is outside server.virtual_prefix")
	}
	device, err := newServerTunDevice(cfg.TUN.ServerName, cfg.TUN.MTU())
	if err != nil {
		return nil, nil, err
	}
	// The handler allocates VIPs upward from base, so use network+1 as the TUN's
	// own address: it cannot collide with any client VIP.
	gateway := prefix.Addr().Next()
	if !prefix.Contains(gateway) || gateway == base {
		_ = device.Close()
		return nil, nil, errors.New("server.virtual_prefix leaves no gateway address")
	}
	gatewayAddr := netip.PrefixFrom(gateway, prefix.Bits()).String()
	if err := configureInterface(cfg.TUN.ServerName, []string{gatewayAddr}, cfg.TUN.MTU()); err != nil {
		_ = device.Close()
		return nil, nil, fmt.Errorf("configure server TUN: %w", err)
	}
	manager, err := newRoutingManager(cfg)
	if err != nil {
		_ = device.Close()
		return nil, nil, err
	}
	if cfg.Server.ManageRouting {
		if err := manager.apply(); err != nil {
			_ = device.Close()
			return nil, nil, err
		}
	}
	cleanup := func() {
		manager.cleanup()
		_ = device.Close()
		removeRoute(prefix.String(), cfg.TUN.ServerName)
		fmt.Println("[cursus] routing rules and server TUN cleaned up")
	}
	handler, err := server.NewTunPacketHandler(server.TunPacketHandlerConfig{
		Device:          device,
		VirtualIPBase:   base,
		VirtualIPPrefix: prefix,
		TargetPolicy:    policy,
		// Host TUNs emit IPv6 neighbor/router advertisements that the IPv4-only
		// TunPacketHandler cannot forward. Dropping them keeps the session alive
		// instead of failing it on the first non-IPv4 packet.
		DropNonIPv4Data: true,
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return handler, cleanup, nil
}

func buildLinuxTunProvider(cfg config.Config) (any, func(), error) {
	entry, err := netip.ParseAddr(cfg.Client.EntranceIP)
	if err != nil || !entry.Is4() {
		return nil, nil, errors.New("client.entrance_ip must be IPv4")
	}
	exit, err := netip.ParseAddr(cfg.Client.ExitIP)
	if err != nil || !exit.Is4() {
		return nil, nil, errors.New("client.exit_ip must be IPv4")
	}
	provider := linuxTunProvider{
		name: cfg.TUN.ClientName,
		mtu:  cfg.TUN.MTU(),
		onEstablish: func(name string) error {
			return configureInterface(name, []string{entry.String(), "peer", exit.String()}, cfg.TUN.MTU())
		},
		onClose: func(name string) {
			fmt.Printf("[cursus] client TUN %s closed; remove routes you added\n", name)
		},
	}
	return provider, func() {}, nil
}

func printRoutingCommands(cfg config.Config) {
	fmt.Println("\n[firewall] 在 VPS 安全组 / 本机防火墙放行（协议 + 端口）：")
	fmt.Printf("  UDP %d   (TalariaUDP, 默认启用)\n", cfg.Server.UDPPort)
	fmt.Printf("  TCP %d   (TalariaTCP, 备用/对比测试)\n", cfg.Server.TCPPort)
	fmt.Println("\n[routing] 客户端把目标网段送进 cursus TUN：")
	for _, route := range cfg.Client.Routes {
		fmt.Printf("  ip route add %s dev %s\n", route, cfg.TUN.ClientName)
	}
	fmt.Println("\n[server] nftables MASQUERADE + ip_forward configured")
	fmt.Printf("  nft list table ip %s\n", nftTableName(cfg.TUN.ServerName))
}
