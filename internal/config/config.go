// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Package config defines the single YAML document understood by both the
// cursus server and the cursus client.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

const (
	// Both protocols use port 443 (UDP and TCP port spaces are independent),
	// so one firewall rule covers the whole deployment.
	DefaultUDPPort uint16 = 443
	DefaultTCPPort uint16 = 443

	// DefaultMTU is Talaria's ceiling for a UDP carrier: 1460 - IPv6/UDP(48) -
	// max VPN header(21) - secure wire envelope(77) = 1314. Exceeding it makes
	// large packets fail before they ever reach the server.
	DefaultMTU = 1314
)

type Config struct {
	// Mode is "server" or "client". The single cursus binary selects the
	// role with -role / a subcommand; Validate enforces that they agree.
	Mode string `yaml:"mode"`

	// Identity is the wire identity AND the TLS SNI. It must be identical on
	// both peers, unique per endpoint, and match the deployment certificate.
	// There is no built-in value: every deployment sets it in YAML.
	Identity string `yaml:"identity"`

	// WireSecret is the deployment-wide pre-shared secret (>=32 bytes).
	// TalariaUDP seals every datagram with it; TalariaTCP authenticates and
	// randomizes the whole stream with it.
	WireSecret string `yaml:"wire_secret"`

	Protocol string `yaml:"protocol"`

	// Server is only needed when mode: server; Client only when mode: client.
	// A YAML that omits the irrelevant section is valid (defaults are filled
	// in memory by Load, and Validate never inspects the other role's fields).
	Server ServerConfig `yaml:"server,omitempty"`
	Client ClientConfig `yaml:"client,omitempty"`
	TUN    TUNConfig    `yaml:"tun"`
	TLS    TLSConfig    `yaml:"tls"`
	Log    LogConfig    `yaml:"log"`
}

// TLSConfig exists only for the no-root echo self-test. In production
// (tun.mode=tun) ca_file is ignored and the client always verifies against
// the system trust store with the deployment's public certificate.
type TLSConfig struct {
	CAFile string `yaml:"ca_file"`
}

type ServerConfig struct {
	ListenHost string `yaml:"listen_host"`
	UDPPort    uint16 `yaml:"udp_port"`
	TCPPort    uint16 `yaml:"tcp_port"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	// Auth holds static credentials. The server rejects any other auth mode.
	Auth AuthConfig `yaml:"auth"`
	// AllowPrivate permits RFC1918 destinations through the reference policy.
	AllowPrivate bool `yaml:"allow_private"`
	// VirtualPrefix / VirtualBase are the UDP instance's source-NAT pool.
	VirtualPrefix string `yaml:"virtual_prefix"`
	VirtualBase   string `yaml:"virtual_base"`
	// The TCP instance needs a disjoint pool so return routes do not collide.
	VirtualPrefixTCP string `yaml:"virtual_prefix_tcp"`
	VirtualBaseTCP   string `yaml:"virtual_base_tcp"`
	// WANInterface is the egress interface used for MASQUERADE.
	WANInterface string `yaml:"wan_interface"`
	// ManageRouting installs reversible sysctl/nft rules on startup.
	ManageRouting bool `yaml:"manage_routing"`
}

type AuthConfig struct {
	ClientID         string `yaml:"client_id"`
	SecretKey        string `yaml:"secret_key"`
	AssignedClientID uint64 `yaml:"assigned_client_id"`
	Version          byte   `yaml:"version"`
}

type ClientConfig struct {
	ServerIP   string `yaml:"server_ip"`
	ServerPort uint16 `yaml:"server_port"`
	ClientID   string `yaml:"client_id"`
	SecretKey  string `yaml:"secret_key"`
	// EntranceIP / ExitIP are the client TUN's point-to-point addresses.
	// They are unused in proxy mode.
	EntranceIP string `yaml:"entrance_ip"`
	ExitIP     string `yaml:"exit_ip"`
	// Routes are prefixes the operator wants through the tunnel, e.g.
	// "1.1.1.1/32". The binary prints ip commands but never changes the
	// host default route by itself.
	Routes []string `yaml:"routes"`
	// Proxy exposes local HTTP / SOCKS5 listeners so LAN devices can use the
	// tunnel without changing their default gateway. Proxy mode requires
	// TalariaTCP and does not need a TUN device or CAP_NET_ADMIN.
	Proxy ProxyConfig `yaml:"proxy"`
}

// ProxyConfig describes the client's LAN-facing proxy listeners.
type ProxyConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenHost string `yaml:"listen_host"`
	SOCKS5Port uint16 `yaml:"socks5_port"`
	HTTPPort   uint16 `yaml:"http_port"`
}

type TUNConfig struct {
	// Mode is "tun" (real /dev/net/tun) or "echo" (in-memory smoke test).
	Mode          string `yaml:"mode"`
	ServerName    string `yaml:"server_name"`
	ServerNameTCP string `yaml:"server_name_tcp"`
	ClientName    string `yaml:"client_name"`
	MTUValue      int    `yaml:"mtu"`
	EchoTarget    string `yaml:"echo_target"`
	EchoPayload   string `yaml:"echo_payload"`
	ProbeSeconds  int    `yaml:"probe_seconds"`
}

type LogConfig struct {
	// Verbose prints per-packet stats; false prints lifecycle events only.
	Verbose bool `yaml:"verbose"`
}

func Default() Config {
	return Config{
		Mode:       "server",
		Identity:   "vpn.example.com",
		WireSecret: "CHANGE-ME-DEPLOYMENT-WIRE-SECRET-32-BYTES",
		Protocol:   "TalariaUDP",
		Server: ServerConfig{
			ListenHost:       "0.0.0.0",
			UDPPort:          DefaultUDPPort,
			TCPPort:          DefaultTCPPort,
			CertFile:         "/etc/letsencrypt/live/vpn.example.com/fullchain.pem",
			KeyFile:          "/etc/letsencrypt/live/vpn.example.com/privkey.pem",
			Auth:             AuthConfig{ClientID: "cursus-demo", SecretKey: "CHANGE-ME-32-BYTES-MINIMUM", AssignedClientID: 1, Version: 1},
			VirtualPrefix:    "10.77.0.0/24",
			VirtualBase:      "10.77.0.2",
			VirtualPrefixTCP: "10.78.0.0/24",
			VirtualBaseTCP:   "10.78.0.2",
			WANInterface:     "eth0",
			ManageRouting:    true,
		},
		Client: ClientConfig{
			ServerIP:   "203.0.113.1", // RFC 5737 TEST-NET-3 placeholder
			ServerPort: DefaultTCPPort,
			ClientID:   "cursus-demo",
			SecretKey:  "CHANGE-ME-32-BYTES-MINIMUM",
			EntranceIP: "10.77.0.1",
			ExitIP:     "10.77.0.2",
			Routes:     []string{"1.1.1.1/32"},
			Proxy: ProxyConfig{
				Enabled:    true,
				ListenHost: "0.0.0.0",
				SOCKS5Port: 1080,
				HTTPPort:   8080,
			},
		},
		TUN: TUNConfig{
			Mode:          "tun",
			ServerName:    "cursus-s0",
			ServerNameTCP: "cursus-t0",
			ClientName:    "cursus-c0",
			MTUValue:      DefaultMTU,
			EchoTarget:    "1.1.1.1",
			EchoPayload:   "cursus",
		},
		TLS: TLSConfig{CAFile: "/var/tmp/cursus-echo-ca.pem"},
		Log: LogConfig{Verbose: false},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return Config{}, errors.New("config path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func (c Config) Save(path string) error {
	raw, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// Validate applies the security invariants Talaria intentionally leaves to the
// embedding application. It never weakens TLS verification.
func (c Config) Validate(expectedMode string) error {
	if c.Mode != expectedMode {
		return fmt.Errorf("config mode %q does not match binary role %q", c.Mode, expectedMode)
	}
	if c.Identity == "" || c.Identity == "vpn.example.com" {
		return errors.New("identity must be set to your own certificate SNI in YAML")
	}
	if len(c.WireSecret) < 32 {
		return errors.New("wire_secret must be at least 32 bytes")
	}
	switch c.Protocol {
	case "TalariaUDP", "TalariaTCP":
	default:
		return fmt.Errorf("unsupported protocol %q", c.Protocol)
	}
	// The server always runs both protocols in one process, so its own
	// `protocol` field is only a label; only the client picks exactly one.
	// Proxy mode requires TalariaTCP because DialStream is a per-connection
	// SOCKS5 CONNECT stream.
	if expectedMode == "client" && c.Protocol == "TalariaTCP" && c.Client.Proxy.Enabled {
		if c.Client.Proxy.SOCKS5Port == 0 && c.Client.Proxy.HTTPPort == 0 {
			return errors.New("client.proxy.enabled needs at least one of socks5_port / http_port")
		}
	}
	if expectedMode == "client" && c.Protocol == "TalariaUDP" && c.Client.Proxy.Enabled {
		return errors.New("client.proxy requires protocol: TalariaTCP (set proxy.enabled=false for TUN mode)")
	}
	if c.TUN.Mode != "tun" && c.TUN.Mode != "echo" {
		return fmt.Errorf("unsupported tun.mode %q", c.TUN.Mode)
	}
	if c.TUN.MTU() < 576 || c.TUN.MTU() > 9000 {
		return errors.New("tun.mtu must be 576..9000")
	}
	if expectedMode == "server" {
		if len(c.Server.Auth.ClientID) == 0 || len(c.Server.Auth.SecretKey) == 0 ||
			len(c.Server.Auth.ClientID) > 255 || len(c.Server.Auth.SecretKey) > 255 {
			return errors.New("server.auth credentials must be 1..255 bytes")
		}
		// No client.* fields are required on the server.
		return nil
	}

	// Client-only checks from here on.
	if len(c.Client.ClientID) == 0 || len(c.Client.SecretKey) == 0 ||
		len(c.Client.ClientID) > 255 || len(c.Client.SecretKey) > 255 {
		return errors.New("client credentials must be 1..255 bytes")
	}
	if c.Client.ServerIP == "" || c.Client.ServerIP == "203.0.113.1" || net.ParseIP(c.Client.ServerIP) == nil {
		return fmt.Errorf("client.server_ip %q must be your real server IP", c.Client.ServerIP)
	}
	if !c.Client.Proxy.Enabled {
		for _, ip := range []string{c.Client.EntranceIP, c.Client.ExitIP} {
			parsed := net.ParseIP(ip)
			if parsed == nil || parsed.To4() == nil {
				return fmt.Errorf("TUN address %q must be IPv4", ip)
			}
		}
	}
	for _, route := range c.Client.Routes {
		if _, _, err := net.ParseCIDR(route); err != nil {
			if net.ParseIP(route) == nil {
				return fmt.Errorf("client.routes entry %q must be CIDR or IP", route)
			}
		}
	}
	return nil
}

// ActivePort reports the port for the configured protocol.
func (c Config) ActivePort() uint16 {
	if c.Protocol == "TalariaTCP" {
		return c.Server.TCPPort
	}
	return c.Server.UDPPort
}

// ClientDialPort is the port the client dials.
func (c Config) ClientDialPort() uint16 { return c.Client.ServerPort }

func (c Config) ListenAddress() string {
	return net.JoinHostPort(c.Server.ListenHost, strconv.Itoa(int(c.ActivePort())))
}

func (c Config) DialAddress() string {
	return net.JoinHostPort(c.Client.ServerIP, strconv.Itoa(int(c.ClientDialPort())))
}

// ProtocolLabel returns a human-friendly "udp/443" or "tcp/443" string.
func (c Config) ProtocolLabel() string {
	if c.Protocol == "TalariaTCP" {
		return "tcp/" + strconv.Itoa(int(c.Server.TCPPort))
	}
	return "udp/" + strconv.Itoa(int(c.Server.UDPPort))
}

func (c Config) ClientProtocolLabel() string {
	if c.Protocol == "TalariaTCP" {
		return "tcp/" + strconv.Itoa(int(c.Client.ServerPort))
	}
	return "udp/" + strconv.Itoa(int(c.Client.ServerPort))
}

// MTU lives on TUNConfig so a compact YAML can set tun.mtu.
func (t TUNConfig) MTU() int {
	if t.MTUValue <= 0 {
		return DefaultMTU
	}
	return t.MTUValue
}
