// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

// Command cursus is ONE binary for both the VPN server and the VPN client.
//
//	cursus -role server -config /etc/cursus/server.yaml
//	cursus -role client -config /etc/cursus/client.yaml
//	cursus server -config ...        (subcommand alias)
//	cursus client -config ...        (subcommand alias)
//
// There is no build-time role injection: the role is always chosen at runtime.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/LeisureLinux/cursus/internal/app"
	"github.com/LeisureLinux/cursus/internal/config"
	"gopkg.in/yaml.v3"
)

// version is set by the Makefile / CI via -ldflags.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cursus: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Accept `cursus server ...` / `cursus client ...` as a convenience alias
	// for `-role server` / `-role client` without breaking flag parsing.
	roleOverride := ""
	if len(args) > 0 {
		switch args[0] {
		case "server", "client":
			roleOverride = args[0]
			args = args[1:]
		}
	}
	fs := flag.NewFlagSet("cursus", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML config (required)")
	role := fs.String("role", "", "server or client (required)")
	showVersion := fs.Bool("version", false, "print version and exit")
	showFirewall := fs.Bool("firewall", false, "print the ports to open and exit")
	duration := fs.Duration("duration", 0, "auto-shutdown after this long (0 = until Ctrl-C)")
	printConfig := fs.Bool("print-config", false, "print a starter YAML and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("cursus %s (single binary; -role server|client)\n", version)
		fmt.Println("  TLS 1.3 only; SNI comes from the YAML identity")
		return nil
	}
	effectiveRole := roleOverride
	if effectiveRole == "" {
		effectiveRole = strings.ToLower(strings.TrimSpace(*role))
	}
	if *printConfig {
		cfg := config.Default()
		if effectiveRole == "client" {
			cfg.Mode = "client"
		}
		raw, err := yaml.Marshal(&cfg)
		if err != nil {
			return err
		}
		fmt.Print(string(raw))
		return nil
	}
	if effectiveRole != "server" && effectiveRole != "client" {
		return errors.New("role is required: -role server|client (or `cursus server` / `cursus client`)")
	}
	if *configPath == "" {
		return errors.New("-config is required (try `cursus -print-config -role server > cursus.yaml`)")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *showFirewall {
		fmt.Printf("protocol=%s  listen=%s  ports: UDP %d, TCP %d\n",
			cfg.Protocol, cfg.ListenAddress(), cfg.Server.UDPPort, cfg.Server.TCPPort)
		fmt.Printf("open now : %s\n", cfg.ProtocolLabel())
		fmt.Printf("other    : %s\n", otherProtocolLabel(cfg))
		return nil
	}
	if err := cfg.Validate(effectiveRole); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	return app.Run(ctx, effectiveRole, cfg)
}

func otherProtocolLabel(cfg config.Config) string {
	if cfg.Protocol == "TalariaTCP" {
		return fmt.Sprintf("udp/%d", cfg.Server.UDPPort)
	}
	return fmt.Sprintf("tcp/%d", cfg.Server.TCPPort)
}
