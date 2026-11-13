// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package app

import (
	"github.com/LeisureLinux/cursus/internal/config"
	"github.com/X-VPN/Talaria/server"
)

func buildTunPacketHandler(_ config.Config, _ server.TargetPolicy) (server.PacketHandler, func(), error) {
	return nil, nil, errTunUnsupported
}

func buildLinuxTunProvider(_ config.Config) (any, func(), error) {
	return nil, nil, errTunUnsupported
}

func printRoutingCommands(_ config.Config) {}
