// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package app

import "errors"

var errTunUnsupported = errors.New("tun.mode=tun requires Linux with /dev/net/tun; use tun.mode=echo on this platform")
