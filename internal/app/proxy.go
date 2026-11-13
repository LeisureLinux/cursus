// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/LeisureLinux/cursus/internal/config"
	"log"

	coretransport "github.com/X-VPN/Talaria/transport"
	socks5 "github.com/things-go/go-socks5"
)

// localProxy exposes HTTP and SOCKS5 listeners on the client host so devices
// on the LAN can use the tunnel without changing their default gateway.
//
// Each connection is mapped to one TalariaTCP SOCKS5 CONNECT stream
// (DialStream), which the server resolves, policy-checks and dials out.
// No TUN device is needed in proxy mode, so no CAP_NET_ADMIN is required.
type localProxy struct {
	dialStream func(ctx context.Context, target coretransport.Destination) (net.Conn, error)
	httpLn     net.Listener
	socksLn    net.Listener
	httpSrv    *http.Server
	socksSrv   *socks5.Server
}

func newLocalProxy(dialStream func(context.Context, coretransport.Destination) (net.Conn, error)) *localProxy {
	return &localProxy{dialStream: dialStream}
}

func (p *localProxy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("proxy supports tcp only, got %s", network)
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid proxy target port %q", portText)
	}
	return p.dialStream(ctx, coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    host,
		Port:    uint16(port),
	})
}

func (p *localProxy) start(cfg config.Config) error {
	if !cfg.Client.Proxy.Enabled {
		return nil
	}
	addr := net.JoinHostPort(cfg.Client.Proxy.ListenHost, strconv.Itoa(int(cfg.Client.Proxy.SOCKS5Port)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen SOCKS5 %s: %w", addr, err)
	}
	p.socksLn = ln
	p.socksSrv = socks5.NewServer(
		socks5.WithDial(p.dial),
		socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", 0))),
	)
	go func() {
		if err := p.socksSrv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Printf("[cursus-proxy] socks5: %v\n", err)
		}
	}()
	fmt.Printf("[cursus-proxy] SOCKS5 listening on %s\n", ln.Addr())

	if cfg.Client.Proxy.HTTPPort > 0 {
		httpAddr := net.JoinHostPort(cfg.Client.Proxy.ListenHost, strconv.Itoa(int(cfg.Client.Proxy.HTTPPort)))
		httpLn, err := net.Listen("tcp", httpAddr)
		if err != nil {
			return fmt.Errorf("listen HTTP proxy %s: %w", httpAddr, err)
		}
		p.httpLn = httpLn
		p.httpSrv = &http.Server{
			Handler:           http.HandlerFunc(p.handleHTTP),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := p.httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("[cursus-proxy] http: %v\n", err)
			}
		}()
		fmt.Printf("[cursus-proxy] HTTP proxy listening on %s\n", httpLn.Addr())
	}
	return nil
}

// handleHTTP supports absolute-form requests (normal proxy) and CONNECT
// (HTTPS tunneling). Both paths reuse one Talaria stream per connection.
func (p *localProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method == http.MethodConnect {
		p.handleConnect(ctx, w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "proxy requires an absolute URL", http.StatusBadRequest)
		return
	}
	port := r.URL.Port()
	if port == "" {
		if r.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	out, err := p.dialStream(ctx, coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    r.URL.Hostname(),
		Port:    uint16(portNum),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer out.Close()
	// Forward the request (already absolute-form) and relay the response.
	if err := r.Write(out); err != nil {
		return
	}
	if hijacker, ok := w.(http.Hijacker); ok {
		client, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		relay(client, out)
		return
	}
	_, _ = io.Copy(w, out)
}

func (p *localProxy) handleConnect(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host, portText, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, portText = r.Host, "443"
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		http.Error(w, "invalid CONNECT port", http.StatusBadRequest)
		return
	}
	// Resolve locally like the SOCKS5 path does: the server's stream handler
	// expects a concrete IP. Prefer IPv4 because the reference target policy
	// rejects unconfigured native IPv6 destinations.
	if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
		addrs, lookupErr := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if lookupErr != nil || len(addrs) == 0 {
			http.Error(w, "DNS lookup failed", http.StatusBadGateway)
			return
		}
		host = addrs[0].String()
	}
	out, err := p.dialStream(ctx, coretransport.Destination{
		Network: coretransport.NetworkTCP,
		Host:    host,
		Port:    uint16(port),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer out.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}
	relay(client, out)
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go copy(a, b)
	go copy(b, a)
	<-done
}

func (p *localProxy) close() {
	if p == nil {
		return
	}
	if p.socksLn != nil {
		_ = p.socksLn.Close()
	}
	if p.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = p.httpSrv.Shutdown(ctx)
	}
	if p.httpLn != nil {
		_ = p.httpLn.Close()
	}
}
