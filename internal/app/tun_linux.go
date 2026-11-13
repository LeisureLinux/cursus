// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/X-VPN/Talaria/client/platform"
	"golang.org/x/sys/unix"
)

// linuxTun is a minimal platform.Tun implementation backed by /dev/net/tun.
// It uses a raw nonblocking fd plus epoll so Close and context cancellation
// interrupt a blocked read, as the platform.Tun contract requires.
type linuxTun struct {
	file      *os.File
	fd        int
	name      string
	mtu       int
	epollFD   int
	closed    chan struct{}
	closeOnce sync.Once
	readMu    sync.Mutex
	writeMu   sync.Mutex
}

func openLinuxTun(name string, mtu int) (*linuxTun, error) {
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (need CAP_NET_ADMIN): %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	ifr.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(int(file.Fd()), unix.TUNSETIFF, ifr); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, err)
	}
	fd := int(file.Fd())
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = file.Close()
		return nil, err
	}
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	event := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	if err := unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, fd, &event); err != nil {
		_ = unix.Close(epollFD)
		_ = file.Close()
		return nil, err
	}
	return &linuxTun{
		file: file, fd: fd, name: ifr.Name(), mtu: mtu,
		epollFD: epollFD, closed: make(chan struct{}),
	}, nil
}

func (t *linuxTun) Name() string { return t.name }

var errWouldBlock = errors.New("would block")

func (t *linuxTun) waitReadable(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	events := make([]unix.EpollEvent, 1)
	for {
		select {
		case <-t.closed:
			return net.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, err := unix.EpollWait(t.epollFD, events, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
	}
}

func (t *linuxTun) readNow(buf []byte) (int, error) {
	n, err := unix.Read(t.fd, buf)
	if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
		return 0, errWouldBlock
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (t *linuxTun) readOne(ctx context.Context, buf []byte) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for {
		select {
		case <-t.closed:
			return 0, net.ErrClosed
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		n, err := t.readNow(buf)
		if err == nil {
			return n, nil
		}
		if !errors.Is(err, errWouldBlock) {
			return 0, err
		}
		if err := t.waitReadable(ctx); err != nil {
			return 0, err
		}
	}
}

func (t *linuxTun) Read(p []byte) (int, error) {
	return t.readOne(context.Background(), p)
}

func (t *linuxTun) ReadPacketOffset(buf []byte, payloadOffset int) (int, error) {
	if payloadOffset < 0 || payloadOffset > len(buf) {
		return 0, unix.EINVAL
	}
	return t.readOne(context.Background(), buf[payloadOffset:])
}

func (t *linuxTun) writeOne(ctx context.Context, p []byte) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	for {
		select {
		case <-t.closed:
			return 0, net.ErrClosed
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		n, err := unix.Write(t.fd, p)
		if err == nil {
			return n, nil
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
			events := make([]unix.EpollEvent, 1)
			if _, waitErr := unix.EpollWait(t.epollFD, events, 10); waitErr != nil && waitErr != unix.EINTR {
				return 0, waitErr
			}
			continue
		}
		return 0, err
	}
}

func (t *linuxTun) Write(p []byte) (int, error) {
	return t.writeOne(context.Background(), p)
}
func (t *linuxTun) WriteContext(ctx context.Context, p []byte) (int, error) {
	return t.writeOne(ctx, p)
}
func (t *linuxTun) WritePacketOffset(ctx context.Context, buf []byte, offset, length int) (int, error) {
	if offset < 0 || length < 0 || offset > len(buf) || length > len(buf)-offset {
		return 0, unix.EINVAL
	}
	return t.writeOne(ctx, buf[offset:offset+length])
}

func (t *linuxTun) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = unix.Close(t.epollFD)
		closeErr = t.file.Close()
	})
	return closeErr
}

// linuxTunProvider implements client.TunProvider for a real Linux TUN.
type linuxTunProvider struct {
	name        string
	mtu         int
	onEstablish func(name string) error
	onClose     func(name string)
}

func (p linuxTunProvider) Establish(_ context.Context, _ platform.TunConfig) (platform.Tun, error) {
	tun, err := openLinuxTun(p.name, p.mtu)
	if err != nil {
		return nil, err
	}
	if p.onEstablish != nil {
		if err := p.onEstablish(tun.Name()); err != nil {
			_ = tun.Close()
			return nil, err
		}
	}
	return &managedTun{linuxTun: tun, onClose: p.onClose}, nil
}

type managedTun struct {
	*linuxTun
	onClose    func(string)
	closeState atomic.Bool
}

func (t *managedTun) Close() error {
	if !t.closeState.CompareAndSwap(false, true) {
		return nil
	}
	if t.onClose != nil {
		t.onClose(t.Name())
	}
	return t.linuxTun.Close()
}

// serverTunDevice implements server.TunDevice on top of linuxTun.
type serverTunDevice struct {
	tun       *linuxTun
	batchSize int
	mtu       int
	closeOnce sync.Once
}

func newServerTunDevice(name string, mtu int) (*serverTunDevice, error) {
	tun, err := openLinuxTun(name, mtu)
	if err != nil {
		return nil, err
	}
	return &serverTunDevice{tun: tun, batchSize: 32, mtu: mtu}, nil
}

func (d *serverTunDevice) BatchSize() int     { return d.batchSize }
func (d *serverTunDevice) MTU() int           { return d.mtu }
func (d *serverTunDevice) WriteHeadroom() int { return 0 }

func (d *serverTunDevice) ReadPackets(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, errors.New("invalid read batch")
	}
	if len(bufs) > d.batchSize {
		bufs = bufs[:d.batchSize]
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.tun.readMu.Lock()
	defer d.tun.readMu.Unlock()
	for i := range bufs {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		if offset < 0 || offset > len(bufs[i]) {
			return i, errors.New("invalid packet offset")
		}
		for {
			select {
			case <-d.tun.closed:
				return i, net.ErrClosed
			case <-ctx.Done():
				return i, ctx.Err()
			default:
			}
			n, err := d.tun.readNow(bufs[i][offset:])
			if err == nil {
				if n <= 0 {
					continue
				}
				sizes[i] = n
				break
			}
			if !errors.Is(err, errWouldBlock) {
				return i, err
			}
			if i == 0 {
				if err := d.tun.waitReadable(ctx); err != nil {
					return 0, err
				}
				continue
			}
			return i, nil
		}
	}
	return len(bufs), nil
}

func (d *serverTunDevice) WritePackets(ctx context.Context, bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) > d.batchSize || len(sizes) < len(bufs) {
		return 0, errors.New("invalid write batch")
	}
	for i := range bufs {
		if err := ctx.Err(); err != nil {
			return i, err
		}
		size := sizes[i]
		if size < 0 || offset < 0 || offset > len(bufs[i]) || size > len(bufs[i])-offset {
			return i, errors.New("invalid packet size")
		}
		if size == 0 {
			continue
		}
		n, err := d.tun.writeOne(ctx, bufs[i][offset:offset+size])
		if err != nil {
			return i, err
		}
		if n != size {
			return i, fmt.Errorf("short TUN write: %d of %d", n, size)
		}
	}
	return len(bufs), nil
}

func (d *serverTunDevice) ReleaseVirtualIP(_ context.Context, _ netip.Addr) error {
	// Prototype: no per-VIP conntrack state is tracked. A production deployment
	// must flush queued packets and NAT state before reusing an address.
	return nil
}

func (d *serverTunDevice) Close() error {
	var err error
	d.closeOnce.Do(func() { err = d.tun.Close() })
	return err
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func configureInterface(name string, addrArgs []string, mtu int) error {
	args := append([]string{"addr", "add"}, addrArgs...)
	args = append(args, "dev", name)
	if _, err := runCommand("ip", args...); err != nil {
		return err
	}
	if _, err := runCommand("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu)); err != nil {
		return err
	}
	_, err := runCommand("ip", "link", "set", "dev", name, "up")
	return err
}

func removeRoute(prefix, device string) {
	_, _ = runCommand("ip", "route", "del", prefix, "dev", device)
}

// otherCursusTunExists reports whether a second cursus TUN is still present,
// so shutting down one instance does not disable forwarding for the other.
func otherCursusTunExists(current string) bool {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != current && strings.HasPrefix(name, "cursus-") {
			return true
		}
	}
	return false
}
