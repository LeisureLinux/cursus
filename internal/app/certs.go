// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/LeisureLinux/cursus/internal/config"
)

// loadServerCertificate reads the deployment's TLS certificate from disk.
// In tun mode this is mandatory: Talaria rejects dynamic GetCertificate
// callbacks, and production never uses a self-signed CA.
//
// In echo mode (no root, local smoke test) a throwaway CA + leaf certificate
// is generated at ca_file so the same YAML can be used for both peers without
// shipping secrets in the repository.
func loadServerCertificate(cfg config.Config) (certPEM, keyPEM string, err error) {
	if cfg.TUN.Mode == "echo" {
		return loadOrCreateEchoCertificate(cfg)
	}
	certBytes, err := os.ReadFile(cfg.Server.CertFile)
	if err != nil {
		return "", "", fmt.Errorf("read cert_file %s: %w", cfg.Server.CertFile, err)
	}
	keyBytes, err := os.ReadFile(cfg.Server.KeyFile)
	if err != nil {
		return "", "", fmt.Errorf("read key_file %s (needs root or letsencrypt group): %w", cfg.Server.KeyFile, err)
	}
	certificate, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return "", "", fmt.Errorf("invalid certificate/key pair: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return "", "", errors.New("certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return "", "", err
	}
	if err := leaf.VerifyHostname(cfg.Identity); err != nil {
		return "", "", fmt.Errorf("certificate does not cover %s: %w", cfg.Identity, err)
	}
	return string(certBytes), string(keyBytes), nil
}

// clientTLS uses the host's system trust store in production. The deployment uses a
// public Let's Encrypt certificate, so no CA file ships with cursus-client.
// In echo mode a locally generated CA is trusted instead. InsecureSkipVerify
// stays false in both cases; Talaria rejects any config that enables it.
func clientTLS(cfg config.Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		ServerName: cfg.Identity,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if cfg.TLS.CAFile == "" && cfg.TUN.Mode == "echo" {
		// Remote connectivity check: in-memory TUN but a real LE certificate.
		// This proves the firewall + TLS + auth path without root privileges.
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			return nil, fmt.Errorf("system certificate pool unavailable: %v", err)
		}
		tlsCfg.RootCAs = roots
		return tlsCfg, nil
	}
	if cfg.TUN.Mode == "echo" && cfg.TLS.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls.ca_file %s: %w", cfg.TLS.CAFile, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("tls.ca_file does not contain a valid CA certificate")
		}
		tlsCfg.RootCAs = roots
		return tlsCfg, nil
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return nil, fmt.Errorf("system certificate pool unavailable: %v", err)
	}
	tlsCfg.RootCAs = roots
	return tlsCfg, nil
}

// loadOrCreateEchoCertificate creates a short-lived self-signed CA for local
// echo tests. It deliberately uses /var/tmp (never /tmp on remote hosts, where
// remote hosts) and writes the CA with 0644 because it contains no secret.
func loadOrCreateEchoCertificate(cfg config.Config) (certPEM, keyPEM string, err error) {
	path := cfg.TLS.CAFile
	if path == "" {
		path = "/var/tmp/cursus-echo-ca.pem"
	}
	if existing, err := os.ReadFile(path); err == nil {
		// We cannot recover the private key from a CA-only file, so store the
		// whole echo bundle (CA cert + leaf cert + key) in one PEM with 0600.
		blocks := decodePEMBlocks(existing)
		if len(blocks) == 3 {
			return string(blocks[1]), string(blocks[2]), nil
		}
		return "", "", fmt.Errorf("%s exists but is not a cursus echo certificate bundle", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cursus echo CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return "", "", err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cfg.Identity},
		DNSNames:  []string{cfg.Identity},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	bundle := append([]byte(nil), caPEM...)
	bundle = append(bundle, []byte(certPEM)...)
	bundle = append(bundle, []byte(keyPEM)...)
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		return "", "", fmt.Errorf("write echo certificate bundle %s: %w", path, err)
	}
	return certPEM, keyPEM, nil
}

func decodePEMBlocks(data []byte) [][]byte {
	var blocks [][]byte
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		blocks = append(blocks, pem.EncodeToMemory(block))
		data = rest
	}
	return blocks
}
