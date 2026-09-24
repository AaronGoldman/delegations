package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// certSANs are the hostnames/IPs the auto-generated self-signed certificate
// covers. Add any other name you reach the proxy by (e.g. another .local
// alias). This host's non-loopback IPv4 addresses are always added too.
var certSANs = struct {
	DNS []string
	IP  []string
}{
	DNS: []string{"spark-a5d9.local", "localhost"},
	IP:  []string{"0.0.0.0"},
}

// ensureSelfSignedCert makes sure certFile and keyFile exist. If either is
// missing it generates a fresh self-signed ECDSA (P-256) certificate covering
// certSANs plus this host's LAN IPv4 addresses, and writes both PEM files to
// disk so they are reused on subsequent runs. Pure standard library — no
// openssl required.
func ensureSelfSignedCert(certFile, keyFile string) error {
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}

	dnsNames := certSANs.DNS
	ips := make([]net.IP, 0, len(certSANs.IP)+4)
	for _, s := range certSANs.IP {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	ips = append(ips, localIPv4s()...)
	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour), // small clock-skew grace
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	if err := writePEM(certFile, 0o644, "CERTIFICATE", der); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	return writePEM(keyFile, 0o600, "EC PRIVATE KEY", keyDER)
}

func writePEM(path string, perm os.FileMode, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// localIPv4s returns this host's non-loopback IPv4 addresses (one per interface).
func localIPv4s() []net.IP {
	var out []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if v4 := ipnet.IP.To4(); v4 != nil {
				out = append(out, v4)
			}
		}
	}
	return out
}
