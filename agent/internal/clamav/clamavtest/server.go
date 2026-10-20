// Package clamavtest provides private test transports, never a production daemon.
package clamavtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/clamav"
)

func Start(t testing.TB, serve func(net.Conn)) clamav.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private ClamAV test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			go func() {
				defer func() { conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(35 * time.Second))
				serve(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for c := range connections {
			c.Close()
		}
	})
	pin := sha256.Sum256(der)
	return clamav.Config{Enabled: true, Address: listener.Addr().String(), ServerCertSHA256: hex.EncodeToString(pin[:]), TimeoutSec: 2, Realtime: true}
}
func Command(c io.Reader) (string, error) {
	var out []byte
	for len(out) < 64 {
		var b [1]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return "", err
		}
		out = append(out, b[0])
		if b[0] == 0 {
			return string(out), nil
		}
	}
	return "", io.ErrShortBuffer
}
func Stream(c io.Reader) ([]byte, error) {
	var out []byte
	for {
		var header [4]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(header[:])
		if n == 0 {
			return out, nil
		}
		if n > 64<<10 || len(out)+int(n) > int(clamav.MaxFileBytes) {
			return nil, io.ErrShortBuffer
		}
		offset := len(out)
		out = append(out, make([]byte, int(n))...)
		if _, err := io.ReadFull(c, out[offset:]); err != nil {
			return nil, err
		}
	}
}
func Reply(c io.Writer, s string) { _, _ = io.WriteString(c, s+"\x00") }
