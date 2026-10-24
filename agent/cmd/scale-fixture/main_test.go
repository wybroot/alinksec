//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const fixtureAgent = "137c5630-425a-4b55-bc33-42855b640905"

type fixture struct {
	pb.UnimplementedEnrollServiceServer
	pb.UnimplementedAgentChannelServer
	ca, clientCert, clientKey []byte
	done                      chan error
}

func (f *fixture) Enroll(ctx context.Context, r *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	if r.EnrollToken != "fixture-token" || r.Host.MachineId == "" {
		return nil, fmt.Errorf("fixture enrollment rejected")
	}
	return &pb.EnrollResponse{AgentId: fixtureAgent, ClientCert: f.clientCert, ClientKey: f.clientKey, CaCert: string(f.ca)}, nil
}

func (f *fixture) Channel(stream pb.AgentChannel_ChannelServer) (failure error) {
	defer func() {
		select {
		case f.done <- failure:
		default:
		}
	}()
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return fmt.Errorf("missing native TLS peer")
	}
	auth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(auth.State.VerifiedChains) == 0 || auth.State.PeerCertificates[0].Subject.CommonName != fixtureAgent {
		return fmt.Errorf("unverified mTLS identity")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.AgentId != fixtureAgent || first.GetHeartbeat() == nil {
		return fmt.Errorf("initial heartbeat missing")
	}
	if err := stream.Send(&pb.Command{CmdId: "b75c6b35-47ef-4070-9b64-a9905b379f31", Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{PolicyVersion: "v42"}}}); err != nil {
		return err
	}
	if err := stream.Send(&pb.Command{CmdId: "540d416c-7681-4f4b-aab1-70ae772d779b", Payload: &pb.Command_CollectNow{CollectNow: &pb.CmdCollectNow{}}}); err != nil {
		return err
	}
	done, log, policy := false, false, false
	for !(done && log && policy) {
		r, err := stream.Recv()
		if err != nil {
			return err
		}
		if r.AgentId != fixtureAgent || !UUIDValid(r.ReportId) {
			return fmt.Errorf("report identity lost")
		}
		if ack := r.GetAck(); ack != nil && ack.CmdId == "540d416c-7681-4f4b-aab1-70ae772d779b" && ack.Stage == pb.RptAck_DONE {
			if ack.Message != "synthetic protocol acknowledgement; no OS action" {
				return fmt.Errorf("synthetic action claim")
			}
			done = true
		}
		if hb := r.GetHeartbeat(); hb != nil {
			policy = hb.PolicyVersion == "v42"
		}
		if batch := r.GetLogBatch(); batch != nil {
			log = len(batch.Lines) == 1 && batch.Lines[0].Fields["timestamp_kind"] == "observed" && len(batch.Lines[0].Fields["source_event_id"]) == 64
		}
	}
	f.done <- nil
	<-stream.Context().Done()
	return nil
}

func UUIDValid(s string) bool {
	return len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

func fixtureTLS(t *testing.T) (*fixture, tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test fixture CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	ca, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	sign := func(name string, serial int64) ([]byte, []byte, tls.Certificate) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: root.NotBefore, NotAfter: root.NotAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, root, &k.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		cert, key := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key, pair
	}
	cert, private, _ := sign(fixtureAgent, 2)
	_, _, server := sign("server", 3)
	return &fixture{ca: caPEM, clientCert: cert, clientKey: private, done: make(chan error, 1)}, server, pool
}

func TestActualMTLSFixturePolicyCollectLogsAndShutdown(t *testing.T) {
	f, serverCert, pool := fixtureTLS(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12})))
	pb.RegisterEnrollServiceServer(server, f)
	pb.RegisterAgentChannelServer(server, f)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := settings{Address: "127.0.0.1:1", Addresses: []string{listener.Addr().String()}, Token: "fixture-token", RunID: "11111111111111111111111111111111", HeartbeatSeconds: 1, LogSeconds: 1}
	stopProducers, producersStopped := make(chan struct{}), make(chan struct{}, 1)
	s.stopProducers, s.producersStopped = stopProducers, producersStopped
	c, err := enroll(ctx, s, 0, pool)
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	old := encoder
	encoder = json.NewEncoder(&raw)
	defer func() { encoder = old }()
	ready := make(chan string, 1)
	exited := make(chan error, 1)
	go func() { exited <- c.run(ctx, s, 0, ready) }()
	select {
	case id := <-ready:
		if id != fixtureAgent {
			t.Fatal(id)
		}
	case <-ctx.Done():
		t.Fatal("initial stream missing")
	}
	select {
	case err := <-f.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("native TLS protocol did not complete")
	}
	close(stopProducers)
	select {
	case <-producersStopped:
	case <-ctx.Done():
		t.Fatal("producers did not quiesce")
	}
	outputMu.Lock()
	before := raw.Len()
	outputMu.Unlock()
	// SQL can inspect the final report with a live stream, while periodic
	// producers stay stopped. Closing at the production deadline would lose it.
	select {
	case <-exited:
		t.Fatal("stream closed before observer drain")
	case <-time.After(1100 * time.Millisecond):
	}
	outputMu.Lock()
	after := raw.Len()
	outputMu.Unlock()
	if before != after {
		t.Fatal("periodic producers continued during durable drain")
	}
	cancel()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("client shutdown blocked")
	}
	if !bytes.Contains(raw.Bytes(), []byte(`"kind":"log"`)) || bytes.Contains(raw.Bytes(), f.clientKey) {
		t.Fatal("bounded protocol observations missing or credentials leaked")
	}
	// The same service must remain unreachable with an untrusted pinned CA.
	wrong := x509.NewCertPool()
	refused, cancelRefused := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancelRefused()
	if c, err := enroll(refused, s, 1, wrong); err == nil {
		c.connection.Close()
		t.Fatal("unpinned TLS server accepted")
	}
}
