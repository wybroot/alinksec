//go:build windows || linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func applyNativeConfig(t *testing.T, binary, work string, contents []byte) {
	t.Helper()
	path := filepath.Join(filepath.Dir(work), "approved-config.yml")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binary, "config", "apply", "--from", path, "--workdir", work).CombinedOutput(); err != nil {
		t.Fatalf("approve native configuration: %v\n%s", err, out)
	}
}

func nativeOSType() pb.OsType {
	if runtime.GOOS == "windows" {
		return pb.OsType_OS_WINDOWS
	}
	return pb.OsType_OS_LINUX
}

type scmConnection struct {
	number   uint32
	commands chan *pb.Command
}

type scmReport struct {
	session uint32
	report  *pb.Report
}

type scmFixture struct {
	pb.UnimplementedEnrollServiceServer
	pb.UnimplementedAgentChannelServer
	response       *pb.EnrollResponse
	enrollments    atomic.Uint32
	sessionCount   atomic.Uint32
	connections    chan scmConnection
	reports        chan scmReport
	pending        []scmReport
	packages       sync.Map
	downloadURL    string
	denyChannels   atomic.Bool
	disconnect     chan struct{}
	activeChannels atomic.Int32
}

func (s *scmFixture) Enroll(_ context.Context, request *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	if request.GetEnrollToken() != "ENROLL-windows-scm-fixture" || request.GetHost().GetOsType() != nativeOSType() || !s.enrollments.CompareAndSwap(0, 1) {
		return nil, status.Error(codes.PermissionDenied, "invalid fixture enrollment")
	}
	return s.response, nil
}

func (s *scmFixture) Channel(stream pb.AgentChannel_ChannelServer) error {
	if s.denyChannels.Load() {
		return status.Error(codes.Unavailable, "fixture transport unavailable")
	}
	s.activeChannels.Add(1)
	defer s.activeChannels.Add(-1)
	remote, ok := peer.FromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "missing TLS identity")
	}
	auth, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok || len(auth.State.VerifiedChains) == 0 || len(auth.State.PeerCertificates) == 0 || auth.State.PeerCertificates[0].Subject.CommonName != s.response.AgentId {
		return status.Error(codes.Unauthenticated, "invalid fixture client certificate")
	}
	connection := scmConnection{number: s.sessionCount.Add(1), commands: make(chan *pb.Command, 2)}
	select {
	case s.connections <- connection:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	if err := stream.Send(&pb.Command{CmdId: fmt.Sprintf("scm-policy-%d", connection.number), Payload: &pb.Command_PolicySync{PolicySync: &pb.CmdPolicySync{
		PolicyVersion: "scm-v1", PolicyJson: `{"decoy":{"enabled":false,"response":"alert_only"},"process_rules":[],"file_rules":[],"login_rules":[]}`,
	}}}); err != nil {
		return err
	}
	received := make(chan error, 1)
	go func() {
		for {
			report, err := stream.Recv()
			if err != nil {
				received <- err
				return
			}
			if report.GetAgentId() != s.response.AgentId {
				received <- status.Error(codes.PermissionDenied, "report identity mismatch")
				return
			}
			select {
			case s.reports <- scmReport{session: connection.number, report: report}:
			case <-stream.Context().Done():
				return
			}
		}
	}()
	for {
		select {
		case <-s.disconnect:
			return status.Error(codes.Unavailable, "fixture transport disconnected")
		case command := <-connection.commands:
			if err := stream.Send(command); err != nil {
				return err
			}
		case err := <-received:
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

func (s *scmFixture) nextConnection(t *testing.T) scmConnection {
	t.Helper()
	select {
	case connection := <-s.connections:
		return connection
	case <-time.After(90 * time.Second):
		t.Fatal("native service did not establish its mTLS channel")
		return scmConnection{}
	}
}

func (s *scmFixture) awaitReport(t *testing.T, session uint32, matches func(*pb.Report) bool) *pb.Report {
	t.Helper()
	for i, result := range s.pending {
		if result.session == session && matches(result.report) {
			s.pending = append(s.pending[:i], s.pending[i+1:]...)
			return result.report
		}
	}
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	for {
		select {
		case result := <-s.reports:
			if result.session == session && matches(result.report) {
				return result.report
			}
			s.pending = append(s.pending, result)
		case <-timer.C:
			t.Fatal("native service did not send the expected report")
			return nil
		}
	}
}

func newSCMFixture(t *testing.T, root string) (*scmFixture, string, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SCM fixture CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caPEM, _ := scmCertificate(t, ca, caKey, ca, caKey)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, serverKeyPEM := scmCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2),
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, serverKey, ca, caKey)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const agentID = "00000000-0000-4000-8000-000000000028"
	clientPEM, clientKeyPEM := scmCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: agentID},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, clientKey, ca, caKey)
	serverCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &scmFixture{response: &pb.EnrollResponse{AgentId: agentID, ClientCert: clientPEM, ClientKey: clientKeyPEM, CaCert: string(caPEM)},
		connections: make(chan scmConnection, 8), reports: make(chan scmReport, 256), disconnect: make(chan struct{}, 1)}
	downloads := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := fixture.packages.Load(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(value.([]byte))
	}))
	downloads.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	downloads.StartTLS()
	t.Cleanup(downloads.Close)
	fixture.downloadURL = downloads.URL
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert},
		ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12})))
	pb.RegisterEnrollServiceServer(server, fixture)
	pb.RegisterAgentChannelServer(server, fixture)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	caFile := filepath.Join(root, "ca.crt")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return fixture, listener.Addr().String(), caFile
}

func scmCertificate(t *testing.T, template *x509.Certificate, key *ecdsa.PrivateKey, parent *x509.Certificate, signer *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
