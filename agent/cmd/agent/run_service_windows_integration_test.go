//go:build windows

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

func TestNativeWindowsService(t *testing.T) {
	if os.Getenv("ALINKSEC_SMOKE_ALLOW_FIXTURES") != "true" {
		t.Skip("requires an explicitly authorized disposable Windows host")
	}
	source, err := filepath.Abs(os.Getenv("ALINKSEC_SMOKE_AGENT_BIN"))
	if err != nil || os.Getenv("ALINKSEC_SMOKE_AGENT_BIN") == "" {
		t.Fatal("ALINKSEC_SMOKE_AGENT_BIN must reference the built Agent exe")
	}
	manager, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Disconnect()
	if existing, err := manager.OpenService("alinksec-agent"); err == nil {
		existing.Close()
		t.Fatal("refusing to replace an existing alinksec-agent service")
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "Agent Installation With Spaces")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "alinksec-agent.exe")
	built, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, built, 0700); err != nil {
		t.Fatal(err)
	}
	fixture, address, caFile := newSCMFixture(t, root)
	work := filepath.Join(root, "Agent Work Directory")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "install", "--server", address,
		"--token", "ENROLL-windows-scm-fixture", "--ca-file", caFile, "--workdir", work).CombinedOutput()
	if err != nil {
		t.Fatalf("native install: %v\n%s", err, output)
	}
	cfgPath := filepath.Join(work, "agent.yml")
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg.EnrollToken != "" {
		t.Fatalf("installed configuration or cleared enrollment token: %v", err)
	}
	disabled := false
	cfg.Decoy = config.DecoyConfig{Enabled: &disabled, Response: "alert_only"}
	cfg.HeartbeatInterval = time.Second
	cfg.CollectInterval = 24 * time.Hour
	contents, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, contents, 0600); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(work, "certs", "client.crt")
	certificate, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := sha256.Sum256(certificate)
	service, err := manager.CreateService("alinksec-agent", binary,
		mgr.Config{DisplayName: "ALinkSec native service validation", StartType: mgr.StartManual},
		"run", "--workdir", work)
	if err != nil {
		t.Fatal(err)
	}
	// Remove recovery first so failed checks cannot leave a restarting service.
	defer func() {
		current, _ := service.Query()
		pid := current.ProcessId
		if err := service.ResetRecoveryActions(); err != nil {
			t.Errorf("reset recovery during cleanup: %v", err)
		}
		service.Control(svc.Stop)
		deadline := time.Now().Add(30 * time.Second)
		for {
			current, err := service.Query()
			if current.ProcessId != 0 {
				pid = current.ProcessId
			}
			if err != nil || current.State == svc.Stopped {
				break
			}
			if time.Now().After(deadline) {
				t.Error("service did not stop during cleanup")
				break
			}
			service.Control(svc.Stop)
			time.Sleep(200 * time.Millisecond)
		}
		if pid != 0 {
			waitSCMProcess(t, pid)
		}
		if err := service.Delete(); err != nil {
			t.Errorf("delete validation service: %v", err)
		}
		service.Close()
	}()
	if err := service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}}, 86400); err != nil {
		t.Fatal(err)
	}
	if err := service.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	first := awaitSCMState(t, service, svc.Running)
	connection := fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat() != nil })
	initial := fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetAsset() != nil }).GetAsset()
	if len(initial.GetSoftware()) == 0 || len(initial.GetProcesses()) == 0 || len(initial.GetAccounts()) == 0 {
		t.Fatal("native Windows host assets were empty")
	}
	t.Logf("SCM RUNNING with real mTLS and assets: software=%d processes=%d accounts=%d", len(initial.GetSoftware()), len(initial.GetProcesses()), len(initial.GetAccounts()))
	if interrogated, err := service.Control(svc.Interrogate); err != nil || interrogated.State != svc.Running {
		t.Fatalf("SCM interrogation: status=%+v error=%v", interrogated, err)
	}
	connection.commands <- &pb.Command{CmdId: "scm-collect", Payload: &pb.Command_CollectNow{CollectNow: &pb.CmdCollectNow{CollectorNames: []string{"software"}}}}
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAsset() != nil && len(report.GetAsset().GetSoftware()) > 0
	})
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAck().GetCmdId() == "scm-collect" && report.GetAck().GetStage() == pb.RptAck_DONE
	})
	stopSCMService(t, service, first.ProcessId)
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	second := awaitSCMState(t, service, svc.Running)
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat() != nil })
	if second.ProcessId == first.ProcessId {
		t.Fatal("SCM stop/start did not create a new Agent process")
	}
	connection.commands <- &pb.Command{CmdId: "scm-restart", Payload: &pb.Command_AgentControl{AgentControl: &pb.CmdAgentControl{Action: pb.CmdAgentControl_RESTART}}}
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool {
		return report.GetAck().GetCmdId() == "scm-restart" && report.GetAck().GetStage() == pb.RptAck_DONE
	})
	connection = fixture.nextConnection(t)
	fixture.awaitReport(t, connection.number, func(report *pb.Report) bool { return report.GetHeartbeat() != nil })
	recovered := awaitSCMState(t, service, svc.Running)
	if recovered.ProcessId == second.ProcessId {
		t.Fatal("SCM recovery did not replace the exiting Agent")
	}
	restored, err := os.ReadFile(certPath)
	if err != nil || sha256.Sum256(restored) != identity || fixture.enrollments.Load() != 1 {
		t.Fatalf("restart changed enrollment identity: error=%v enrollments=%d", err, fixture.enrollments.Load())
	}
	stopSCMService(t, service, recovered.ProcessId)
	time.Sleep(2500 * time.Millisecond)
	awaitSCMState(t, service, svc.Stopped)
	if fixture.sessionCount.Load() != 3 {
		t.Fatalf("unexpected sessions after explicit stop: %d", fixture.sessionCount.Load())
	}
	t.Log("SCM stop/start, successful-exit recovery, stable identity and explicit-stop behavior passed")
}

func awaitSCMState(t *testing.T, service *mgr.Service, want svc.State) svc.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		current, err := service.Query()
		if err != nil {
			t.Fatal(err)
		}
		if current.State == want && (want != svc.Running || current.ProcessId != 0) {
			return current
		}
		if time.Now().After(deadline) {
			t.Fatalf("SCM state=%+v, want %v", current, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func stopSCMService(t *testing.T, service *mgr.Service, pid uint32) {
	t.Helper()
	if _, err := service.Control(svc.Stop); err != nil {
		t.Fatal(err)
	}
	stopped := awaitSCMState(t, service, svc.Stopped)
	if stopped.Win32ExitCode != 0 || stopped.ServiceSpecificExitCode != 0 {
		t.Fatalf("normal SCM stop reported failure: %+v", stopped)
	}
	waitSCMProcess(t, pid)
}

func waitSCMProcess(t *testing.T, pid uint32) {
	t.Helper()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Error(err)
		return
	}
	defer windows.CloseHandle(process)
	if result, err := windows.WaitForSingleObject(process, 10000); err != nil || result != windows.WAIT_OBJECT_0 {
		t.Errorf("Agent process did not exit after SCM stop: result=%v error=%v", result, err)
	}
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
	response     *pb.EnrollResponse
	enrollments  atomic.Uint32
	sessionCount atomic.Uint32
	connections  chan scmConnection
	reports      chan scmReport
	pending      []scmReport
}

func (s *scmFixture) Enroll(_ context.Context, request *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	if request.GetEnrollToken() != "ENROLL-windows-scm-fixture" || request.GetHost().GetOsType() != pb.OsType_OS_WINDOWS || !s.enrollments.CompareAndSwap(0, 1) {
		return nil, status.Error(codes.PermissionDenied, "invalid fixture enrollment")
	}
	return s.response, nil
}

func (s *scmFixture) Channel(stream pb.AgentChannel_ChannelServer) error {
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
	case <-time.After(45 * time.Second):
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
	timer := time.NewTimer(60 * time.Second)
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
		connections: make(chan scmConnection, 8), reports: make(chan scmReport, 256)}
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
