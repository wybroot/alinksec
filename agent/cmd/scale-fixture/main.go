//go:build linux

// scale-fixture is a disposable protocol load generator, not an Agent binary.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type settings struct {
	Address          string   `json:"address"`
	Addresses        []string `json:"addresses"`
	CA               string   `json:"ca"`
	Token            string   `json:"token"`
	RunID            string   `json:"runId"`
	Clients          int      `json:"clients"`
	DurationSeconds  int      `json:"durationSeconds"`
	HeartbeatSeconds int      `json:"heartbeatSeconds"`
	LogSeconds       int      `json:"logSeconds"`
	stopProducers    <-chan struct{}
	producersStopped chan<- struct{}
}

// Only fixed local labels and gRPC status enums may enter public evidence.
type fixtureFailure string

func (f fixtureFailure) Error() string { return string(f) }
func safeFailure(err error) string {
	var fixed fixtureFailure
	if errors.As(err, &fixed) {
		return string(fixed)
	}
	return "stream_" + status.Code(err).String()
}

var outputMu sync.Mutex
var encoder = json.NewEncoder(os.Stdout)
var sent atomic.Uint64

func emit(value any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	if err := encoder.Encode(value); err != nil {
		panic("fixture output unavailable")
	}
}

func mono() int64 {
	var t unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &t) != nil {
		panic("monotonic clock unavailable")
	}
	return t.Nano()
}
func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

type client struct {
	id         string
	connection *grpc.ClientConn
	stream     pb.AgentChannel_ChannelClient
	commands   chan *pb.Command
	errors     chan error
}

func enroll(ctx context.Context, s settings, index int, pool *x509.CertPool) (*client, error) {
	address := s.Address
	if len(s.Addresses) > 0 {
		address = s.Addresses[index%len(s.Addresses)]
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})))
	if err != nil {
		return nil, fixtureFailure("enrollment_connection_" + status.Code(err).String())
	}
	defer conn.Close()
	rpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	id := s.RunID + "-" + strconv.Itoa(index)
	response, err := pb.NewEnrollServiceClient(conn).Enroll(rpcCtx, &pb.EnrollRequest{EnrollToken: s.Token, Nonce: uuid(), Host: &pb.HostInfo{
		Hostname: "synthetic-" + id, MachineId: "synthetic-" + id, OsType: pb.OsType_OS_LINUX, OsVersion: "synthetic protocol fixture", Kernel: "not-a-real-host", Arch: runtime.GOARCH, AgentVersion: "synthetic-fixture"}})
	if err != nil {
		return nil, fixtureFailure("enrollment_rpc_" + status.Code(err).String())
	}
	cert, err := tls.X509KeyPair(response.ClientCert, response.ClientKey)
	if err != nil {
		return nil, err
	}
	channel, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})))
	if err != nil {
		return nil, err
	}
	stream, err := pb.NewAgentChannelClient(channel).Channel(ctx)
	if err != nil {
		channel.Close()
		return nil, err
	}
	return &client{id: response.AgentId, connection: channel, stream: stream, commands: make(chan *pb.Command, 16), errors: make(chan error, 1)}, nil
}

func (c *client) send(kind string, seq int, r *pb.Report) error {
	r.AgentId = c.id
	r.ReportId = uuid()
	r.Ts = time.Now().UnixMilli()
	at := mono()
	if err := c.stream.Send(r); err != nil {
		return err
	}
	sent.Add(1)
	// CLOCK_MONOTONIC is shared with the Python SQL observer on this same host.
	// Stream Send completion alone is never treated as a durable receipt.
	emit(map[string]any{"kind": kind, "agentId": c.id, "reportId": r.ReportId, "sequence": seq, "sentMonotonicNs": at, "sentUnixMillis": r.Ts})
	return nil
}

func (c *client) run(ctx context.Context, s settings, index int, ready chan<- string) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			cmd, err := c.stream.Recv()
			if err != nil {
				select {
				case c.errors <- err:
				default:
				}
				return
			}
			select {
			case c.commands <- cmd:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { c.connection.Close(); <-done }()
	policyVersion := ""
	hb := func(seq int) error {
		return c.send("heartbeat", seq, &pb.Report{Payload: &pb.Report_Heartbeat{Heartbeat: &pb.RptHeartbeat{AgentVersion: "synthetic-fixture", PolicyVersion: policyVersion, GuardStatus: "disabled_synthetic"}}})
	}
	if err := hb(0); err != nil {
		return err
	}
	select {
	case ready <- c.id:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Spread producers across one period to avoid accidental synchronized bursts.
	stagger := time.NewTimer(time.Duration(index%s.HeartbeatSeconds) * time.Second)
	defer stagger.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-stagger.C:
	}
	heartbeats := time.NewTicker(time.Duration(s.HeartbeatSeconds) * time.Second)
	defer heartbeats.Stop()
	logs := time.NewTicker(time.Duration(s.LogSeconds) * time.Second)
	defer logs.Stop()
	heartbeatTicks, logTicks, stop := heartbeats.C, logs.C, s.stopProducers
	hseq, lseq := 0, 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-c.errors:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case <-stop:
			heartbeats.Stop()
			logs.Stop()
			heartbeatTicks, logTicks, stop = nil, nil, nil
			select {
			case s.producersStopped <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
		case <-heartbeatTicks:
			hseq++
			if err := hb(hseq); err != nil {
				return err
			}
		case <-logTicks:
			lseq++
			digest := sha256.Sum256([]byte(s.RunID + "/" + c.id + "/" + strconv.Itoa(lseq)))
			if err := c.send("log", lseq, &pb.Report{Payload: &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{Source: "scale:" + s.RunID, Lines: []*pb.LogLine{{Ts: time.Now().UnixMilli(), Content: "synthetic harmless log 中文 " + strconv.Itoa(lseq), Fields: map[string]string{"timestamp_kind": "observed", "source_event_id": hex.EncodeToString(digest[:])}}}}}}); err != nil {
				return err
			}
		case cmd := <-c.commands:
			if cmd.CmdId == "" {
				return fixtureFailure("unexpected_ephemeral_command")
			}
			if cmd.GetCollectNow() == nil && cmd.GetPolicySync() == nil {
				return fixtureFailure("unexpected_actionable_command")
			}
			if policy := cmd.GetPolicySync(); policy != nil {
				policyVersion = policy.PolicyVersion
			}
			for _, stage := range []pb.RptAck_Stage{pb.RptAck_RECEIVED, pb.RptAck_DONE} {
				if err := c.send("ack", 0, &pb.Report{Payload: &pb.Report_Ack{Ack: &pb.RptAck{CmdId: cmd.CmdId, Stage: stage, Message: "synthetic protocol acknowledgement; no OS action"}}}); err != nil {
					return err
				}
			}
		}
	}
}

func run() error {
	path := flag.String("config", "", "private disposable fixture JSON")
	flag.Parse()
	if os.Getenv("ALINKSEC_SMOKE_ALLOW_FIXTURES") != "true" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return errors.New("disposable hosted-runner fixture gate required")
	}
	b, err := os.ReadFile(*path)
	if err != nil {
		return errors.New("private settings unavailable")
	}
	if len(b) > 65536 {
		return errors.New("settings too large")
	}
	var s settings
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("invalid settings")
	}
	host, _, err := net.SplitHostPort(s.Address)
	if err != nil || host != "127.0.0.1" || s.Clients < 1 || s.Clients > 2000 || s.DurationSeconds < 30 || s.DurationSeconds > 600 || s.HeartbeatSeconds < 1 || s.LogSeconds < s.HeartbeatSeconds || len(s.RunID) != 32 {
		return errors.New("invalid bounded loopback profile")
	}
	if len(s.Addresses) > 2 {
		return errors.New("too many fixture endpoints")
	}
	for _, address := range s.Addresses {
		host, _, err := net.SplitHostPort(address)
		if err != nil || host != "127.0.0.1" {
			return errors.New("non-loopback fixture endpoint")
		}
	}
	if _, err := hex.DecodeString(s.RunID); err != nil {
		return errors.New("invalid run identity")
	}
	ca, err := os.ReadFile(s.CA)
	if err != nil {
		return errors.New("CA unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("invalid pinned CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.DurationSeconds+180)*time.Second)
	defer cancel()
	stopProducers := make(chan struct{})
	producersStopped := make(chan struct{}, s.Clients)
	s.stopProducers, s.producersStopped = stopProducers, producersStopped
	ready := make(chan string, s.Clients)
	errorsCh := make(chan error, s.Clients)
	work := make(chan int)
	var workers, clients sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				c, err := enroll(ctx, s, i, pool)
				if err != nil {
					errorsCh <- err
					continue
				}
				clients.Add(1)
				go func(index int) {
					defer clients.Done()
					if err := c.run(ctx, s, index, ready); err != nil && ctx.Err() == nil {
						errorsCh <- err
					}
				}(i)
			}
		}()
	}
	go func() {
		defer close(work)
		for i := 0; i < s.Clients; i++ {
			select {
			case work <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	ids := make([]string, 0, s.Clients)
	deadline := time.NewTimer(120 * time.Second)
	defer deadline.Stop()
	for len(ids) < s.Clients {
		select {
		case id := <-ready:
			ids = append(ids, id)
		case failure := <-errorsCh:
			cancel()
			workers.Wait()
			clients.Wait()
			return errors.New("synthetic startup failed: " + safeFailure(failure))
		case <-deadline.C:
			cancel()
			workers.Wait()
			clients.Wait()
			return errors.New("synthetic stream startup deadline")
		case <-ctx.Done():
			workers.Wait()
			clients.Wait()
			return ctx.Err()
		}
	}
	workers.Wait()
	emit(map[string]any{"kind": "ready", "agentIds": ids, "clients": len(ids), "realAgents": 0, "realHosts": 0, "startedMonotonicNs": mono()})
	timer := time.NewTimer(time.Duration(s.DurationSeconds) * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-errorsCh:
		cancel()
		clients.Wait()
		return errors.New("synthetic stream failed during sustained window")
	case <-ctx.Done():
		clients.Wait()
		return ctx.Err()
	}
	// Stop periodic producers while retaining streams and final ACK delivery.
	// The independent SQL observer authorizes closure only after durable drain.
	close(stopProducers)
	for range s.Clients {
		select {
		case <-producersStopped:
		case <-errorsCh:
			cancel()
			clients.Wait()
			return errors.New("synthetic stream failed before producer barrier")
		case <-ctx.Done():
			clients.Wait()
			return ctx.Err()
		}
	}
	emit(map[string]any{"kind": "produced", "clients": len(ids), "producedMonotonicNs": mono()})
	stopRequested := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		stopRequested <- scanner.Scan() && scanner.Text() == "stop"
	}()
	drain := time.NewTimer(35 * time.Second)
	defer drain.Stop()
	select {
	case valid := <-stopRequested:
		if !valid {
			cancel()
			clients.Wait()
			return errors.New("SQL observer did not authorize closure")
		}
	case <-drain.C:
		cancel()
		clients.Wait()
		return errors.New("SQL observer drain deadline")
	case <-errorsCh:
		cancel()
		clients.Wait()
		return errors.New("synthetic stream failed during durable drain")
	case <-ctx.Done():
		clients.Wait()
		return ctx.Err()
	}
	cancel()
	clients.Wait()
	select {
	case <-errorsCh:
		return errors.New("synthetic stream error retained at shutdown")
	default:
	}
	emit(map[string]any{"kind": "finished", "sentReports": sent.Load(), "clients": len(ids), "finishedMonotonicNs": mono()})
	return nil
}

func main() {
	if err := run(); err != nil {
		emit(map[string]any{"kind": "error", "code": err.Error()})
		os.Exit(1)
	}
}
