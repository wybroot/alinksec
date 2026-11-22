// review-runtime-fixture seeds a harmless production spool record or generates
// synthetic protocol load. It is not an Agent binary.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/comm"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
)

type settings struct {
	Mode, Workdir, ReportID, Source, Address, CA, Token, RecordFile string
	DurationSeconds                                                 int
}

var output sync.Mutex

func emit(value any) {
	output.Lock()
	defer output.Unlock()
	if json.NewEncoder(os.Stdout).Encode(value) != nil {
		panic("fixture output unavailable")
	}
}
func run() error {
	path := flag.String("config", "", "private fixture configuration")
	flag.Parse()
	data, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var cfg settings
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	if cfg.Mode == "spool" {
		state, err := comm.LoadState(cfg.Workdir)
		if err != nil {
			return err
		}
		if state.AgentID == "" {
			return fmt.Errorf("enrolled Agent required")
		}
		queue, err := comm.NewOfflineQueue(cfg.Workdir)
		if err != nil {
			return err
		}
		report := &pb.Report{AgentId: state.AgentID, ReportId: cfg.ReportID, Ts: time.Now().UnixMilli(), Reliable: true, Payload: &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{Source: cfg.Source, Lines: []*pb.LogLine{{Ts: time.Now().UnixMilli(), Content: "harmless runtime crash/replay acceptance", Fields: map[string]string{"timestamp_kind": "observed"}}}}}}
		if cfg.RecordFile != "" {
			if bytes, err := os.ReadFile(cfg.RecordFile); err == nil {
				if err = proto.Unmarshal(bytes, report); err != nil {
					return err
				}
			} else if !os.IsNotExist(err) {
				return err
			}
		}
		bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
		if err != nil {
			return err
		}
		if cfg.RecordFile != "" {
			if err = os.WriteFile(cfg.RecordFile, bytes, 0600); err != nil {
				return err
			}
		}
		if err = queue.Push(report); err != nil {
			return err
		}
		digest := sha256.Sum256(bytes)
		emit(map[string]any{"seeded": true, "agentId": state.AgentID, "reportId": cfg.ReportID, "source": cfg.Source, "sha256": hex.EncodeToString(digest[:]), "bytes": len(bytes)})
		return nil
	}
	if cfg.Mode != "load" || cfg.DurationSeconds < 20 || cfg.DurationSeconds > 120 {
		return fmt.Errorf("bounded load configuration required")
	}
	ca, err := os.ReadFile(cfg.CA)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid CA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.DurationSeconds+15)*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	failures := make(chan error, 2)
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func(index int) { defer workers.Done(); failures <- load(ctx, cfg, pool, index) }(index)
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			return err
		}
	}
	emit(map[string]any{"complete": true, "producers": 2, "durationSeconds": cfg.DurationSeconds})
	return nil
}
func load(ctx context.Context, cfg settings, pool *x509.CertPool, index int) error {
	tlsConfig := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	enrollment, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	rpc, cancel := context.WithTimeout(ctx, 15*time.Second)
	host := fmt.Sprintf("review-load-%d-%d", time.Now().UnixNano(), index)
	identity, err := pb.NewEnrollServiceClient(enrollment).Enroll(rpc, &pb.EnrollRequest{EnrollToken: cfg.Token, Nonce: host, Host: &pb.HostInfo{Hostname: host, MachineId: host, OsType: pb.OsType_OS_LINUX, AgentVersion: "synthetic-runtime-fixture", Arch: "synthetic"}})
	cancel()
	enrollment.Close()
	if err != nil {
		return err
	}
	certificate, err := tls.X509KeyPair(identity.ClientCert, identity.ClientKey)
	if err != nil {
		return err
	}
	tlsConfig.Certificates = []tls.Certificate{certificate}
	connection, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer connection.Close()
	stream, err := pb.NewAgentChannelClient(connection).Channel(ctx)
	if err != nil {
		return err
	}
	receipts := make(chan string, 512)
	go func() {
		for {
			command, err := stream.Recv()
			if err != nil {
				return
			}
			if receipt := command.GetReportReceipt(); receipt != nil && receipt.ReportId != "" {
				emit(map[string]any{"kind": "business-receipt", "agentId": identity.AgentId, "reportId": receipt.ReportId, "at": time.Now().UnixMilli()})
				receipts <- receipt.ReportId
			}
		}
	}()
	agent := identity.AgentId
	if err = stream.Send(&pb.Report{AgentId: agent, ReportId: host, Payload: &pb.Report_Heartbeat{Heartbeat: &pb.RptHeartbeat{ReportReceiptContract: 1}}}); err != nil {
		return err
	}
	batch := &pb.RptMetricsBatch{}
	for i := 0; i < 256; i++ {
		labels := map[string]string{}
		for k := 0; k < 8; k++ {
			labels[fmt.Sprintf("label_%d", k)] = strings.Repeat("x", 800)
		}
		batch.Samples = append(batch.Samples, &pb.MetricSample{Name: "runtime_pressure", Value: float64(i), Ts: time.Now().UnixMilli(), Labels: labels})
	}
	batch.Samples = append(batch.Samples, &pb.MetricSample{Name: "runtime_pressure", Labels: map[string]string{"oversize": strings.Repeat("x", 2000)}})
	start := time.Now()
	count := 0
	expected := map[string]bool{}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for time.Since(start) < time.Duration(cfg.DurationSeconds)*time.Second {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		id := fmt.Sprintf("runtime-load-%d-%d", index, count)
		if err = stream.Send(&pb.Report{AgentId: agent, ReportId: id, Payload: &pb.Report_Metrics{Metrics: batch}}); err != nil {
			return err
		}
		count++
		if count%50 == 0 {
			digest := sha256.Sum256([]byte(id))
			report := &pb.Report{AgentId: agent, ReportId: id + "-log", Reliable: true, Payload: &pb.Report_LogBatch{LogBatch: &pb.RptLogBatch{Source: "runtime-load", Lines: []*pb.LogLine{{Ts: time.Now().UnixMilli(), Content: "harmless concurrent control report", Fields: map[string]string{"source_event_id": hex.EncodeToString(digest[:]), "timestamp_kind": "observed"}}}}}}
			at := time.Now().UnixMilli()
			if err = stream.Send(report); err != nil {
				return err
			}
			expected[report.ReportId] = true
			emit(map[string]any{"kind": "business-sent", "agentId": agent, "reportId": report.ReportId, "at": at})
		}
	}
	elapsed := time.Since(start).Milliseconds()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for len(expected) > 0 {
		select {
		case id := <-receipts:
			delete(expected, id)
		case <-deadline.C:
			return fmt.Errorf("business receipts did not drain")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	emit(map[string]any{"producer": index, "agentId": agent, "batches": count, "samplesPerBatch": len(batch.Samples), "batchBytes": proto.Size(batch), "elapsedMillis": elapsed})
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "runtime fixture failed:", err)
		os.Exit(1)
	}
}
