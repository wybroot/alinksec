package comm

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"time"

	"github.com/alinksec/alinksec-agent/internal/identity"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/alinksec/alinksec-agent/internal/virusscan"
	"google.golang.org/protobuf/encoding/protojson"
)

const maxEvidenceBytes = 1 << 20

var evidenceUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func evidenceContract() uint32 {
	if runtime.GOOS == "linux" || runtime.GOOS == "windows" {
		return 1
	}
	return 0
}

// The allowlist consists of runtime counters and the already public heartbeat.
// No arbitrary file, environment, configuration, token, key or command is read.
func (c *Client) diagnosticZIP(request string) ([]byte, error) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	runtimeJSON, err := json.Marshal(map[string]any{
		"format": 1, "requestId": request, "agentId": c.state.AgentID,
		"collectedAt": time.Now().UTC().Format(time.RFC3339Nano), "agentVersion": identity.AgentVersion,
		"os": runtime.GOOS, "arch": runtime.GOARCH, "goVersion": runtime.Version(),
		"goroutines": runtime.NumGoroutine(), "heapAllocatedBytes": memory.HeapAlloc,
		"heapSystemBytes": memory.HeapSys, "gcCycles": memory.NumGC,
	})
	if err != nil {
		return nil, err
	}
	heartbeat, err := protojson.Marshal(c.buildHeartbeat().GetHeartbeat())
	if err != nil || len(heartbeat) > 128<<10 {
		return nil, fmt.Errorf("heartbeat exceeds diagnostic limit")
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"runtime.json", runtimeJSON}, {"heartbeat.json", heartbeat},
		{"README.txt", []byte("Diagnostic contract 1: fixed runtime counters and heartbeat status only. No raw logs, secrets, configuration or arbitrary files are collected. A status reports observed coverage, not proof that protection is complete.\n")},
	} {
		file, err := archive.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Deflate})
		if err != nil {
			return nil, err
		}
		if _, err := file.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	if buffer.Len() > maxEvidenceBytes {
		return nil, fmt.Errorf("diagnostic exceeds limit")
	}
	return buffer.Bytes(), nil
}

func (c *Client) executeEvidence(command *pb.CmdEvidenceCollect, received *pb.RptAck) []*pb.RptAck {
	fail := func(code string) []*pb.RptAck {
		return []*pb.RptAck{received, {CmdId: received.CmdId, Stage: pb.RptAck_FAILED, Code: 1, Message: code}}
	}
	if command == nil || evidenceContract() != 1 || command.ExecutionContract != 1 ||
		!evidenceUUID.MatchString(command.RequestId) || !evidenceUUID.MatchString(received.CmdId) ||
		command.Deadline <= time.Now().UnixMilli() || command.Deadline > time.Now().Add(15*time.Minute).UnixMilli() {
		return fail("invalid_or_expired_evidence_request")
	}
	if command.Kind != "diagnostic" && command.Kind != "quarantine_sample" {
		return fail("unsupported_evidence_kind")
	}
	if command.Kind == "diagnostic" && (command.QuarantineId != "" || command.OriginalPath != "" || command.ExpectedSha256 != "") {
		return fail("invalid_diagnostic_target")
	}
	if previous, err := c.previousEvidence(received.CmdId, command); err != nil {
		return fail("evidence_journal_unavailable")
	} else if previous != nil {
		return []*pb.RptAck{received, previous}
	}
	if !c.beginBulk() {
		return c.resourceBusy(received)
	}
	go func() {
		defer c.bulkBusy.Store(false)
		ctx, cancel := context.WithDeadline(context.Background(), minTime(time.Now().Add(30*time.Second), time.UnixMilli(command.Deadline)))
		defer cancel()
		result := &pb.RptEvidence{RequestId: command.RequestId, CommandId: received.CmdId,
			ExecutionContract: 1, Kind: command.Kind, CollectedAt: time.Now().UnixMilli()}
		var err error
		if command.Kind == "diagnostic" {
			result.Content, err = c.diagnosticZIP(command.RequestId)
		} else {
			result.Content, err = virusscan.NewQuarantine(c.workDir).ExportExpected(ctx,
				command.OriginalPath, command.QuarantineId, command.ExpectedSha256, maxEvidenceBytes)
		}
		if err != nil || ctx.Err() != nil {
			result.Content = nil
			result.ErrorCode = "collection_unavailable_or_limit_exceeded"
		} else {
			sum := sha256.Sum256(result.Content)
			result.Sha256 = hex.EncodeToString(sum[:])
		}
		report := &pb.Report{AgentId: c.state.AgentID, ReportId: command.RequestId + "-evidence", Ts: time.Now().UnixMilli(), Payload: &pb.Report_Evidence{Evidence: result}}
		ack := &pb.RptAck{CmdId: received.CmdId, Stage: pb.RptAck_DONE, Message: "evidence queued for authenticated delivery"}
		// Put the bytes in the offline queue before acknowledging completion. The
		// server marks READY only after validating these bytes, never from ACK.
		if err := c.saveEvidence(command, report); err != nil {
			ack.Stage, ack.Code, ack.Message = pb.RptAck_FAILED, 1, "evidence_journal_unavailable"
		} else if err := c.queue.Push(report); err != nil {
			ack.Stage, ack.Code, ack.Message = pb.RptAck_FAILED, 1, "evidence_queue_unavailable"
		} else if result.ErrorCode != "" {
			ack.Stage, ack.Code, ack.Message = pb.RptAck_FAILED, 1, result.ErrorCode
		}
		c.dedup.Put(received.CmdId, ack)
		c.pushReport(c.wrapAck(ack))
	}()
	return []*pb.RptAck{received, {CmdId: received.CmdId, Stage: pb.RptAck_RUNNING, Message: "bounded evidence collection running"}}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
