package collector

import (
	"errors"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"io"
	"log/slog"
	"testing"
)

func TestEnumerationFailureIsNotSuccessfulEmptyInventory(t *testing.T) {
	oldPorts, oldProcesses := listConnections, listProcesses
	t.Cleanup(func() { listConnections = oldPorts; listProcesses = oldProcesses })
	listConnections = func(string) ([]gnet.ConnectionStat, error) { return nil, errors.New("injected") }
	listProcesses = func() ([]*process.Process, error) { return nil, errors.New("injected") }
	snap := Snapshot([]string{"ports", "processes"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(snap.Collections) != 2 {
		t.Fatalf("statuses: %v", snap.Collections)
	}
	for _, state := range snap.Collections {
		if state.Status != pb.AssetCollection_FAILED || state.Error == "" {
			t.Fatalf("failure became empty success: %v", state)
		}
	}
	listConnections = func(string) ([]gnet.ConnectionStat, error) { return nil, nil }
	listProcesses = func() ([]*process.Process, error) { return nil, nil }
	empty := Snapshot([]string{"ports", "processes"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, state := range empty.Collections {
		if state.Status != pb.AssetCollection_COMPLETE {
			t.Fatalf("true empty snapshot must remain complete: %v", state)
		}
	}
}
