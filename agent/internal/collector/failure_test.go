package collector

import (
	"errors"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"google.golang.org/protobuf/proto"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestEnumerationFailureIsNotSuccessfulEmptyInventory(t *testing.T) {
	oldPorts, oldProcesses, oldDisks := listConnections, listProcesses, listPartitions
	t.Cleanup(func() { listConnections = oldPorts; listProcesses = oldProcesses; listPartitions = oldDisks })
	self, err := process.NewProcess(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	listConnections = func(string) ([]gnet.ConnectionStat, error) {
		return []gnet.ConnectionStat{{Status: "LISTEN", Laddr: gnet.Addr{IP: "127.0.0.1", Port: 4443}, Pid: self.Pid}}, nil
	}
	listProcesses = func() ([]*process.Process, error) { return []*process.Process{self}, nil }
	mount := t.TempDir()
	listPartitions = func(bool) ([]disk.PartitionStat, error) {
		return []disk.PartitionStat{{Mountpoint: mount, Fstype: "fixture"}}, nil
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	complete := Snapshot([]string{"ports", "processes", "disks"}, logger)
	if len(complete.Ports) != 1 || len(complete.Processes) != 1 || len(complete.Disks) != 1 || complete.Processes[0].Name == "" {
		t.Fatalf("missing initial nonempty enumeration: %v", complete)
	}
	for _, state := range complete.Collections {
		if state.Status != pb.AssetCollection_COMPLETE {
			t.Fatalf("initial status: %v", state)
		}
	}
	listConnections = func(string) ([]gnet.ConnectionStat, error) { return nil, errors.New("injected") }
	listProcesses = func() ([]*process.Process, error) { return nil, errors.New("injected") }
	listPartitions = func(bool) ([]disk.PartitionStat, error) { return nil, errors.New("injected") }
	snap := Snapshot([]string{"ports", "processes", "disks"}, logger)
	if len(snap.Collections) != 3 || len(snap.Ports)+len(snap.Processes)+len(snap.Disks) != 0 {
		t.Fatalf("statuses: %v", snap.Collections)
	}
	for _, state := range snap.Collections {
		if state.Status != pb.AssetCollection_FAILED || state.Error == "" {
			t.Fatalf("failure became empty success: %v", state)
		}
	}
	listConnections = func(string) ([]gnet.ConnectionStat, error) { return nil, nil }
	listProcesses = func() ([]*process.Process, error) { return nil, nil }
	listPartitions = func(bool) ([]disk.PartitionStat, error) { return nil, nil }
	empty := Snapshot([]string{"ports", "processes", "disks"}, logger)
	for _, state := range empty.Collections {
		if state.Status != pb.AssetCollection_COMPLETE {
			t.Fatalf("true empty snapshot must remain complete: %v", state)
		}
	}
	if directory := os.Getenv("ALINKSEC_ASSET_COLLECTOR_FIXTURES"); directory != "" {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		for name, snapshot := range map[string]*pb.RptAssetSnapshot{"complete": complete, "failed": snap, "empty": empty} {
			data, err := proto.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, name+".pb"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
