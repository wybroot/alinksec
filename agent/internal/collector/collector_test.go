package collector

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"runtime"
	"syscall"
	"testing"

	"github.com/shirou/gopsutil/v4/disk"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestRedactCommandLine(t *testing.T) {
	got := redactCommandLine([]string{
		"worker", "--token=secret-value", "--password", "p@ss", "--mode=scan",
	})
	want := "worker --token=*** --password *** --mode=scan"
	if got != want {
		t.Fatalf("redactCommandLine() = %q, want %q", got, want)
	}
}

func TestRedactCommandLineMasksPrefixedCredentials(t *testing.T) {
	got := redactCommandLine([]string{
		"worker", "--db-password=hunter2", "--access_key", "AKIA...", "--mode=scan",
	})
	want := "worker --db-password=*** --access_key *** --mode=scan"
	if got != want {
		t.Fatalf("redactCommandLine() = %q, want %q", got, want)
	}
}

func TestSnapshotMarksOnlyRequestedCollectors(t *testing.T) {
	selected := selectedTasks([]string{"processes"})
	if len(selected) != 1 || selected[0].name != "processes" {
		t.Fatalf("selected = %v, want [processes]", selected)
	}
}

type fakeProcessReader struct {
	pid     int32
	name    string
	nameErr error
	exe     string
	exeErr  error
	cmd     []string
	cmdErr  error
	user    string
	userErr error
	rss     uint64
	memErr  error
}

func (f fakeProcessReader) PID() int32                    { return f.pid }
func (f fakeProcessReader) Name() (string, error)         { return f.name, f.nameErr }
func (f fakeProcessReader) Exe() (string, error)          { return f.exe, f.exeErr }
func (f fakeProcessReader) CmdlineSlice() ([]string, error) { return f.cmd, f.cmdErr }
func (f fakeProcessReader) Username() (string, error)     { return f.user, f.userErr }
func (f fakeProcessReader) MemoryInfo() (*process.MemoryInfoStat, error) {
	if f.memErr != nil {
		return nil, f.memErr
	}
	return &process.MemoryInfoStat{RSS: f.rss}, nil
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestCollectPortsAttributesProcessAndMarksIncomplete(t *testing.T) {
	oldConns, oldLookup := listConnections, lookupPortProcess
	t.Cleanup(func() { listConnections = oldConns; lookupPortProcess = oldLookup })

	t.Run("healthy_and_cached_and_ignores_non_listen", func(t *testing.T) {
		calls := 0
		listConnections = func(string) ([]gnet.ConnectionStat, error) {
			return []gnet.ConnectionStat{
				{Type: syscall.SOCK_STREAM, Status: "ESTABLISHED", Laddr: gnet.Addr{IP: "10.0.0.2", Port: 50000}, Pid: 0},
				{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "0.0.0.0", Port: 443}, Pid: 42},
				{Type: syscall.SOCK_DGRAM, Status: "NONE", Laddr: gnet.Addr{IP: "::", Port: 5353}, Pid: 42},
			}, nil
		}
		lookupPortProcess = func(pid int32) (string, error) {
			calls++
			if pid != 42 {
				t.Fatalf("unexpected pid lookup %d", pid)
			}
			return "nginx", nil
		}
		snap := Snapshot([]string{"ports"}, testLogger())
		if calls != 1 {
			t.Fatalf("lookup calls = %d, want 1", calls)
		}
		if snap.Collections[0].Status != pb.AssetCollection_COMPLETE || snap.Collections[0].Error != "" {
			t.Fatalf("unexpected collection status: %+v", snap.Collections[0])
		}
		if len(snap.Ports) != 2 || snap.Ports[0].Protocol != "tcp" || snap.Ports[1].Protocol != "udp6" ||
			snap.Ports[0].Process != "nginx" || snap.Ports[1].Process != "nginx" {
			t.Fatalf("unexpected ports: %+v", snap.Ports)
		}
	})

	t.Run("pid_zero_unattributed", func(t *testing.T) {
		listConnections = func(string) ([]gnet.ConnectionStat, error) {
			return []gnet.ConnectionStat{{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "127.0.0.1", Port: 80}, Pid: 0}}, nil
		}
		snap := Snapshot([]string{"ports"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "port_process_unattributed" {
			t.Fatalf("got %+v, want partial port_process_unattributed", snap.Collections[0])
		}
		if len(snap.Ports) != 1 || snap.Ports[0].Process != "" {
			t.Fatalf("unexpected ports: %+v", snap.Ports)
		}
	})

	t.Run("permission_denied_cached_across_sockets", func(t *testing.T) {
		calls := 0
		listConnections = func(string) ([]gnet.ConnectionStat, error) {
			return []gnet.ConnectionStat{
				{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "0.0.0.0", Port: 22}, Pid: 100},
				{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "::", Port: 2222}, Pid: 100},
			}, nil
		}
		lookupPortProcess = func(int32) (string, error) {
			calls++
			return "", fmt.Errorf("could not get Name: %w", os.ErrPermission)
		}
		snap := Snapshot([]string{"ports"}, testLogger())
		if calls != 1 {
			t.Fatalf("lookup calls = %d, want 1", calls)
		}
		if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "port_process_permission_denied" {
			t.Fatalf("got %+v, want permission denied", snap.Collections[0])
		}
		if len(snap.Ports) != 2 {
			t.Fatalf("expected both partial port rows retained: %+v", snap.Ports)
		}
	})

	t.Run("wrapped_windows_access_denied", func(t *testing.T) {
		listConnections = func(string) ([]gnet.ConnectionStat, error) {
			return []gnet.ConnectionStat{{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "127.0.0.1", Port: 135}, Pid: 7}}, nil
		}
		lookupPortProcess = func(int32) (string, error) {
			return "", errors.New("could not get Name: Access is denied.")
		}
		snap := Snapshot([]string{"ports"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "port_process_permission_denied" {
			t.Fatalf("got %+v", snap.Collections[0])
		}
	})

	t.Run("lookup_failed_and_empty_name", func(t *testing.T) {
		for _, err := range []error{errors.New("stat failed"), errEmptyProcessName} {
			listConnections = func(string) ([]gnet.ConnectionStat, error) {
				return []gnet.ConnectionStat{{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "127.0.0.1", Port: 8080}, Pid: 88}}, nil
			}
			lookupPortProcess = func(int32) (string, error) { return "", err }
			snap := Snapshot([]string{"ports"}, testLogger())
			if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "port_process_lookup_failed" {
				t.Fatalf("got %+v for err %v", snap.Collections[0], err)
			}
		}
	})

	t.Run("error_precedence", func(t *testing.T) {
		listConnections = func(string) ([]gnet.ConnectionStat, error) {
			return []gnet.ConnectionStat{
				{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "0.0.0.0", Port: 81}, Pid: 11},
				{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "0.0.0.0", Port: 82}, Pid: 0},
				{Type: syscall.SOCK_STREAM, Status: "LISTEN", Laddr: gnet.Addr{IP: "0.0.0.0", Port: 83}, Pid: 12},
			}, nil
		}
		lookupPortProcess = func(pid int32) (string, error) {
			if pid == 12 {
				return "", os.ErrPermission
			}
			return "", errors.New("not found")
		}
		snap := Snapshot([]string{"ports"}, testLogger())
		if snap.Collections[0].Error != "port_process_permission_denied" {
			t.Fatalf("expected permission denied precedence, got %+v", snap.Collections[0])
		}

		lookupPortProcess = func(int32) (string, error) { return "", errors.New("not found") }
		snap = Snapshot([]string{"ports"}, testLogger())
		if snap.Collections[0].Error != "port_process_unattributed" {
			t.Fatalf("expected unattributed precedence over lookup failure, got %+v", snap.Collections[0])
		}
	})
}

func TestCollectProcessesDistinguishesVanishedKernelAndFieldFailures(t *testing.T) {
	oldReaders := listProcessReaders
	t.Cleanup(func() { listProcessReaders = oldReaders })

	t.Run("vanished_kernel_thread_and_unmapped_uid_remain_complete", func(t *testing.T) {
		listProcessReaders = func() ([]processReader, error) {
			return []processReader{
				fakeProcessReader{pid: 10, name: "worker", exe: "/usr/bin/worker", cmd: []string{"worker", "--token=secret"}, user: "svc", rss: 2048},
				fakeProcessReader{pid: 11, nameErr: process.ErrorProcessNotRunning},
				fakeProcessReader{pid: 12, name: "shortlived", cmd: []string{"shortlived"}, rss: 100, exeErr: syscall.ESRCH},
				fakeProcessReader{pid: 2, name: "kworker/0:1", user: "root", rss: 0, exeErr: &os.PathError{Op: "readlink", Path: "/proc/2/exe", Err: os.ErrNotExist}},
				fakeProcessReader{pid: 100, name: "container-app", exe: "/app/bin", userErr: user.UnknownUserIdError(10001), rss: 4096},
			}, nil
		}
		snap := Snapshot([]string{"processes"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_COMPLETE || snap.Collections[0].Error != "" {
			t.Fatalf("unexpected status: %+v", snap.Collections[0])
		}
		if len(snap.Processes) != 3 {
			t.Fatalf("got %d processes, want 3: %+v", len(snap.Processes), snap.Processes)
		}
		if snap.Processes[0].Cmdline != "worker --token=***" || snap.Processes[1].Exe != "" || snap.Processes[2].User != "uid:10001" {
			t.Fatalf("unexpected process rows: %+v", snap.Processes)
		}
	})

	t.Run("permission_failures_on_fields", func(t *testing.T) {
		cases := []struct {
			label string
			proc  fakeProcessReader
		}{
			{"name", fakeProcessReader{pid: 21, nameErr: errors.New("could not get Name: Access is denied.")}},
			{"exe", fakeProcessReader{pid: 22, name: "secret", exeErr: os.ErrPermission}},
			{"cmdline", fakeProcessReader{pid: 23, name: "secret", exe: "/bin/secret", cmdErr: syscall.EACCES}},
			{"user", fakeProcessReader{pid: 24, name: "secret", exe: "/bin/secret", userErr: process.ErrorNotPermitted}},
			{"mem", fakeProcessReader{pid: 25, name: "secret", exe: "/bin/secret", memErr: os.ErrPermission}},
		}
		for _, tc := range cases {
			t.Run(tc.label, func(t *testing.T) {
				listProcessReaders = func() ([]processReader, error) { return []processReader{tc.proc}, nil }
				snap := Snapshot([]string{"processes"}, testLogger())
				if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "process_fields_permission_denied" {
					t.Fatalf("%s: got %+v", tc.label, snap.Collections[0])
				}
				if len(snap.Processes) != 1 || snap.Processes[0].Pid != tc.proc.pid {
					t.Fatalf("%s: expected partial row retained: %+v", tc.label, snap.Processes)
				}
			})
		}
	})

	t.Run("generic_error_and_empty_name", func(t *testing.T) {
		for _, p := range []fakeProcessReader{
			{pid: 31, name: "  "},
			{pid: 32, name: "broken", exeErr: errors.New("corrupt link")},
			{pid: 33, name: "broken", memErr: errors.New("unreadable statm")},
		} {
			listProcessReaders = func() ([]processReader, error) { return []processReader{p}, nil }
			snap := Snapshot([]string{"processes"}, testLogger())
			if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "process_fields_incomplete" {
				t.Fatalf("got %+v for %+v", snap.Collections[0], p)
			}
		}
	})

	if runtime.GOOS == "windows" {
		t.Run("windows_kernel_pseudo_processes_do_not_degrade", func(t *testing.T) {
			listProcessReaders = func() ([]processReader, error) {
				return []processReader{
					fakeProcessReader{pid: 0, name: "System Idle Process", exeErr: os.ErrPermission, cmdErr: os.ErrPermission, userErr: os.ErrPermission, memErr: os.ErrPermission},
					fakeProcessReader{pid: 4, name: "System", exeErr: os.ErrPermission, cmdErr: os.ErrPermission, userErr: os.ErrPermission, memErr: os.ErrPermission},
				}, nil
			}
			snap := Snapshot([]string{"processes"}, testLogger())
			if snap.Collections[0].Status != pb.AssetCollection_COMPLETE || len(snap.Processes) != 2 {
				t.Fatalf("unexpected Windows pseudo process handling: status=%+v rows=%+v", snap.Collections[0], snap.Processes)
			}
		})
	}
}

func TestCollectDisksMarksUnreadableInvalidAndDeduplicatesMounts(t *testing.T) {
	oldParts, oldUsage := listPartitions, diskUsage
	t.Cleanup(func() { listPartitions = oldParts; diskUsage = oldUsage })

	t.Run("deduplicates_duplicate_mounts", func(t *testing.T) {
		listPartitions = func(bool) ([]disk.PartitionStat, error) {
			return []disk.PartitionStat{
				{Mountpoint: "/data", Fstype: "ext4"},
				{Mountpoint: "/data", Fstype: "ext4"},
			}, nil
		}
		diskUsage = func(string) (*disk.UsageStat, error) {
			return &disk.UsageStat{Total: 1000, Used: 400}, nil
		}
		snap := Snapshot([]string{"disks"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_COMPLETE || len(snap.Disks) != 1 {
			t.Fatalf("unexpected disks result: status=%+v disks=%+v", snap.Collections[0], snap.Disks)
		}
	})

	t.Run("unreadable_and_zero_total", func(t *testing.T) {
		listPartitions = func(bool) ([]disk.PartitionStat, error) {
			return []disk.PartitionStat{
				{Mountpoint: "/ok", Fstype: "ext4"},
				{Mountpoint: "/zero", Fstype: "ext4"},
				{Mountpoint: "/err", Fstype: "ext4"},
			}, nil
		}
		diskUsage = func(m string) (*disk.UsageStat, error) {
			switch m {
			case "/ok":
				return &disk.UsageStat{Total: 500, Used: 100}, nil
			case "/zero":
				return &disk.UsageStat{Total: 0, Used: 0}, nil
			default:
				return nil, os.ErrPermission
			}
		}
		snap := Snapshot([]string{"disks"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "mount_unreadable" || len(snap.Disks) != 1 {
			t.Fatalf("got status=%+v disks=%+v", snap.Collections[0], snap.Disks)
		}
	})

	t.Run("used_exceeds_total_and_blank_mount", func(t *testing.T) {
		listPartitions = func(bool) ([]disk.PartitionStat, error) {
			return []disk.PartitionStat{
				{Mountpoint: "", Fstype: "ext4"},
				{Mountpoint: "/bad", Fstype: "ext4"},
				{Mountpoint: "/ok", Fstype: "ext4"},
			}, nil
		}
		diskUsage = func(m string) (*disk.UsageStat, error) {
			if m == "/bad" {
				return &disk.UsageStat{Total: 100, Used: 200}, nil
			}
			return &disk.UsageStat{Total: 1000, Used: 100}, nil
		}
		snap := Snapshot([]string{"disks"}, testLogger())
		if snap.Collections[0].Status != pb.AssetCollection_PARTIAL || snap.Collections[0].Error != "invalid_mount_usage" ||
			len(snap.Disks) != 1 || snap.Disks[0].Mount != "/ok" {
			t.Fatalf("got status=%+v disks=%+v", snap.Collections[0], snap.Disks)
		}
	})
}
