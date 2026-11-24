//go:build linux

package collector

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func TestKubernetesPodArgsLimitsToNode(t *testing.T) {
	args := kubernetesPodArgs("worker-a")
	want := []string{"get", "pods", "--all-namespaces", "--field-selector", "spec.nodeName=worker-a", "-o", "json"}
	if len(args) != len(want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestContainerSourceStatusMatrixAndInspectFidelity(t *testing.T) {
	oldLook, oldRun, oldHost := lookContainerPath, runContainerCommand, localHostname
	t.Cleanup(func() { lookContainerPath = oldLook; runContainerCommand = oldRun; localHostname = oldHost })

	k8sJSON := `{"items":[{"metadata":{"namespace":"prod","name":"web-1","creationTimestamp":"2026-01-01T00:00:00Z","labels":{"app":"web"}},"status":{"containerStatuses":[{"name":"app","image":"nginx:1.27","imageID":"sha256:img","containerID":"containerd://c1","ready":true,"state":{"running":{"startedAt":"2026-01-01T00:01:00Z"}}}]}}]}`
	dockerPSOne := "cid-1\tweb\tnginx:latest\tUp 2 hours\t0.0.0.0:80->80/tcp\n"
	dockerInspectEmptyUser := "sha256:dimg\t2026-01-01T00:00:00Z\t2026-01-01T00:00:05Z\t{\"env\":\"prod\"}\ttrue\thost\t\n"

	t.Run("both_missing_is_unsupported", func(t *testing.T) {
		lookContainerPath = func(string) (string, error) { return "", exec.ErrNotFound }
		snap := Snapshot([]string{"containers"}, testLogger())
		st := snap.Collections[0]
		if st.Status != pb.AssetCollection_UNSUPPORTED || st.Error != "container_runtime_unavailable" || len(snap.ContainerSources) != 0 {
			t.Fatalf("got %+v sources=%v", st, snap.ContainerSources)
		}
	})

	t.Run("docker_complete_with_empty_user_and_kubectl_missing", func(t *testing.T) {
		lookContainerPath = func(name string) (string, error) {
			if name == "docker" {
				return "/usr/bin/docker", nil
			}
			return "", exec.ErrNotFound
		}
		runContainerCommand = func(_ time.Duration, command string, args ...string) ([]byte, error) {
			if command == "/usr/bin/docker" && len(args) > 0 && args[0] == "ps" {
				return []byte(dockerPSOne), nil
			}
			if command == "/usr/bin/docker" && len(args) > 0 && args[0] == "inspect" {
				return []byte(dockerInspectEmptyUser), nil
			}
			return nil, errors.New("unexpected call")
		}
		snap := Snapshot([]string{"containers"}, testLogger())
		st := snap.Collections[0]
		if st.Status != pb.AssetCollection_PARTIAL || st.Error != "orchestrator_unavailable" {
			t.Fatalf("got %+v", st)
		}
		if !reflect.DeepEqual(snap.ContainerSources, []string{"docker"}) || len(snap.Containers) != 1 {
			t.Fatalf("sources=%v containers=%+v", snap.ContainerSources, snap.Containers)
		}
		got := snap.Containers[0]
		if !got.Risky || !reflect.DeepEqual(got.RiskReasons, []string{"privileged", "host_network", "runs_as_root"}) || got.Labels["env"] != "prod" {
			t.Fatalf("empty Config.User failed risk detection: %+v", got)
		}
	})

	t.Run("k8s_complete_and_docker_missing", func(t *testing.T) {
		lookContainerPath = func(name string) (string, error) {
			if name == "kubectl" {
				return "/usr/bin/kubectl", nil
			}
			return "", exec.ErrNotFound
		}
		localHostname = func() (string, error) { return "node-1", nil }
		runContainerCommand = func(_ time.Duration, command string, _ ...string) ([]byte, error) {
			if command == "/usr/bin/kubectl" {
				return []byte(k8sJSON), nil
			}
			return nil, errors.New("unexpected")
		}
		snap := Snapshot([]string{"containers"}, testLogger())
		st := snap.Collections[0]
		if st.Status != pb.AssetCollection_PARTIAL || st.Error != "runtime_unavailable" {
			t.Fatalf("got %+v", st)
		}
		if !reflect.DeepEqual(snap.ContainerSources, []string{"kubernetes"}) || len(snap.Containers) != 1 || snap.Containers[0].Namespace != "prod" {
			t.Fatalf("sources=%v containers=%+v", snap.ContainerSources, snap.Containers)
		}
	})

	t.Run("both_complete", func(t *testing.T) {
		lookContainerPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
		localHostname = func() (string, error) { return "node-1", nil }
		runContainerCommand = func(_ time.Duration, command string, args ...string) ([]byte, error) {
			if command == "/usr/bin/docker" && args[0] == "ps" {
				return []byte(dockerPSOne), nil
			}
			if command == "/usr/bin/docker" && args[0] == "inspect" {
				return []byte("sha256:dimg\t2026-01-01T00:00:00Z\t2026-01-01T00:00:05Z\t{}\tfalse\tbridge\t1000:1000\n"), nil
			}
			return []byte(k8sJSON), nil
		}
		snap := Snapshot([]string{"containers"}, testLogger())
		st := snap.Collections[0]
		if st.Status != pb.AssetCollection_COMPLETE || st.Error != "" {
			t.Fatalf("got %+v", st)
		}
		if !reflect.DeepEqual(snap.ContainerSources, []string{"docker", "kubernetes"}) || len(snap.Containers) != 2 || snap.Containers[0].Risky {
			t.Fatalf("sources=%v containers=%+v", snap.ContainerSources, snap.Containers)
		}
	})

	t.Run("docker_inspect_failure_excludes_docker_source", func(t *testing.T) {
		for _, badInspect := range []string{"truncated\tonly\tthree", "sha256:d\t2026-01-01T00:00:00Z\t2026-01-01T00:00:05Z\t{bad\tfalse\tbridge\tnonroot"} {
			lookContainerPath = func(name string) (string, error) {
				if name == "docker" {
					return "/usr/bin/docker", nil
				}
				return "", exec.ErrNotFound
			}
			runContainerCommand = func(_ time.Duration, _ string, args ...string) ([]byte, error) {
				if args[0] == "ps" {
					return []byte(dockerPSOne), nil
				}
				return []byte(badInspect), nil
			}
			snap := Snapshot([]string{"containers"}, testLogger())
			st := snap.Collections[0]
			if st.Status != pb.AssetCollection_FAILED || st.Error != "docker_inspect_failed" || len(snap.ContainerSources) != 0 || len(snap.Containers) != 0 {
				t.Fatalf("got status=%+v sources=%v containers=%d", st, snap.ContainerSources, len(snap.Containers))
			}
		}
	})

	t.Run("docker_ps_malformed_and_hostname_failure_and_both_failed", func(t *testing.T) {
		lookContainerPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
		localHostname = func() (string, error) { return "", errors.New("no hostname") }
		runContainerCommand = func(time.Duration, string, ...string) ([]byte, error) {
			return []byte("malformed-line\n"), nil
		}
		snap := Snapshot([]string{"containers"}, testLogger())
		st := snap.Collections[0]
		if st.Status != pb.AssetCollection_FAILED || st.Error != "invalid_runtime_output;node_name_unavailable" || len(st.Error) > 128 {
			t.Fatalf("got %+v", st)
		}
	})
}

func TestContainerCommandStopsAtDeadlineAndCapsOutput(t *testing.T) {
	var out containerOutput
	if _, err := out.Write([]byte(strings.Repeat("a", containerOutputLimit))); err != nil {
		t.Fatal(err)
	}
	if _, err := out.Write([]byte("b")); err == nil {
		t.Fatal("oversized container output accepted")
	}

	start := time.Now()
	if data, err := runContainerCommandWithTimeout(50*time.Millisecond, "/bin/sh", "-c", "sleep 30"); err == nil || len(data) != 0 {
		t.Fatalf("timed-out container command succeeded: len=%d err=%v", len(data), err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("container command deadline did not stop process group in time (%v)", time.Since(start))
	}
}
