//go:build linux

package collector

import (
	"errors"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
	"io"
	"log/slog"
	"testing"
)

func TestContainerSourcesReportIndependentOutcomes(t *testing.T) {
	old := containerCommand
	defer func() { containerCommand = old }()
	for _, tc := range []struct {
		name, docker, kubernetes       string
		failDocker                     bool
		dockerStatus, kubernetesStatus pb.AssetCollectionAttempt_Status
	}{
		{"complete empty", "", `{"items":[]}`, false, pb.AssetCollectionAttempt_COMPLETE, pb.AssetCollectionAttempt_COMPLETE},
		{"permission denied", "", `{"items":[]}`, true, pb.AssetCollectionAttempt_FAILED, pb.AssetCollectionAttempt_COMPLETE},
		{"malformed docker", "unexpected", `{"items":[]}`, false, pb.AssetCollectionAttempt_PARTIAL, pb.AssetCollectionAttempt_COMPLETE},
		{"malformed kubernetes", "", `{}`, false, pb.AssetCollectionAttempt_COMPLETE, pb.AssetCollectionAttempt_FAILED},
	} {
		t.Run(tc.name, func(t *testing.T) {
			containerCommand = func(name string, args ...string) ([]byte, error) {
				if name == "docker" {
					if tc.failDocker {
						return nil, errors.New("denied")
					}
					return []byte(tc.docker), nil
				}
				return []byte(tc.kubernetes), nil
			}
			snap := &pb.RptAssetSnapshot{}
			collectContainersForNode(snap, "worker")
			if len(snap.CollectionAttempts) != 2 || snap.CollectionAttempts[0].Status != tc.dockerStatus || snap.CollectionAttempts[1].Status != tc.kubernetesStatus {
				t.Fatalf("outcomes: %v", snap.CollectionAttempts)
			}
		})
	}
}

func TestDockerTrailingEmptyColumnsRemainValid(t *testing.T) {
	old := containerCommand
	defer func() { containerCommand = old }()
	containerCommand = func(name string, args ...string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte("id\tname\timage\tUp\t\n"), nil
		}
		return []byte("sha\t2026-01-01T00:00:00Z\t2026-01-01T00:00:00Z\t{}\tfalse\tbridge\t\n"), nil
	}
	snap := &pb.RptAssetSnapshot{}
	collectDockerContainers(snap)
	if len(snap.Containers) != 1 || snap.CollectionAttempts[0].Status != pb.AssetCollectionAttempt_COMPLETE {
		t.Fatalf("snapshot: %v", snap)
	}
}

func TestUnreadableShadowDoesNotMeanEmptyPassword(t *testing.T) {
	if hasEmptyPassword(map[string]string{}, "alice") {
		t.Fatal("missing password evidence treated as empty password")
	}
	if !hasEmptyPassword(map[string]string{"alice": ""}, "alice") {
		t.Fatal("actual empty password missed")
	}
}

func TestFailedSnapshotCannotClearAssetsOnLegacyServer(t *testing.T) {
	old := containerCommand
	defer func() { containerCommand = old }()
	containerCommand = func(string, ...string) ([]byte, error) { return nil, errors.New("denied") }
	snap := SnapshotWithKubernetesNode([]string{"containers"}, slog.New(slog.NewTextHandler(io.Discard, nil)), "worker")
	if len(snap.Collected) != 1 || snap.Collected[0] != "collection-contract-1" {
		t.Fatalf("unsafe legacy replacement: %v", snap.Collected)
	}
	if safeForLegacyReplacement(snap, "containers") {
		t.Fatal("failed collection authorizes replacement")
	}
}
