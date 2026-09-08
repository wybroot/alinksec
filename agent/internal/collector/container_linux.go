//go:build linux

package collector

import (
	"encoding/json"
	"os/exec"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// collectContainers uses Docker's CLI rather than its socket. This preserves a
// read-only integration boundary and gracefully does nothing when unavailable.
func collectContainers(snap *pb.RptAssetSnapshot) {
	out, err := exec.Command("docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 5 || parts[0] == "" {
			continue
		}
		c := &pb.ContainerInfo{ContainerId: parts[0], Name: parts[1], Image: parts[2], Status: parts[3]}
		if parts[4] != "" {
			c.Ports = strings.Split(parts[4], ", ")
		}
		fillContainerDetails(c)
		snap.Containers = append(snap.Containers, c)
	}
}

func fillContainerDetails(c *pb.ContainerInfo) {
	out, err := exec.Command("docker", "inspect", "--format", "{{.Image}}\t{{.Created}}\t{{.State.StartedAt}}\t{{json .Config.Labels}}", c.ContainerId).Output()
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "\t", 4)
	if len(parts) > 0 {
		c.ImageId = parts[0]
	}
	if len(parts) > 1 {
		c.CreatedAt = dockerTime(parts[1])
	}
	if len(parts) > 2 {
		c.StartedAt = dockerTime(parts[2])
	}
	if len(parts) > 3 {
		_ = json.Unmarshal([]byte(parts[3]), &c.Labels)
	}
}

func dockerTime(value string) int64 {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}
