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
		c := &pb.ContainerInfo{ContainerId: parts[0], Name: parts[1], Image: parts[2], Status: parts[3], Orchestrator: "docker"}
		if parts[4] != "" {
			c.Ports = strings.Split(parts[4], ", ")
		}
		fillContainerDetails(c)
		snap.Containers = append(snap.Containers, c)
	}
	collectKubernetesContainers(snap)
}

type podList struct {
	Items []struct {
		Metadata struct {
			Namespace         string            `json:"namespace"`
			Name              string            `json:"name"`
			CreationTimestamp string            `json:"creationTimestamp"`
			Labels            map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			ContainerStatuses []struct {
				Name        string `json:"name"`
				Image       string `json:"image"`
				ImageID     string `json:"imageID"`
				ContainerID string `json:"containerID"`
				Ready       bool   `json:"ready"`
				State       struct {
					Running struct {
						StartedAt string `json:"startedAt"`
					} `json:"running"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

func collectKubernetesContainers(snap *pb.RptAssetSnapshot) {
	out, err := exec.Command("kubectl", "get", "pods", "--all-namespaces", "-o", "json").Output()
	if err != nil {
		return
	}
	var pods podList
	if json.Unmarshal(out, &pods) != nil {
		return
	}
	for _, pod := range pods.Items {
		for _, status := range pod.Status.ContainerStatuses {
			id := status.ContainerID
			if id == "" {
				id = pod.Metadata.Namespace + "/" + pod.Metadata.Name + "/" + status.Name
			}
			state := "not_ready"
			if status.Ready {
				state = "running"
			}
			snap.Containers = append(snap.Containers, &pb.ContainerInfo{ContainerId: id, Name: pod.Metadata.Name + "/" + status.Name, Image: status.Image, ImageId: status.ImageID, Status: state, CreatedAt: dockerTime(pod.Metadata.CreationTimestamp), StartedAt: dockerTime(status.State.Running.StartedAt), Labels: pod.Metadata.Labels, Orchestrator: "kubernetes", Namespace: pod.Metadata.Namespace})
		}
	}
}

func fillContainerDetails(c *pb.ContainerInfo) {
	out, err := exec.Command("docker", "inspect", "--format", "{{.Image}}\t{{.Created}}\t{{.State.StartedAt}}\t{{json .Config.Labels}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.NetworkMode}}\t{{.Config.User}}", c.ContainerId).Output()
	if err != nil {
		return
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "\t", 7)
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
	if len(parts) > 4 && parts[4] == "true" {
		c.Risky, c.RiskReasons = true, append(c.RiskReasons, "privileged")
	}
	if len(parts) > 5 && parts[5] == "host" {
		c.Risky, c.RiskReasons = true, append(c.RiskReasons, "host_network")
	}
	if len(parts) > 6 && (parts[6] == "" || parts[6] == "0" || parts[6] == "root") {
		c.Risky, c.RiskReasons = true, append(c.RiskReasons, "runs_as_root")
	}
}

func dockerTime(value string) int64 {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}
