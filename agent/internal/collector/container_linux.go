//go:build linux

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const (
	containerQueryTimeout   = 10 * time.Second
	containerInspectTimeout = 5 * time.Second
	containerOutputLimit    = 8 << 20
)

type containerSourceOutcome int

const (
	containerSourceComplete containerSourceOutcome = iota
	containerSourceMissing
	containerSourceFailed
)

type containerSourceResult struct {
	status containerSourceOutcome
	reason string
}

type containerOutput struct{ strings.Builder }

func (out *containerOutput) Write(p []byte) (int, error) {
	if len(p) > containerOutputLimit-out.Len() {
		return 0, errors.New("container output limit exceeded")
	}
	return out.Builder.Write(p)
}

func runContainerCommandWithTimeout(timeout time.Duration, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var output containerOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return []byte(output.String()), nil
}

var lookContainerPath = exec.LookPath
var runContainerCommand = runContainerCommandWithTimeout
var localHostname = os.Hostname

// collectContainers retains the default local-node behavior for callers outside
// Snapshot. Docker and Kubernetes probes intentionally remain independent.
func collectContainers(snap *pb.RptAssetSnapshot) {
	collectContainersForNode(snap, "")
}

// collectContainersForNode reads only local runtime and host-local Kubernetes
// context. Neither source can block the other when unavailable.
func collectContainersForNode(snap *pb.RptAssetSnapshot, kubernetesNodeName string) {
	dockerRes := collectDockerContainers(snap)
	k8sRes := collectKubernetesContainers(snap, kubernetesNodeName)
	status, reason := combineContainerResults(dockerRes, k8sRes)
	collectionStatus(snap, "containers", status, reason)
}

func combineContainerResults(dockerRes, k8sRes containerSourceResult) (pb.AssetCollection_Status, string) {
	switch {
	case dockerRes.status == containerSourceComplete && k8sRes.status == containerSourceComplete:
		return pb.AssetCollection_COMPLETE, ""
	case dockerRes.status == containerSourceMissing && k8sRes.status == containerSourceMissing:
		return pb.AssetCollection_UNSUPPORTED, "container_runtime_unavailable"
	case dockerRes.status == containerSourceComplete:
		return pb.AssetCollection_PARTIAL, k8sRes.reason
	case k8sRes.status == containerSourceComplete:
		return pb.AssetCollection_PARTIAL, dockerRes.reason
	case dockerRes.status == containerSourceFailed && k8sRes.status == containerSourceFailed:
		if dockerRes.reason == k8sRes.reason {
			return pb.AssetCollection_FAILED, dockerRes.reason
		}
		return pb.AssetCollection_FAILED, dockerRes.reason + ";" + k8sRes.reason
	case dockerRes.status == containerSourceFailed:
		return pb.AssetCollection_FAILED, dockerRes.reason
	default:
		return pb.AssetCollection_FAILED, k8sRes.reason
	}
}

func collectDockerContainers(snap *pb.RptAssetSnapshot) containerSourceResult {
	path, err := lookContainerPath("docker")
	if errors.Is(err, exec.ErrNotFound) {
		return containerSourceResult{status: containerSourceMissing, reason: "runtime_unavailable"}
	}
	if err != nil {
		return containerSourceResult{status: containerSourceFailed, reason: "runtime_lookup_failed"}
	}
	out, err := runContainerCommand(containerQueryTimeout, path, "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
	if err != nil {
		return containerSourceResult{status: containerSourceFailed, reason: "runtime_query_failed"}
	}
	trimmed := strings.TrimRight(string(out), "\r\n")
	var items []*pb.ContainerInfo
	if trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			if line == "" {
				continue
			}
			parts := strings.Split(strings.TrimRight(line, "\r"), "\t")
			if len(parts) != 5 || strings.TrimSpace(parts[0]) == "" {
				return containerSourceResult{status: containerSourceFailed, reason: "invalid_runtime_output"}
			}
			c := &pb.ContainerInfo{ContainerId: parts[0], Name: parts[1], Image: parts[2], Status: parts[3], Orchestrator: "docker"}
			if parts[4] != "" {
				c.Ports = strings.Split(parts[4], ", ")
			}
			if err := fillContainerDetails(path, c); err != nil {
				return containerSourceResult{status: containerSourceFailed, reason: "docker_inspect_failed"}
			}
			items = append(items, c)
		}
	}
	snap.ContainerSources = append(snap.ContainerSources, "docker")
	snap.Containers = append(snap.Containers, items...)
	return containerSourceResult{status: containerSourceComplete}
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

func collectKubernetesContainers(snap *pb.RptAssetSnapshot, configuredNodeName string) containerSourceResult {
	path, err := lookContainerPath("kubectl")
	if errors.Is(err, exec.ErrNotFound) {
		return containerSourceResult{status: containerSourceMissing, reason: "orchestrator_unavailable"}
	}
	if err != nil {
		return containerSourceResult{status: containerSourceFailed, reason: "orchestrator_lookup_failed"}
	}
	nodeName := strings.TrimSpace(configuredNodeName)
	if nodeName == "" {
		nodeName, err = localHostname()
		nodeName = strings.TrimSpace(nodeName)
		if err != nil || nodeName == "" {
			return containerSourceResult{status: containerSourceFailed, reason: "node_name_unavailable"}
		}
	}
	out, err := runContainerCommand(containerQueryTimeout, path, kubernetesPodArgs(nodeName)...)
	if err != nil {
		return containerSourceResult{status: containerSourceFailed, reason: "orchestrator_query_failed"}
	}
	var pods podList
	if json.Unmarshal(out, &pods) != nil {
		return containerSourceResult{status: containerSourceFailed, reason: "invalid_orchestrator_output"}
	}
	var items []*pb.ContainerInfo
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
			items = append(items, &pb.ContainerInfo{
				ContainerId:  id,
				Name:         pod.Metadata.Name + "/" + status.Name,
				Image:        status.Image,
				ImageId:      status.ImageID,
				Status:       state,
				CreatedAt:    dockerTime(pod.Metadata.CreationTimestamp),
				StartedAt:    dockerTime(status.State.Running.StartedAt),
				Labels:       pod.Metadata.Labels,
				Orchestrator: "kubernetes",
				Namespace:    pod.Metadata.Namespace,
			})
		}
	}
	snap.ContainerSources = append(snap.ContainerSources, "kubernetes")
	snap.Containers = append(snap.Containers, items...)
	return containerSourceResult{status: containerSourceComplete}
}

func kubernetesPodArgs(nodeName string) []string {
	return []string{"get", "pods", "--all-namespaces", "--field-selector", "spec.nodeName=" + nodeName, "-o", "json"}
}

func fillContainerDetails(dockerPath string, c *pb.ContainerInfo) error {
	out, err := runContainerCommand(containerInspectTimeout, dockerPath, "inspect", "--format", "{{.Image}}\t{{.Created}}\t{{.State.StartedAt}}\t{{json .Config.Labels}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.NetworkMode}}\t{{.Config.User}}", c.ContainerId)
	if err != nil {
		return err
	}
	// Preserve a trailing empty tab column when Config.User is unset (default root).
	raw := strings.TrimRight(string(out), "\r\n")
	parts := strings.Split(raw, "\t")
	if len(parts) != 7 {
		return errors.New("invalid docker inspect output")
	}
	c.ImageId = strings.TrimSpace(parts[0])
	c.CreatedAt = dockerTime(strings.TrimSpace(parts[1]))
	c.StartedAt = dockerTime(strings.TrimSpace(parts[2]))
	if labelsRaw := strings.TrimSpace(parts[3]); labelsRaw != "" && labelsRaw != "null" {
		if err := json.Unmarshal([]byte(labelsRaw), &c.Labels); err != nil {
			return err
		}
	}
	privileged := strings.TrimSpace(parts[4])
	if privileged != "true" && privileged != "false" {
		return errors.New("invalid privileged flag")
	}
	if privileged == "true" {
		c.Risky, c.RiskReasons = true, append(c.RiskReasons, "privileged")
	}
	if strings.TrimSpace(parts[5]) == "host" {
		c.Risky, c.RiskReasons = true, append(c.RiskReasons, "host_network")
	}
	userPart := strings.TrimSpace(strings.SplitN(parts[6], ":", 2)[0])
	if userPart == "" || userPart == "0" || userPart == "root" {
		c.Risky, c.RiskReasons = true, append(c.RiskReasons, "runs_as_root")
	}
	return nil
}

func dockerTime(value string) int64 {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}
