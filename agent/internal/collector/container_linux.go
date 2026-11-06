//go:build linux

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const (
	maxContainerOutputBytes = 4 * 1024 * 1024 // 4 MiB output protection limit (G17)
	maxContainersPerSource  = 200             // Max container count budget per source
	dockerTotalBudget       = 30 * time.Second
	kubernetesTotalBudget   = 30 * time.Second
)

// collectContainers retains the default local-node behavior for callers outside
// Snapshot. Docker and Kubernetes probes intentionally remain independent.
func collectContainers(snap *pb.RptAssetSnapshot) {
	collectContainersForNode(snap, "")
}

// collectContainersForNode reads only local runtime and host-local Kubernetes
// context. Neither source can block the other when unavailable.
func collectContainersForNode(snap *pb.RptAssetSnapshot, kubernetesNodeName string) {
	collectDockerContainers(snap)
	collectKubernetesContainers(snap, kubernetesNodeName)
}

func collectDockerContainers(snap *pb.RptAssetSnapshot) {
	deadline := time.Now().Add(dockerTotalBudget)
	out, err := containerCommand("docker", "ps", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}")
	if err != nil {
		recordAttempt(snap, "docker", pb.AssetCollectionAttempt_FAILED, "docker_list_failed")
		return
	}
	recordAttempt(snap, "docker", pb.AssetCollectionAttempt_COMPLETE, "")
	lines := strings.Split(strings.TrimRight(string(out), "\r\n"), "\n")
	budgetExhausted := false
	if len(lines) > maxContainersPerSource {
		lines = lines[:maxContainersPerSource]
		budgetExhausted = true
	}
	for _, line := range lines {
		if line == "" {
			continue
		}
		if time.Now().After(deadline) {
			recordAttempt(snap, "docker", pb.AssetCollectionAttempt_PARTIAL, "container_time_budget_exhausted")
			break
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 5 || parts[0] == "" {
			recordAttempt(snap, "docker", pb.AssetCollectionAttempt_PARTIAL, "docker_list_invalid")
			continue
		}
		c := &pb.ContainerInfo{ContainerId: parts[0], Name: parts[1], Image: parts[2], Status: parts[3], Orchestrator: "docker"}
		if parts[4] != "" {
			c.Ports = strings.Split(parts[4], ", ")
		}
		if err := fillContainerDetails(c); err != nil {
			recordAttempt(snap, "docker", pb.AssetCollectionAttempt_PARTIAL, "docker_inspect_failed")
		}
		snap.Containers = append(snap.Containers, c)
	}
	if budgetExhausted && len(snap.Containers) >= maxContainersPerSource {
		recordAttempt(snap, "docker", pb.AssetCollectionAttempt_PARTIAL, "container_count_budget_exhausted")
	}
}

type podList struct {
	Items []struct {
		Metadata struct {
			Namespace         string            `json:"namespace"`
			Name              string            `json:"name"`
			CreationTimestamp string            `json:"creationTimestamp"`
			Labels            map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			HostNetwork     bool `json:"hostNetwork"`
			HostPID         bool `json:"hostPID"`
			HostIPC         bool `json:"hostIPC"`
			SecurityContext *struct {
				RunAsUser    *int64 `json:"runAsUser"`
				RunAsNonRoot *bool  `json:"runAsNonRoot"`
			} `json:"securityContext"`
			Containers []struct {
				Name            string `json:"name"`
				SecurityContext *struct {
					Privileged               *bool  `json:"privileged"`
					AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
					RunAsUser                *int64 `json:"runAsUser"`
					RunAsNonRoot             *bool  `json:"runAsNonRoot"`
				} `json:"securityContext"`
			} `json:"containers"`
		} `json:"spec"`
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

func collectKubernetesContainers(snap *pb.RptAssetSnapshot, configuredNodeName string) {
	nodeName := strings.TrimSpace(configuredNodeName)
	if nodeName == "" {
		var err error
		nodeName, err = os.Hostname()
		if err != nil || strings.TrimSpace(nodeName) == "" {
			recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_FAILED, "node_name_unavailable")
			return
		}
	}
	out, err := containerCommand("kubectl", kubernetesPodArgs(nodeName)...)
	if err != nil {
		recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_FAILED, "kubernetes_list_failed")
		return
	}
	var pods podList
	if json.Unmarshal(out, &pods) != nil || pods.Items == nil {
		recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_FAILED, "kubernetes_list_invalid")
		return
	}
	recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_COMPLETE, "")
	budgetExhausted := false
	containerCount := 0
	for _, pod := range pods.Items {
		if time.Now().After(deadline) {
			recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_PARTIAL, "container_time_budget_exhausted")
			break
		}
		for _, status := range pod.Status.ContainerStatuses {
			if containerCount >= maxContainersPerSource {
				budgetExhausted = true
				break
			}
			containerCount++
			id := status.ContainerID
			if id == "" {
				id = pod.Metadata.Namespace + "/" + pod.Metadata.Name + "/" + status.Name
			}
			state := "not_ready"
			if status.Ready {
				state = "running"
			}
			c := &pb.ContainerInfo{
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
			}
			// Kubernetes security evaluation
			if pod.Spec.HostNetwork {
				c.Risky = true
				c.RiskReasons = append(c.RiskReasons, "host_network")
			}
			if pod.Spec.HostPID {
				c.Risky = true
				c.RiskReasons = append(c.RiskReasons, "host_pid")
			}
			if pod.Spec.HostIPC {
				c.Risky = true
				c.RiskReasons = append(c.RiskReasons, "host_ipc")
			}
			for _, sc := range pod.Spec.Containers {
				if sc.Name == status.Name {
					if sc.SecurityContext != nil {
						if sc.SecurityContext.Privileged != nil && *sc.SecurityContext.Privileged {
							c.Risky = true
							c.RiskReasons = append(c.RiskReasons, "privileged")
						}
						if sc.SecurityContext.AllowPrivilegeEscalation != nil && *sc.SecurityContext.AllowPrivilegeEscalation {
							c.Risky = true
							c.RiskReasons = append(c.RiskReasons, "allow_privilege_escalation")
						}
						if sc.SecurityContext.RunAsUser != nil && *sc.SecurityContext.RunAsUser == 0 {
							c.Risky = true
							c.RiskReasons = append(c.RiskReasons, "runs_as_root")
						} else if sc.SecurityContext.RunAsNonRoot != nil && !*sc.SecurityContext.RunAsNonRoot {
							c.Risky = true
							c.RiskReasons = append(c.RiskReasons, "runs_as_root")
						}
					} else if pod.Spec.SecurityContext != nil {
						if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
							c.Risky = true
							c.RiskReasons = append(c.RiskReasons, "runs_as_root")
						} else if pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
							c.Risky = true
							c.RiskReasons = append(c.RiskReasons, "runs_as_root")
						}
					}
					break
				}
			}
			snap.Containers = append(snap.Containers, c)
		}
		if budgetExhausted {
			recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_PARTIAL, "container_count_budget_exhausted")
			break
		}
	}
}

func kubernetesPodArgs(nodeName string) []string {
	return []string{"get", "pods", "--all-namespaces", "--field-selector", "spec.nodeName=" + nodeName, "-o", "json"}
}

func fillContainerDetails(c *pb.ContainerInfo) error {
	out, err := containerCommand("docker", "inspect", "--format", "{{.Image}}\t{{.Created}}\t{{.State.StartedAt}}\t{{json .Config.Labels}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.NetworkMode}}\t{{.Config.User}}", c.ContainerId)
	if err != nil {
		return err
	}
	parts := strings.SplitN(strings.TrimRight(string(out), "\r\n"), "\t", 7)
	if len(parts) != 7 {
		return fmt.Errorf("invalid inspect result")
	}
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
		if err := json.Unmarshal([]byte(parts[3]), &c.Labels); err != nil {
			return err
		}
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
	return nil
}

var containerCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	limited := io.LimitReader(stdout, maxContainerOutputBytes+1)
	out, readErr := io.ReadAll(limited)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if len(out) > maxContainerOutputBytes {
		return nil, fmt.Errorf("command output exceeded %d bytes budget", maxContainerOutputBytes)
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return out, nil
}

func dockerTime(value string) int64 {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}
