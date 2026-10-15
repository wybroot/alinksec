//go:build linux

package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

func stopService() error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	run := func(args ...string) (string, error) {
		b, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("systemctl %s: %w: %.1024s", strings.Join(args, " "), err, b)
		}
		return strings.TrimSpace(string(b)), nil
	}
	state, err := run("show", "--property=LoadState", "--value", "alinksec-agent.service")
	if err != nil {
		return err
	}
	if state == "not-found" {
		return nil
	}
	if _, err := run("stop", "alinksec-agent.service"); err != nil {
		return err
	}
	pid, err := run("show", "--property=MainPID", "--value", "alinksec-agent.service")
	if err != nil {
		return err
	}
	if pid != "0" {
		return fmt.Errorf("Agent service still has a process")
	}
	_, err = run("disable", "alinksec-agent.service")
	return err
}
