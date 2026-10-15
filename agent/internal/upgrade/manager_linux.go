//go:build linux

package upgrade

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type nativeManager struct{}

const watchdogUnit = "/etc/systemd/system/" + watchdogServiceName + ".service"

func systemctl(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl %s: %w: %.1024s", strings.Join(args, " "), err, b)
	}
	return strings.TrimSpace(string(b)), nil
}
func (nativeManager) pid() (int, error) {
	s, err := systemctl("show", "--property=MainPID", "--value", agentServiceName+".service")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(s)
}
func (m nativeManager) verify(executable string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("automatic Agent upgrade requires the root systemd service")
	}
	pid, err := m.pid()
	if err != nil {
		return err
	}
	if pid != os.Getpid() {
		return fmt.Errorf("automatic Agent upgrade requires alinksec-agent.service as the current process")
	}
	actual, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	if actual != executable {
		return fmt.Errorf("Agent service executable does not match")
	}
	return nil
}

// systemd specifiers and shell-like unit escaping must remain literal. No shell
// is used to start the helper; the command has a fixed subcommand and flags.
func unitArg(value string) string {
	r := strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "%", "%%", "\n", "\\n", "\r", "\\r")
	return "\"" + r.Replace(value) + "\""
}
func unitContents(helper, workDir string) string {
	return "[Unit]\nDescription=ALinkSec pending upgrade recovery\nAfter=local-fs.target\nBefore=alinksec-agent.service\n\n[Service]\nType=simple\nUser=root\nExecStart=" + unitArg(helper) + " upgrade-watchdog --workdir " + unitArg(workDir) + "\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
}
func (nativeManager) install(helper, workDir string) error {
	// Never overwrite an administrator's unit or a recovery already in progress.
	f, err := os.OpenFile(watchdogUnit, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(unitContents(helper, workDir))
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		os.Remove(watchdogUnit)
		return err
	}
	if err := syncDirectory(filepath.Dir(watchdogUnit)); err != nil {
		return err
	}
	if _, err = systemctl("daemon-reload"); err != nil {
		return err
	}
	if _, err = systemctl("enable", "--now", watchdogServiceName+".service"); err != nil {
		return err
	}
	return syncDirectory("/etc/systemd/system/multi-user.target.wants")
}
func (nativeManager) remove(helper, workDir string) error {
	b, err := os.ReadFile(watchdogUnit)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(b) != unitContents(helper, workDir) {
		return fmt.Errorf("refusing to remove an unrelated watchdog unit")
	}
	if _, err = systemctl("disable", watchdogServiceName+".service"); err != nil {
		return err
	}
	if err = os.Remove(watchdogUnit); err != nil {
		return err
	}
	_, err = systemctl("daemon-reload")
	return err
}
func (nativeManager) stop(string, string) error {
	_, err := systemctl("stop", agentServiceName+".service")
	return err
}
func (nativeManager) start() error {
	_, err := systemctl("start", agentServiceName+".service")
	return err
}
func runWatchdogService(run func(context.Context) error) error { return run(context.Background()) }
