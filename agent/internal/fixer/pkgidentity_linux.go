//go:build linux

package fixer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/alinksec/alinksec-agent/internal/collector"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func currentInstallation(name string, log *slog.Logger) (PackageInstallation, error) {
	return installationFromSnapshot(name, collector.Snapshot([]string{"software"}, log))
}

func installationFromSnapshot(name string, snap *pb.RptAssetSnapshot) (PackageInstallation, error) {
	identity := snap.GetSoftwareInventory()
	if identity.GetStatus() != pb.SoftwareInventory_COMPLETE || identity.GetPackageRepairContract() != 2 || identity.GetIdentityError() != "" || !repairDistro.MatchString(identity.GetDistroId()) || !repairDistroVersion.MatchString(identity.GetDistroVersion()) {
		return PackageInstallation{}, errors.New("native installation identity unavailable")
	}
	var installed *pb.SoftwareInfo
	for _, candidate := range snap.GetSoftware() {
		if candidate.GetName() != name {
			continue
		}
		if installed != nil {
			return PackageInstallation{}, errors.New("ambiguous same-name installation")
		}
		installed = candidate
	}
	if installed == nil || (installed.GetSource() != "rpm" && installed.GetSource() != "dpkg") || !repairArchitecture.MatchString(installed.GetArchitecture()) || !repairVersion.MatchString(installed.GetVersion()) {
		return PackageInstallation{}, errors.New("installed package absent or incomplete")
	}
	return PackageInstallation{Contract: 2, OSType: 1, Source: installed.GetSource(), Architecture: installed.GetArchitecture(), DistroID: identity.GetDistroId(), DistroVersion: identity.GetDistroVersion(), InstalledVersion: installed.GetVersion()}, nil
}

func inspectPackage(p *PkgPayload, file string) (packageMetadata, error) {
	command, args := "rpm", []string{"-qp", "--nosignature", "--qf", "%{NAME}\x1f%{EPOCHNUM}\x1f%{VERSION}\x1f%{RELEASE}\x1f%{ARCH}\n", "--", file}
	if p.RepoType == "deb" {
		command, args = "dpkg-deb", []string{"--show", "--showformat=${Package}\x1f${Version}\x1f${Architecture}\n", file}
	}
	out, err := packageCommand(true, 10*time.Second, command, args...)
	if err != nil {
		return packageMetadata{}, err
	}
	return parsePackageMetadata(p.RepoType, string(out))
}

func parsePackageMetadata(repoType, output string) (packageMetadata, error) {
	output = strings.TrimSuffix(output, "\n")
	fields := strings.Split(output, "\x1f")
	var metadata packageMetadata
	if strings.ContainsAny(output, "\r\n") {
		return metadata, errors.New("multiple or malformed package headers")
	}
	switch {
	case repoType == "deb" && len(fields) == 3:
		metadata = packageMetadata{Name: fields[0], Version: fields[1], Architecture: fields[2], Source: "dpkg"}
	case repoType == "rpm" && len(fields) == 5:
		version := rpmInstalledVersion(strings.Join(fields[1:4], "\x1f") + "\n")
		metadata = packageMetadata{Name: fields[0], Version: version, Architecture: fields[4], Source: "rpm"}
	default:
		return metadata, errors.New("unsupported package header")
	}
	if !repairName.MatchString(metadata.Name) || !repairVersion.MatchString(metadata.Version) || !repairArchitecture.MatchString(metadata.Architecture) || metadata.Architecture == "src" || metadata.Architecture == "nosrc" {
		return packageMetadata{}, errors.New("invalid binary package identity")
	}
	return metadata, nil
}

type packageOutput struct {
	strings.Builder
	limit  int
	cancel func() error
}

func (out *packageOutput) Write(value []byte) (int, error) {
	if len(value) > out.limit-out.Len() {
		_ = out.cancel()
		return 0, io.ErrShortWrite
	}
	return out.Builder.Write(value)
}

// Metadata parsers receive memory/CPU limits and never run package scripts.
// Installers have a wall-time/output bound; their side effects cannot be rolled back automatically.
func packageCommand(metadata bool, timeout time.Duration, command string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(command)
	if err != nil {
		return nil, errors.New("required native package tool unavailable")
	}
	if metadata {
		guard, err := exec.LookPath("prlimit")
		if err != nil {
			return nil, errors.New("bounded package parser unavailable")
		}
		args = append([]string{"--as=268435456", "--cpu=10", "--", path}, args...)
		path = guard
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	output := &packageOutput{limit: 64 << 10, cancel: cmd.Cancel}
	if metadata {
		output.limit = 16 << 10
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = output
	}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return []byte(output.String()), errors.New("native package command failed, timed out or exceeded its limits")
	}
	return []byte(output.String()), nil
}
