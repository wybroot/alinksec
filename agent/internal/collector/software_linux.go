//go:build linux

package collector

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alinksec/alinksec-agent/internal/packageversion"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const rpmInventoryFormat = "%{NAME}\x1f%{EPOCHNUM}\x1f%{VERSION}\x1f%{RELEASE}\x1f%{VENDOR}\x1f%{INSTALLTIME}\x1f%{ARCH}\n"
const dpkgInventoryFormat = "${Package}\x1f${Version}\x1f${db:Status-Abbrev}\x1f${Architecture}\n"
const softwareOutputLimit = 16 << 20
const softwarePackageLimit = 100000

var packageArchPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)
var distroIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
var distroVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

func collectSoftware(snap *pb.RptAssetSnapshot) {
	identity, err := readDistributionIdentity()
	if err != nil {
		identity = &pb.SoftwareInventory{IdentityError: "distribution_identity_unavailable"}
	}
	collectLinuxSoftware(snap, identity, exec.LookPath, runSoftwareQuery)
}

// Query each available package database. An installed rpm utility on a Debian
// system does not make Debian packages disappear, nor does an empty RPM database
// imply a query failure. Any failed database makes this attempt incomplete.
func collectLinuxSoftware(snap *pb.RptAssetSnapshot, inventory *pb.SoftwareInventory,
	lookPath func(string) (string, error), run func(string, ...string) ([]byte, error)) {
	snap.SoftwareInventory = inventory
	var packages []*pb.SoftwareInfo
	var sources []string
	for _, source := range []string{"rpm", "dpkg"} {
		command, args := "rpm", []string{"-qa", "--qf", rpmInventoryFormat}
		if source == "dpkg" {
			command, args = "dpkg-query", []string{"-W", "-f", dpkgInventoryFormat}
		}
		path, err := lookPath(command)
		if errors.Is(err, exec.ErrNotFound) {
			continue
		}
		if err != nil {
			inventory.Status, inventory.Error = pb.SoftwareInventory_FAILED, "package_manager_lookup_failed"
			return
		}
		sources = append(sources, source)
		out, err := run(path, args...)
		if err != nil {
			inventory.Status, inventory.Error = pb.SoftwareInventory_FAILED, "package_query_failed"
			return
		}
		var items []*pb.SoftwareInfo
		if source == "rpm" {
			items, err = parseRPMPackages(string(out))
		} else {
			items, err = parseDPKGPackages(string(out))
		}
		if err != nil || len(packages)+len(items) > softwarePackageLimit {
			inventory.Status, inventory.Error = pb.SoftwareInventory_FAILED, "package_output_invalid_or_limited"
			return
		}
		packages = append(packages, items...)
	}
	if len(sources) == 0 {
		inventory.Status, inventory.Error = pb.SoftwareInventory_UNSUPPORTED, "package_manager_unavailable"
		return
	}
	inventory.Source = sources[0]
	if len(sources) > 1 {
		inventory.Source = "mixed"
	}
	inventory.Status = pb.SoftwareInventory_COMPLETE
	inventory.PackageRepairContract = 2
	snap.Software = packages
}

type softwareOutput struct{ strings.Builder }

func (out *softwareOutput) Write(p []byte) (int, error) {
	if len(p) > softwareOutputLimit-out.Len() {
		return 0, errors.New("software output limit exceeded")
	}
	return out.Builder.Write(p)
}

func runSoftwareQuery(command string, args ...string) ([]byte, error) {
	return runSoftwareQueryWithTimeout(20*time.Second, command, args...)
}

func runSoftwareQueryWithTimeout(timeout time.Duration, command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	var output softwareOutput
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return []byte(output.String()), nil
}

func parseRPMPackages(out string) ([]*pb.SoftwareInfo, error) {
	var list []*pb.SoftwareInfo
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		// Older RPM databases store imported public keys as pseudo-packages.
		// They are repository metadata, without a software architecture.
		if len(f) == 7 && f[0] == "gpg-pubkey" && f[6] == "(none)" {
			continue
		}
		if len(f) != 7 || f[0] == "" || len(f[0]) > 255 || !packageArchPattern.MatchString(f[6]) {
			return nil, errors.New("invalid RPM record")
		}
		version, err := packageversion.RPM(f[1], f[2], f[3])
		if err != nil || len(version) > 255 {
			return nil, errors.New("invalid RPM version")
		}
		ts, _ := strconv.ParseInt(f[5], 10, 64)
		if ts < 0 || ts > (1<<63-1)/1000 {
			ts = 0
		}
		list = append(list, &pb.SoftwareInfo{Name: f[0], Version: version, Vendor: f[4],
			InstallTime: ts * 1000, Source: "rpm", Architecture: f[6]})
		if len(list) > softwarePackageLimit {
			return nil, errors.New("package count limit exceeded")
		}
	}
	return list, nil
}

func parseDPKGPackages(out string) ([]*pb.SoftwareInfo, error) {
	var list []*pb.SoftwareInfo
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\x1f")
		if len(f) != 4 || f[0] == "" || len(f[0]) > 255 || len(f[2]) != 3 {
			return nil, errors.New("invalid DPKG record")
		}
		// Want=hold is also an installed package. The second status character
		// must be installed, and the third must indicate no package error.
		if f[2][1] == 'n' || f[2][1] == 'c' {
			continue
		}
		if f[2][1] != 'i' || f[2][2] != ' ' {
			return nil, errors.New("DPKG package is in an incomplete installation state")
		}
		if f[1] == "" || len(f[1]) > 255 || !packageArchPattern.MatchString(f[3]) {
			return nil, errors.New("incomplete installed DPKG record")
		}
		list = append(list, &pb.SoftwareInfo{Name: f[0], Version: f[1], Source: "dpkg", Architecture: f[3]})
		if len(list) > softwarePackageLimit {
			return nil, errors.New("package count limit exceeded")
		}
	}
	return list, nil
}

func readDistributionIdentity() (*pb.SoftwareInventory, error) {
	path := "/etc/os-release"
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.OpenFile("/usr/lib/os-release", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		return nil, errors.New("os-release is not a regular file")
	}
	out, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(out) > 64<<10 {
		return nil, errors.New("os-release unreadable or oversized")
	}
	return parseDistributionIdentity(string(out)), nil
}

// Only literal ID and VERSION_ID are accepted; no shell expansion, ID_LIKE
// fallback, codename inference or PRETTY_NAME parsing is performed.
func parseDistributionIdentity(out string) *pb.SoftwareInventory {
	values := map[string]string{}
	invalid := func() *pb.SoftwareInventory {
		return &pb.SoftwareInventory{IdentityError: "distribution_identity_invalid"}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if key != "ID" && key != "VERSION_ID" {
			continue
		}
		if !ok {
			return invalid()
		}
		if _, exists := values[key]; exists {
			return invalid()
		}
		if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
			if len(value) < 2 || value[len(value)-1] != value[0] {
				return invalid()
			}
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	identity := &pb.SoftwareInventory{DistroId: values["ID"], DistroVersion: values["VERSION_ID"]}
	if identity.DistroId != "" && !distroIDPattern.MatchString(identity.DistroId) ||
		identity.DistroVersion != "" && !distroVersionPattern.MatchString(identity.DistroVersion) {
		return invalid()
	}
	if identity.DistroId == "" || identity.DistroVersion == "" {
		identity.IdentityError = "distribution_identity_incomplete"
	}
	return identity
}
