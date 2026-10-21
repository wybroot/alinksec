package scap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

const workerArg = "__alinksec_scap_worker_v1"

type workerInput struct {
	Config    Config
	WorkDir   string
	Probe     bool
	Archive   []byte
	Benchmark string
	Profile   string
}
type workerOutput struct {
	Issue        string
	SourceSHA256 string
	Rules        []*pb.ScapRuleResult
	Scores       []*pb.ScapScore
}

func init() {
	if len(os.Args) == 2 && os.Args[1] == workerArg {
		debug.SetMemoryLimit(64 << 20)
		os.Exit(worker(os.Stdin, os.Stdout))
	}
}
func worker(in io.Reader, out io.Writer) int {
	var result workerOutput
	if workerLimits() != nil {
		result.Issue = "scap_resource_limit"
	} else {
		var input workerInput
		d := json.NewDecoder(io.LimitReader(in, 3<<20))
		d.DisallowUnknownFields()
		if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF || input.Config.Validate() != nil || !input.Config.Enabled || !filepath.IsAbs(input.WorkDir) || len(input.Archive) > MaxArchive {
			return 2
		}
		seconds := input.Config.TimeoutSec
		if seconds == 0 {
			seconds = 600
		}
		if input.Probe {
			seconds = 55
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
		result, err := executeNative(ctx, input)
		cancel()
		if err != nil {
			result = workerOutput{Issue: Code(err)}
		}
		if json.NewEncoder(out).Encode(result) != nil {
			return 2
		}
		return 0
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	return 0
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, issue("scap_result_limit")
	}
	return b.Buffer.Write(p)
}
func cleanEnvironment() []string {
	env := []string{"GOMEMLIMIT=64MiB", "GOMAXPROCS=1", "GOGC=50", "LANG=C.UTF-8"}
	for _, key := range []string{"SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR"} {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	if root := os.Getenv("SYSTEMROOT"); root != "" {
		env = append(env, "PATH="+filepath.Join(root, "System32"))
	} else {
		env = append(env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin")
	}
	return env
}
func runWorker(ctx context.Context, input workerInput) (workerOutput, error) {
	var result workerOutput
	executable, err := os.Executable()
	if err != nil {
		return result, issue("scap_worker_failed")
	}
	cmd := exec.CommandContext(ctx, executable, workerArg)
	cmd.Env = cleanEnvironment()
	cmd.WaitDelay = time.Second
	configureProcess(cmd)
	stdout, stderr := &cappedBuffer{limit: 2 << 20}, &cappedBuffer{limit: 4096}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return result, issue("scap_worker_failed")
	}
	if err = cmd.Start(); err != nil {
		pipe.Close()
		return result, issue("scap_worker_failed")
	}
	cleanup, err := limitProcess(cmd.Process)
	if err != nil {
		pipe.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return result, issue("scap_resource_limit")
	}
	defer cleanup()
	err = json.NewEncoder(pipe).Encode(input)
	pipe.Close()
	if err != nil {
		cmd.Cancel()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil || waitErr != nil || stderr.Len() != 0 {
		return result, issue("scap_worker_failed")
	}
	d := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF {
		return workerOutput{}, issue("scap_worker_protocol")
	}
	if result.Issue != "" {
		if !strings.HasPrefix(result.Issue, "scap_") || len(result.Issue) > 64 {
			return workerOutput{}, issue("scap_worker_protocol")
		}
		return workerOutput{}, issue(result.Issue)
	}
	if input.Probe {
		if len(result.Rules) != 0 || len(result.Scores) != 0 || result.SourceSHA256 != "" {
			return workerOutput{}, issue("scap_worker_protocol")
		}
		return result, nil
	}
	// Independently enforce the normalized worker protocol before reporting.
	content, err := ParseContent(input.Archive)
	if err != nil {
		return workerOutput{}, err
	}
	expected := map[string]bool{}
	for _, id := range content.Rules {
		expected[id] = true
	}
	if !validHash(result.SourceSHA256) || len(result.Rules) != len(expected) || len(result.Scores) == 0 || len(result.Scores) > 16 {
		return workerOutput{}, issue("scap_worker_protocol")
	}
	for _, rule := range result.Rules {
		if rule == nil || !expected[rule.RuleId] || !Outcomes[rule.Result] || !finite(rule.Weight) || rule.Weight < 0 || rule.Weight > 1e6 {
			return workerOutput{}, issue("scap_worker_protocol")
		}
		delete(expected, rule.RuleId)
	}
	seen := map[string]bool{}
	for _, score := range result.Scores {
		if score == nil || score.System == "" || len(score.System) > 256 || seen[score.System] || !finite(score.Value) || !finite(score.Maximum) || score.Value < 0 || score.Maximum < 0 || score.Maximum > 1e6 || score.Value > score.Maximum {
			return workerOutput{}, issue("scap_worker_protocol")
		}
		seen[score.System] = true
	}
	return result, nil
}
func executeNative(ctx context.Context, input workerInput) (workerOutput, error) {
	var result workerOutput
	directory, err := os.MkdirTemp(input.WorkDir, ".scap-")
	if err != nil {
		return result, issue("scap_worker_failed")
	}
	defer os.RemoveAll(directory)
	native := filepath.Join(directory, "runtime")
	reports := filepath.Join(directory, "reports")
	bin, err := cloneRuntime(ctx, input.Config, native)
	if err != nil {
		return result, err
	}
	if err = configureRuntime(native, reports, input.Config.TimeoutSec); err != nil {
		return result, err
	}
	run := func(args ...string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = native
		cmd.Env = cleanEnvironment()
		cmd.WaitDelay = time.Second
		stdout, stderr := &cappedBuffer{limit: 64 << 10}, &cappedBuffer{limit: 4096}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			return "", issue("scap_native_failed")
		}
		finished := make(chan error, 1)
		go func() { finished <- cmd.Wait() }()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		var nativeErr error
		waiting := true
		for waiting {
			select {
			case nativeErr = <-finished:
				waiting = false
			case <-tick.C:
				if err := workspaceBudget(directory); err != nil {
					cmd.Process.Kill()
					<-finished
					return "", err
				}
			case <-ctx.Done():
				cmd.Process.Kill()
				<-finished
				return "", ctx.Err()
			}
		}
		if nativeErr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", issue("scap_native_failed")
		}
		// SCC can exit zero after native errors. Complete bound XML evidence is
		// still mandatory, and crashes in native helper threads fail closed.
		if stderr.Len() != 0 {
			return "", issue("scap_native_failed")
		}
		return stdout.String(), nil
	}
	version, err := run("--version")
	if err != nil {
		return result, err
	}
	if !strings.Contains(version, "scc version: 5.15 date:") {
		return result, issue("scap_engine_version")
	}
	if input.Probe {
		return result, nil
	}
	content, err := ParseContent(input.Archive)
	if err != nil {
		return result, err
	}
	if content.Manifest.BenchmarkID != input.Benchmark || content.Manifest.ProfileID != input.Profile {
		return result, issue("scap_command_invalid")
	}
	archive := filepath.Join(directory, "content.zip")
	if os.WriteFile(archive, input.Archive, 0600) != nil {
		return result, issue("scap_worker_failed")
	}
	if _, err = run("--installScap", archive); err != nil {
		return result, err
	}
	profile, benchmark := input.Profile, input.Benchmark
	if parts := strings.SplitN(profile, "_profile_", 2); len(parts) == 2 {
		profile = parts[1]
	}
	if parts := strings.SplitN(benchmark, "_benchmark_", 2); len(parts) == 2 {
		benchmark = parts[1]
	}
	if _, err = run("--setProfile", profile, benchmark); err != nil {
		return result, err
	}
	if _, err = run("--userDir", reports); err != nil {
		return result, err
	}
	var source []byte
	var total int64
	count := 0
	err = filepath.WalkDir(reports, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return issue("scap_result_invalid")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			return nil
		}
		count++
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return issue("scap_result_invalid")
		}
		total += info.Size()
		if count > 512 || total > 64<<20 || info.Size() > 8<<20 {
			return issue("scap_result_limit")
		}
		if strings.Contains(entry.Name(), "_XCCDF-Results_") && strings.HasSuffix(entry.Name(), ".xml") {
			if source != nil {
				return issue("scap_result_invalid")
			}
			source, err = os.ReadFile(path)
			return err
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	if len(source) == 0 {
		return result, issue("scap_result_missing")
	}
	result.Rules, result.Scores, err = ParseResults(source, content)
	if err != nil {
		return workerOutput{}, err
	}
	result.SourceSHA256 = Digest(source)
	return result, nil
}

func workspaceBudget(directory string) error {
	var total int64
	count := 0
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return issue("scap_worker_failed")
		}
		count++
		if count > 8192 {
			return issue("scap_resource_limit")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return issue("scap_resource_limit")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return issue("scap_worker_failed")
		}
		total += info.Size()
		if total > 640<<20 || info.Size() > 128<<20 {
			return issue("scap_resource_limit")
		}
		return nil
	})
}
