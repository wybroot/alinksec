package scap

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
	scapconfig "github.com/alinksec/alinksec-agent/internal/scap/config"
)

type Config = scapconfig.Config

type Status struct {
	State         string `json:"state"`
	Version       string `json:"version"`
	RuntimeSHA256 string `json:"runtime_sha256"`
	ObservedAt    int64  `json:"observed_at"`
	LastIssue     string `json:"last_issue"`
}
type Client struct {
	cfg     Config
	workDir string
	mu      sync.Mutex
	status  Status
	gate    chan struct{}
}

func Contract() uint32 {
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") || runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		return 1
	}
	return 0
}
func New(cfg Config, workDir string) *Client {
	state := Status{State: "disabled"}
	if cfg.Enabled {
		state.State = "starting"
	}
	if Contract() == 0 {
		state.State = "unavailable"
		state.LastIssue = "scap_unsupported"
	}
	return &Client{cfg: cfg, workDir: workDir, status: state, gate: make(chan struct{}, 1)}
}
func (c *Client) Status() Status {
	if c == nil {
		return Status{State: "disabled"}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}
func (c *Client) StatusJSON() string { b, _ := json.Marshal(c.Status()); return string(b) }
func (c *Client) ready() error {
	if c == nil || !c.cfg.Enabled {
		return issue("scap_disabled")
	}
	if Contract() != 1 {
		return issue("scap_unsupported")
	}
	if c.cfg.Validate() != nil {
		return issue("scap_config_invalid")
	}
	return nil
}
func (c *Client) observe(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status.ObservedAt = time.Now().Unix()
	c.status.LastIssue = Code(err)
	if err != nil {
		c.status.State = "unavailable"
		return
	}
	c.status.State = "ready"
	c.status.Version = "5.15"
	c.status.RuntimeSHA256 = c.cfg.RuntimeSHA256
}
func (c *Client) Probe(ctx context.Context) error {
	if err := c.ready(); err != nil {
		return err
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	default:
		return issue("scap_busy")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	_, err := runWorker(ctx, workerInput{Config: c.cfg, WorkDir: c.workDir, Probe: true})
	c.observe(err)
	return err
}
func (c *Client) Run(ctx context.Context) {
	if c.ready() != nil {
		return
	}
	tick := time.NewTicker(4 * time.Minute)
	defer tick.Stop()
	for {
		c.Probe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (c *Client) Scan(ctx context.Context, commandID string, command *pb.CmdScapScan) *pb.RptScapResult {
	started := time.Now()
	result := &pb.RptScapResult{TaskId: command.GetTaskId(), CommandId: commandID, ExecutionContract: 1, Engine: "SCC", ContentSha256: command.GetContentSha256(), BenchmarkId: command.GetBenchmarkId(), ProfileId: command.GetProfileId(), State: "failed"}
	finish := func(err error) *pb.RptScapResult {
		result.DurationMs = uint64(time.Since(started).Milliseconds())
		result.Issue = Code(err)
		return result
	}
	if err := c.ready(); err != nil {
		return finish(err)
	}
	if commandID == "" || len(commandID) > 128 || command.GetTaskId() == "" || len(command.GetTaskId()) > 128 || command.GetExecutionContract() != 1 || len(command.GetContentZip()) == 0 || len(command.GetContentZip()) > MaxArchive || !validHash(command.GetContentSha256()) || Digest(command.GetContentZip()) != command.GetContentSha256() || command.GetRuntimeSha256() != c.cfg.RuntimeSHA256 || !identifier.MatchString(command.GetBenchmarkId()) || !identifier.MatchString(command.GetProfileId()) {
		return finish(issue("scap_command_invalid"))
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	default:
		return finish(issue("scap_busy"))
	}
	c.mu.Lock()
	c.status.State = "running"
	c.mu.Unlock()
	seconds := c.cfg.TimeoutSec
	if seconds == 0 {
		seconds = 600
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	output, err := runWorker(ctx, workerInput{Config: c.cfg, WorkDir: c.workDir, Archive: command.GetContentZip(), Benchmark: command.GetBenchmarkId(), Profile: command.GetProfileId()})
	c.observe(err)
	if err != nil {
		return finish(err)
	}
	result.State = "complete"
	result.EngineVersion = "5.15"
	result.RuntimeSha256 = c.cfg.RuntimeSHA256
	result.Rules = output.Rules
	result.Scores = output.Scores
	result.SourceResultSha256 = output.SourceSHA256
	return finish(nil)
}
