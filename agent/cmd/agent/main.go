// alinksec-agent 入口：run（默认）/ install 两个子命令
//
//	alinksec-agent run    --config <agent.yml> --workdir <dir>
//	alinksec-agent install --server host:port --token ENROLL-xxx --ca-file ca.crt --workdir <dir>
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/alinksec/alinksec-agent/internal/comm"
	"github.com/alinksec/alinksec-agent/internal/config"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`alinksec-agent ` + runtime.Version() + `

用法:
  alinksec-agent run       --config <path>  --workdir <dir>   前台运行（开发/容器）
	  alinksec-agent install   --server <addr> --token <code> --ca-file <ca.pem> [--workdir <dir>]
                                                          写入配置并完成注册
  alinksec-agent uninstall --token <口令>  [--workdir <dir>]
                                                          需平台先布防口令（15min 有效一次性）

默认工作目录:
  Linux   /var/lib/alinksec-agent
  Windows C:\ProgramData\alinksec-agent
`)
}

// defaultWorkDir 平台默认工作目录
func defaultWorkDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\alinksec-agent`
	}
	return "/var/lib/alinksec-agent"
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

/* -------------------- run -------------------- */

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "配置文件路径（默认 <workdir>/agent.yml）")
	workDir := fs.String("workdir", defaultWorkDir(), "工作目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := newLogger()
	if *cfgPath == "" {
		*cfgPath = *workDir + string(os.PathSeparator) + "agent.yml"
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}

	client, err := comm.New(cfg, *workDir, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := client.EnsureEnrolled(ctx); err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}
	log.Info("agent 启动", "agent_id", client.AgentID(), "server", cfg.ServerAddr)
	return client.Run(ctx)
}

/* -------------------- install -------------------- */

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "服务端地址 host:port（必填）")
	token := fs.String("token", "", "注册码（必填）")
	caFile := fs.String("ca-file", "", "平台 CA PEM 文件（必填）")
	workDir := fs.String("workdir", defaultWorkDir(), "工作目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *token == "" || *caFile == "" {
		return fmt.Errorf("--server、--token 与 --ca-file 必填")
	}
	log := newLogger()
	if err := os.MkdirAll(*workDir, 0750); err != nil {
		return err
	}
	cfgPath := *workDir + string(os.PathSeparator) + "agent.yml"
	if err := config.WriteExample(cfgPath, *server, *token, *caFile); err != nil {
		return fmt.Errorf("写入配置: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	client, err := comm.New(cfg, *workDir, log)
	if err != nil {
		return err
	}
	if err := client.EnsureEnrolled(context.Background()); err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}
	if err := config.ClearEnrollToken(cfgPath); err != nil {
		log.Warn("注册成功，但未能从配置文件清除注册码", "error", err)
	}
	fmt.Printf("安装完成：agent_id=%s\n配置: %s\n启动服务或运行 alinksec-agent run\n", client.AgentID(), cfgPath)
	return nil
}

/* -------------------- uninstall -------------------- */

// cmdUninstall 卸载 Agent（docs/01 §6.1：需平台布防的动态口令，15min 有效，一次性消费）。
// 校验通过后：停服务 → 清理工作目录（证书/队列/状态/特征库）→ 尽力删除自身二进制。
func cmdUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	token := fs.String("token", "", "平台布防的卸载口令（必填）")
	workDir := fs.String("workdir", defaultWorkDir(), "工作目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		return fmt.Errorf("--token 必填（由平台生成并下发布防）")
	}
	st, err := comm.LoadState(*workDir)
	if err != nil {
		return fmt.Errorf("读取本地状态: %w", err)
	}
	now := time.Now().Unix()
	switch {
	case st.UninstallToken == "":
		return fmt.Errorf("未布防卸载口令：请先在平台「主机管理」申请卸载口令")
	case subtle.ConstantTimeCompare([]byte(st.UninstallToken), []byte(*token)) != 1:
		return fmt.Errorf("卸载口令不匹配")
	case now > st.UninstallExpire:
		return fmt.Errorf("卸载口令已过期（布防后 15 分钟内有效），请重新申请")
	}
	// 一次性消费：先清口令再执行，中途失败不可重放
	st.UninstallToken, st.UninstallExpire = "", 0
	_ = st.Save(*workDir)

	stopService() // 停服务（等 Agent 进程退出释放文件句柄）
	time.Sleep(2 * time.Second)

	if err := os.RemoveAll(*workDir); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: 工作目录清理不完整: %v\n", err)
	}
	// 尽力删除自身（Windows 运行中占用会失败，提示手动删）
	if err := os.Remove(os.Args[0]); err != nil {
		fmt.Printf("卸载完成（请手动删除残留二进制 %s）\n", os.Args[0])
	} else {
		fmt.Println("卸载完成")
	}
	return nil
}

// stopService 尽力停止/移除服务单元（权限不足时仅提示，不阻塞数据清理）
func stopService() {
	var cmds []*exec.Cmd
	if runtime.GOOS == "windows" {
		cmds = []*exec.Cmd{
			exec.Command("net", "stop", "alinksec-agent"),
			exec.Command("sc", "delete", "alinksec-agent"),
		}
	} else {
		cmds = []*exec.Cmd{
			exec.Command("systemctl", "stop", "alinksec-agent"),
			exec.Command("systemctl", "disable", "alinksec-agent"),
		}
	}
	for _, c := range cmds {
		_ = c.Run()
	}
}
