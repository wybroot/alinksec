//go:build windows

package logcollect

import (
	"encoding/csv"
	"os/exec"
	"strings"
	"time"

	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

// pollInterval Windows：事件日志查询周期（wevtutil 启动开销大，放宽到 30s）
func pollInterval() time.Duration { return 30 * time.Second }

// winQueryDedup 事件去重：RecordId 已见集合（重启后首轮重拉，服务端幂等丢弃代价可控）
var winQueryDedup = map[string]bool{}

// pollOnce Windows：wevtutil 拉 Security 事件（4624 登录成功 / 4625 登录失败 / 4720 账户创建），
// XPath 按时间窗过滤（timediff ≤ 65s），CSV 输出解析。
func (c *Collector) pollOnce() {
	const xpath = `*[System[(EventID=4624 or EventID=4625 or EventID=4720) and TimeCreated[timediff(@SystemTime) <= 65000]]]`
	out, err := exec.Command("wevtutil", "qe", "Security", "/q:"+xpath, "/f:csv", "/c:200").Output()
	if err != nil {
		return // 无权限读 Security 日志（需管理员/审核策略）：静默跳过
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return
	}
	header := rows[0]
	col := func(rec []string, name string) string {
		for i, h := range header {
			if h == name && i < len(rec) {
				return rec[i]
			}
		}
		return ""
	}
	var batch []*pb.LogLine
	for _, rec := range rows[1:] {
		rid := col(rec, "Event ID") + "|" + col(rec, "Time Created") + "|" + col(rec, "Computer")
		if rid == "|" || winQueryDedup[rid] {
			continue
		}
		winQueryDedup[rid] = true
		if len(winQueryDedup) > 5000 { // 环形清理
			winQueryDedup = map[string]bool{}
		}
		ev := map[string]string{
			"event_id": col(rec, "Event ID"),
			"computer": col(rec, "Computer"),
		}
		content := "WinEvent " + col(rec, "Event ID") + " " + col(rec, "Time Created") + " " + col(rec, "Message")
		if len(content) > maxLineBytes {
			content = content[:maxLineBytes]
		}
		ts := time.Now().UnixMilli()
		if t, err := time.Parse("2006-01-02T15:04:05.999Z0700", col(rec, "Time Created")); err == nil {
			ts = t.UnixMilli()
		}
		batch = append(batch, &pb.LogLine{Ts: ts, Content: content, Fields: ev})
		if len(batch) >= maxBatchLines {
			break
		}
	}
	if len(batch) > 0 {
		c.send("windows-security", batch)
	}
}
