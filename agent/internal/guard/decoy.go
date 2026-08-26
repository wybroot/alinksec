package guard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alinksec/alinksec-agent/internal/config"
)

/* 诱饵文件管理：本地生成 → 投放 → 哈希登记（decoys.json）。
 * 生成规则（docs/05 §2.2）：业务感文件名随机组合 + 随机字节 + 真实格式魔数头，
 * 不依赖平台下载；正常业务几乎不可能写入这些文件 → 高置信触发。 */

const decoyStateFile = "decoys.json"

// namePools 文件名模板池（业务感组合：主体 + 日期 + 扩展）
var (
	decoySubjects = []string{
		"财务报表", "2026年度合同", "核心数据备份", "密码本", "员工花名册",
		"工资表", "客户清单", "服务器账号", "运维手册", "数据库导出",
		"投标文件", "设计图纸归档", "人事档案", "结算单", "开票记录",
	}
	decoyExts = []string{".xlsx", ".docx", ".pdf", ".sql.zip", ".csv"}
)

// formatMagics 常见办公/归档格式魔数头（诱饵内容以真实格式开头，规避简单内容扫描）
var formatMagics = map[string][]byte{
	".xlsx":    {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00},             // ZIP (xlsx)
	".docx":    {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00},             // ZIP (docx)
	".sql.zip": {0x50, 0x4B, 0x03, 0x04},                         // ZIP
	".pdf":     {0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37}, // %PDF-1.7
	".csv":     {0xEF, 0xBB, 0xBF},                               // UTF-8 BOM
}

// decoyState 诱饵登记表（工作目录持久化，重启后延续哈希基准）
type decoyState struct {
	mu     sync.Mutex
	Decoys map[string]string `json:"decoys"` // path → sha256（生成时基准）
}

func (s *decoyState) load(workDir string) {
	s.Decoys = map[string]string{}
	if b, err := os.ReadFile(filepath.Join(workDir, decoyStateFile)); err == nil {
		_ = json.Unmarshal(b, &s.Decoys)
	}
}

func (s *decoyState) save(workDir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.MarshalIndent(s.Decoys, "", "  ")
	_ = os.WriteFile(filepath.Join(workDir, decoyStateFile), b, 0600)
}

/* ---- decoyManager ---- */

type decoyManager struct {
	cfg     *config.DecoyConfig
	workDir string
	state   *decoyState
}

func newDecoyManager(cfg *config.DecoyConfig, workDir string) *decoyManager {
	st := &decoyState{}
	st.load(workDir)
	return &decoyManager{cfg: cfg, workDir: workDir, state: st}
}

// deployDirs 解析投放目录（配置优先，缺省平台默认；展开 /home/* 一级通配）
func (g *Guard) deployDirs() []string {
	dirs := g.cur().Dirs
	if len(dirs) == 0 {
		dirs = defaultDecoyDirs()
	}
	var out []string
	for _, d := range dirs {
		if strings.HasSuffix(d, "/*") { // /home/* → 各用户家目录
			base := strings.TrimSuffix(d, "*")
			if entries, err := os.ReadDir(base); err == nil {
				for _, e := range entries {
					if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
						p := filepath.Join(base, e.Name())
						if isWritableDir(p) {
							out = append(out, p)
						}
					}
				}
				continue
			}
		}
		if isWritableDir(d) {
			out = append(out, d)
		}
	}
	return out
}

// ensureDeployed 投放/补齐各目录诱饵；返回本次新建数
func (m *decoyManager) ensureDeployed(dirs []string) int {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	created := 0
	for _, dir := range dirs {
		// 统计该目录下已登记诱饵
		existing := 0
		for p := range m.state.Decoys {
			if filepath.Dir(p) == dir {
				existing++
			}
		}
		for i := existing; i < m.cfg.CountPerDir; i++ {
			path, sum, err := m.createOne(dir)
			if err != nil {
				continue
			}
			m.state.Decoys[path] = sum
			created++
		}
	}
	if created > 0 {
		m.persistLocked()
	}
	return created
}

// createOne 在目录生成单个诱饵：随机名 + 魔数头 + 随机字节（8~64KB）
func (m *decoyManager) createOne(dir string) (path, sha string, err error) {
	name := fmt.Sprintf("%s_%s%s", randPick(decoySubjects),
		time.Now().Format("20060102"), randPick(decoyExts))
	path = filepath.Join(dir, name)
	// 同名碰撞：附加随机后缀
	if _, err := os.Stat(path); err == nil {
		path = filepath.Join(dir, fmt.Sprintf("%s_%d%s", randPick(decoySubjects),
			time.Now().UnixNano()%1e6, randPick(decoyExts)))
	}
	ext := strings.ToLower(filepath.Ext(path))
	if strings.HasSuffix(path, ".zip") { // .sql.zip 取复合扩展
		ext = ".sql.zip"
	}
	magic := formatMagics[ext]

	size, _ := rand.Int(rand.Reader, big.NewInt(56*1024))
	body := make([]byte, 8*1024+size.Int64())
	if _, err := rand.Read(body); err != nil {
		return "", "", err
	}
	content := append(append([]byte{}, magic...), body...)
	if err := os.WriteFile(path, content, 0644); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(content)
	return path, hex.EncodeToString(sum[:]), nil
}

// healthResult 一次健康检查结果
type healthResult struct {
	Missing  []string // 丢失（可能正常清理 → 低危告警 + 补投）
	Tampered []string // 内容/大小变化（高置信触发）
}

// healthCheck 校验全部登记诱饵：哈希变更即篡改；缺失即丢失
func (m *decoyManager) healthCheck() healthResult {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	res := healthResult{}
	for path, base := range m.state.Decoys {
		info, err := os.Stat(path)
		if err != nil {
			res.Missing = append(res.Missing, path)
			continue
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			res.Tampered = append(res.Tampered, path)
			continue
		}
		if sum := fileSha256(path); sum != "" && sum != base {
			res.Tampered = append(res.Tampered, path)
		}
	}
	// 丢失的移出登记（补投在 ensureDeployed 中完成）
	for _, p := range res.Missing {
		delete(m.state.Decoys, p)
	}
	if len(res.Missing) > 0 {
		m.persistLocked()
	}
	return res
}

func (m *decoyManager) persistLocked() {
	b, _ := json.MarshalIndent(m.state.Decoys, "", "  ")
	_ = os.WriteFile(filepath.Join(m.workDir, decoyStateFile), b, 0600)
}

func (m *decoyManager) knownDecoys() []string {
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	out := make([]string, 0, len(m.state.Decoys))
	for p := range m.state.Decoys {
		out = append(out, p)
	}
	return out
}

/* ---- 工具 ---- */

func randPick(list []string) string {
	if len(list) == 0 {
		return ""
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	return list[n.Int64()]
}

func fileSha256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func isWritableDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
