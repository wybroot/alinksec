// L2 规则层（docs/05 §1.1）：
// 纯 Go 原生规则引擎，语义对齐 YARA 子集（strings + all/any 条件 + 平台/扩展/大小过滤）。
// 真正的 go-yara（CGO）后端可后续在同名接口下替换；受限环境保持本实现（hash+rule 纯 Go 构建）。
//
// 特征库包内 rules.json 格式：
//
//	{"rules":[
//	  {"name":"Trojan.Linux.Miner.X","severity":4,"platform":"linux",
//	   "exts":[".sh",".py"],            // 空 = 全部可扫描扩展
//	   "max_mb":50,                     // 对象大小上限（缺省 50MB，封顶 50MB）
//	   "condition":"all",               // all / any（strings 命中条件，缺省 all）
//	   "strings":[
//	     {"type":"text","value":"stratum+tcp"},
//	     {"type":"hex","value":"4d5a900003000000"}    // 十六进制（可含空格）
//	   ]}
//	]}
package virusscan

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ruleMaxSizeMB L2 扫描对象大小硬上限（docs/05 §1.1：< 50MB）
const ruleMaxSizeMB = 50

// ruleHeadBytes 规则匹配只读文件头部（特征串集中在头部；控制实时防护单文件开销）
const ruleHeadBytes = 2 << 20

// ruleString 单条特征串
type ruleString struct {
	Type  string `json:"type"` // text / hex
	Value string `json:"value"`
	bytes []byte // 编译后
}

// Rule 单条规则
type Rule struct {
	Name      string       `json:"name"`
	Severity  int32        `json:"severity"` // 1-5（缺省 4 高危）
	Platform  string       `json:"platform"` // linux / windows / all（缺省 all）
	Exts      []string     `json:"exts"`     // 限定扩展名（空 = 全部可扫描扩展）
	MaxMB     int          `json:"max_mb"`   // 对象大小上限
	Condition string       `json:"condition"`
	Strings   []ruleString `json:"strings"`
}

// scanableExts L2 可扫描扩展（docs/05 §1.1：PE/ELF/脚本/office 文档类）
var scanableExts = map[string]bool{
	// PE
	".exe": true, ".dll": true, ".sys": true, ".scr": true, ".com": true,
	".bat": true, ".cmd": true, ".ps1": true,
	// ELF / 库
	".so": true, ".bin": true,
	// 脚本
	".sh": true, ".py": true, ".pl": true, ".rb": true, ".js": true,
	".vbs": true, ".wsf": true, ".php": true, ".jar": true,
	// office / 文档
	".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
	".ppt": true, ".pptx": true, ".rtf": true, ".hwp": true, ".pdf": true,
}

// parseRules 加载 db 目录 rules.json（损坏/缺失返回空，不影响 L1）
func parseRules(dir string) []*Rule {
	b, err := os.ReadFile(filepath.Join(dir, "rules.json"))
	if err != nil {
		return nil
	}
	var wrap struct {
		Rules []*Rule `json:"rules"`
	}
	if json.Unmarshal(b, &wrap) != nil {
		return nil
	}
	var out []*Rule
	for _, r := range wrap.Rules {
		if r == nil || r.Name == "" || len(r.Strings) == 0 {
			continue
		}
		if r.Severity < 1 || r.Severity > 5 {
			r.Severity = 4
		}
		if r.Condition != "any" {
			r.Condition = "all"
		}
		if r.MaxMB <= 0 || r.MaxMB > ruleMaxSizeMB {
			r.MaxMB = ruleMaxSizeMB
		}
		valid := true
		for i := range r.Strings {
			s := &r.Strings[i]
			switch strings.ToLower(s.Type) {
			case "hex":
				v, err := hex.DecodeString(strings.Join(strings.Fields(s.Value), ""))
				if err != nil || len(v) == 0 {
					valid = false
				} else {
					s.bytes = v
				}
			default: // text
				if s.Value == "" {
					valid = false
				} else {
					s.bytes = []byte(s.Value)
				}
			}
			if !valid {
				break
			}
		}
		if valid {
			out = append(out, r)
		}
	}
	return out
}

// matchRules 对单个文件跑全部适用规则：平台 → 扩展/大小过滤 → 头部特征串匹配。
// 返回首个命中规则（nil = 干净）。head 由调用侧传入可复用（避免实时防护重复读盘）。
func matchRules(rules []*Rule, path string, size int64, head []byte) *Rule {
	if len(rules) == 0 || len(head) == 0 {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	noExt := ext == ""
	linux := runtime.GOOS != "windows"
	for _, r := range rules {
		switch r.Platform {
		case "linux":
			if !linux {
				continue
			}
		case "windows":
			if linux {
				continue
			}
		}
		if size > int64(r.MaxMB)<<20 {
			continue
		}
		if len(r.Exts) > 0 {
			hit := false
			for _, e := range r.Exts {
				if ext == strings.ToLower(e) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		} else if noExt && !linux {
			continue // Windows 无扩展名文件不进 L2
		}
		// 特征串条件判定
		matched, need := 0, 0
		for _, s := range r.Strings {
			if len(s.bytes) == 0 {
				continue
			}
			need++
			if bytes.Contains(head, s.bytes) {
				matched++
			}
		}
		if need == 0 {
			continue
		}
		if (r.Condition == "any" && matched > 0) ||
			(r.Condition == "all" && matched == need) {
			return r
		}
	}
	return nil
}

// readHeadLimited 读取文件头部（最多 ruleHeadBytes；失败返回空）
func readHeadLimited(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, ruleHeadBytes)
	n, err := f.Read(buf)
	if n <= 0 || (err != nil && n == 0) {
		return nil
	}
	return buf[:n]
}
