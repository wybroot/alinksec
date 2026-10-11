package baseline

import (
	"fmt"
	"regexp"
	"strings"
)

// A finite apt.conf grammar, never an APT invocation. Hooks remain inert data.
// Maps include empty ancestor nodes: #clear and Binary subtree movement can
// override a global scalar with an empty value (FindB then uses false).
type aptTree map[string]string
type aptToken struct {
	value  string
	quoted bool
}

var aptPartName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
var aptName = regexp.MustCompile(`^[A-Za-z0-9_./+-]+(::[A-Za-z0-9_./+-]+)*(::)?$`)
var aptBoolKeys = []string{"apt::get::allowunauthenticated", "apt::get::force-yes"}

func aptTokens(raw string) ([]aptToken, error) {
	bad := func() ([]aptToken, error) {
		return nil, fmt.Errorf("APT 配置超出有限 ASCII/LF、引号值与完整作用域语法")
	}
	var tokens []aptToken
	inBlock := false
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		if len(line) > 4096 {
			return bad()
		}
		for _, c := range []byte(line) {
			if c != '\t' && (c < 32 || c > 126) {
				return bad()
			}
		}
		line = strings.TrimSpace(line)
		// Whole-line block comments only. Native strips // and # before /*;
		// excluding mixed/inline block comments avoids different token boundaries.
		if inBlock || strings.HasPrefix(line, "/*") {
			if !inBlock {
				line = line[2:]
				inBlock = true
			}
			if strings.Contains(line, "/*") || strings.Contains(line, "//") || strings.Contains(line, "#") {
				return bad()
			}
			if end := strings.Index(line, "*/"); end >= 0 {
				if strings.TrimSpace(line[end+2:]) != "" {
					return bad()
				}
				inBlock = false
			}
			continue
		}
		for i := 0; i < len(line); {
			if line[i] == ' ' || line[i] == '\t' {
				i++
				continue
			}
			if strings.HasPrefix(line[i:], "//") {
				break
			}
			if line[i] == '#' && !strings.HasPrefix(line[i:], "#clear") && !strings.HasPrefix(line[i:], "#include") && !strings.HasPrefix(line[i:], "#x-apt-configure-index") {
				break
			}
			if strings.ContainsRune("{};", rune(line[i])) {
				tokens = append(tokens, aptToken{value: line[i : i+1]})
				i++
				continue
			}
			if line[i] == '"' {
				// Native ParseQuoteWord merges adjacent name/quote text into one
				// token. Require a separator so it cannot be mistaken for assignment.
				if i > 0 && !strings.ContainsRune(" \t{;", rune(line[i-1])) {
					return bad()
				}
				end := strings.IndexByte(line[i+1:], '"')
				if end < 0 {
					return bad()
				}
				value := line[i+1 : i+1+end]
				if strings.ContainsAny(value, "\\\t") {
					return bad()
				}
				tokens = append(tokens, aptToken{value: value, quoted: true})
				i += end + 2
				continue
			}
			start := i
			for i < len(line) && !strings.ContainsRune(" \t{};\"#", rune(line[i])) {
				i++
			}
			if i == start && line[i] == '#' { // recognized directives only
				i++
				for i < len(line) && (line[i] >= 'a' && line[i] <= 'z' || line[i] == '-') {
					i++
				}
			}
			if i == start {
				return bad()
			}
			tokens = append(tokens, aptToken{value: line[start:i]})
		}
	}
	if inBlock || len(tokens) > 32768 {
		return bad()
	}
	return tokens, nil
}

func aptContextKey(key string) string {
	if strings.HasPrefix(key, "binary::") {
		parts := strings.SplitN(key, "::", 3)
		if len(parts) == 3 {
			return parts[2]
		}
	}
	return key
}
func aptLoadingKey(key string, clear bool) bool {
	key = aptContextKey(key)
	for _, path := range []string{"rootdir", "dir", "dir::etc", "dir::etc::main", "dir::etc::parts"} {
		if key == path || path != "dir" && path != "dir::etc" && strings.HasPrefix(key, path+"::") || clear && strings.HasPrefix(path, key+"::") {
			return true
		}
	}
	return false
}
func (tree aptTree) assign(key, value string) error {
	key = strings.ToLower(key)
	if aptLoadingKey(key, false) {
		return fmt.Errorf("APT 配置入口/根目录重定向未支持")
	}
	context := aptContextKey(key)
	if strings.HasPrefix(key, "binary::") && strings.HasPrefix(context, "binary::") {
		return fmt.Errorf("APT 嵌套 Binary 覆盖未支持")
	}
	for _, b := range aptBoolKeys {
		if strings.HasPrefix(context, b+"::") {
			return fmt.Errorf("APT 安装布尔项不能含列表或子项")
		}
	}
	parts := strings.Split(key, "::")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[:i], "::")
		if _, ok := tree[parent]; !ok {
			tree[parent] = ""
		}
	}
	tree[key] = value
	return nil
}

func (tree aptTree) parse(raw string) error { return tree.parseMode(raw, false) }

func (tree aptTree) parseMode(raw string, sourceMode bool) error {
	tokens, err := aptTokens(raw)
	if err != nil {
		return err
	}
	pos, statements := 0, 0
	var scope func(string, int) error
	scope = func(parent string, depth int) error {
		bad := func() error {
			return fmt.Errorf("APT 配置包含未支持/不完整语法、包含指令或过深作用域")
		}
		if depth > 16 {
			return bad()
		}
		for pos < len(tokens) {
			tok := tokens[pos]
			pos++
			if !tok.quoted && tok.value == "}" {
				if depth == 0 || pos == len(tokens) || tokens[pos].value != ";" || tokens[pos].quoted {
					return bad()
				}
				pos++
				return nil
			}
			statements++
			if statements > 8192 {
				return bad()
			}
			if !tok.quoted && tok.value == "#clear" {
				if depth != 0 || pos+1 >= len(tokens) || !aptName.MatchString(tokens[pos].value) || strings.HasSuffix(tokens[pos].value, "::") || tokens[pos+1].value != ";" || tokens[pos+1].quoted {
					return bad()
				}
				key := strings.ToLower(tokens[pos].value)
				pos += 2
				if aptLoadingKey(key, true) || sourceMode && aptSourceLoadingKey(key, true) {
					return fmt.Errorf("APT 配置加载树清除未支持")
				}
				if _, ok := tree[key]; ok {
					for k := range tree {
						if strings.HasPrefix(k, key+"::") {
							delete(tree, k)
						}
					}
					tree[key] = ""
				}
				continue
			}
			if tok.quoted { // anonymous list entry; never evaluated or executed
				if parent == "" || pos >= len(tokens) || tokens[pos].value != ";" || tokens[pos].quoted {
					return bad()
				}
				pos++
				if sourceMode && aptSourceLoadingKey(parent, false) {
					return fmt.Errorf("APT 软件源加载重定向/额外源未支持")
				}
				if err := tree.assign(fmt.Sprintf("%s::$%d", parent, statements), tok.value); err != nil {
					return err
				}
				continue
			}
			if !aptName.MatchString(tok.value) || len(tok.value) > 256 {
				return bad()
			}
			key := tok.value
			if parent != "" {
				key = parent + "::" + key
			}
			if pos >= len(tokens) {
				return bad()
			}
			next := tokens[pos]
			pos++
			if !next.quoted && next.value == "{" {
				if strings.HasSuffix(key, "::") {
					return bad()
				}
				if err := scope(key, depth+1); err != nil {
					return err
				}
			} else if next.quoted {
				if pos >= len(tokens) || tokens[pos].value != ";" || tokens[pos].quoted {
					return bad()
				}
				pos++
				if strings.HasSuffix(key, "::") {
					key += fmt.Sprintf("$%d", statements)
				}
				if sourceMode && aptSourceLoadingKey(key, false) {
					return fmt.Errorf("APT 软件源加载重定向/额外源未支持")
				}
				if err := tree.assign(key, next.value); err != nil {
					return err
				}
			} else {
				return bad()
			}
		}
		if depth != 0 {
			return bad()
		}
		return nil
	}
	return scope("", 0)
}

func aptBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "", "0", "false", "no", "off", "without", "disable":
		return false, nil
	case "1", "true", "yes", "on", "with", "enable":
		return true, nil
	}
	return false, fmt.Errorf("APT 安装策略布尔值未支持；不采用未知值的成功默认值")
}
func (tree aptTree) resolved(binary, key string) (bool, string, error) {
	value, ok := tree[key]
	origin := "global"
	if v, exists := tree["binary::"+binary+"::"+key]; exists {
		value, ok, origin = v, true, "binary"
	}
	if !ok || value == "" {
		origin += "-default"
	}
	b, err := aptBool(value)
	return b, origin, err
}
