package baseline

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var aptSourceBoolKeys = []string{"acquire::allowinsecurerepositories", "acquire::allowweakrepositories", "acquire::allowdowngradetoinsecurerepositories"}
var aptSourceOptions = []string{"allow-insecure", "allow-weak", "allow-downgrade-to-insecure"}
var aptSourceHost = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
var aptSourceWord = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*$`)
var aptKeyringName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]*\.(gpg|asc)$`)
var aptFingerprint = regexp.MustCompile(`^[0-9A-Fa-f]{40}!?$`)

type aptSourceDeclaration struct {
	uri, suite, trusted, signedBy string
	options                       map[string]string
}
type aptSources struct {
	declarations []aptSourceDeclaration
	disabled     int
}

func aptSourceSelected(name string) bool {
	if strings.HasPrefix(name, ".") || !aptPartName.MatchString(name) {
		return false
	}
	return strings.HasSuffix(name, ".list") || strings.HasSuffix(name, ".sources")
}

// Every accepted declaration is interpreted. Unknown fields/options, duplicate
// fields and syntax that needs native URI transformations remain execution errors.
func (s *aptSources) parse(raw string, deb822 bool) error {
	for _, line := range strings.Split(raw, "\n") {
		if len(line) > 4096 {
			return fmt.Errorf("APT 软件源行超过4096字节")
		}
		for _, c := range []byte(line) {
			if c != '\t' && (c < 32 || c > 126) {
				return fmt.Errorf("APT 软件源仅支持 ASCII/LF")
			}
		}
	}
	if deb822 {
		return s.parseDeb822(raw)
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, "\"'\\") {
			return fmt.Errorf("APT 单行源引号/转义未支持")
		}
		words := strings.Fields(line)
		if len(words) < 4 || words[0] != "deb" && words[0] != "deb-src" {
			return fmt.Errorf("APT 单行源类型或结构未支持")
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, words[0]))
		opts := map[string]string{}
		if strings.HasPrefix(rest, "[") {
			end := strings.IndexByte(rest, ']')
			if end < 0 || end+1 >= len(rest) || rest[end+1] != ' ' && rest[end+1] != '\t' {
				return fmt.Errorf("APT 软件源选项括号未支持")
			}
			for _, token := range strings.Fields(rest[1:end]) {
				kv := strings.SplitN(token, "=", 2)
				if len(kv) != 2 || kv[1] == "" {
					return fmt.Errorf("APT 软件源需非空选项赋值")
				}
				if _, exists := opts[kv[0]]; exists {
					return fmt.Errorf("APT 软件源重复选项未支持")
				}
				switch kv[0] {
				case "trusted", "signed-by", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure":
				case "arch":
					for _, v := range strings.Split(kv[1], ",") {
						if !aptSourceWord.MatchString(v) {
							return fmt.Errorf("APT 源架构未支持")
						}
					}
				default:
					return fmt.Errorf("APT 软件源包含未支持选项")
				}
				opts[kv[0]] = kv[1]
			}
			rest = strings.TrimSpace(rest[end+1:])
		}
		words = strings.Fields(rest)
		if len(words) < 3 {
			return fmt.Errorf("APT 软件源缺URI/发行套件/组件")
		}
		if err := s.add([]string{words[0]}, []string{words[1]}, words[2:], opts); err != nil {
			return err
		}
	}
	return nil
}
func (s *aptSources) parseDeb822(raw string) error {
	fields := map[string]string{}
	previous := ""
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		// APT returns before validating disabled stanza content. We still constrain
		// the complete grammar/known field set, but do not inspect disabled keyrings.
		if v, ok := fields["enabled"]; ok {
			if v == "" {
				return fmt.Errorf("APT Enabled需明确布尔值")
			}
			b, err := aptBool(v)
			if err != nil {
				return err
			}
			if !b {
				s.disabled++
				fields = map[string]string{}
				previous = ""
				return nil
			}
		}
		types := strings.Fields(fields["types"])
		if len(types) == 0 || len(types) > 2 {
			return fmt.Errorf("APT Deb822源缺Types或类型超限")
		}
		seen := map[string]bool{}
		for _, typ := range types {
			if typ != "deb" && typ != "deb-src" || seen[typ] {
				return fmt.Errorf("APT Deb822源Types未支持")
			}
			seen[typ] = true
		}
		opts := map[string]string{}
		for _, key := range []string{"trusted", "signed-by"} {
			if v, ok := fields[key]; ok {
				opts[key] = v
			}
		}
		if v, ok := fields["architectures"]; ok {
			for _, w := range strings.Fields(v) {
				if !aptSourceWord.MatchString(w) {
					return fmt.Errorf("APT 源架构未支持")
				}
			}
		}
		if err := s.add(strings.Fields(fields["uris"]), strings.Fields(fields["suites"]), strings.Fields(fields["components"]), opts); err != nil {
			return err
		}
		fields = map[string]string{}
		previous = ""
		return nil
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if previous == "" {
				return fmt.Errorf("APT Deb822无前置字段的续行未支持")
			}
			fields[previous] += " " + strings.TrimSpace(line)
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 1 {
			return fmt.Errorf("APT Deb822字段结构未支持")
		}
		key := strings.ToLower(line[:colon])
		switch key {
		case "types", "uris", "suites", "components", "signed-by", "trusted", "enabled", "architectures":
		default:
			return fmt.Errorf("APT Deb822未知字段或未支持原生映射；包括 Allow-Insecure/Allow-Weak/Allow-Downgrade-To-Insecure")
		}
		if _, ok := fields[key]; ok {
			return fmt.Errorf("APT Deb822重复字段未支持")
		}
		fields[key] = strings.TrimSpace(line[colon+1:])
		previous = key
	}
	return flush()
}
func (s *aptSources) add(uris, suites, components []string, opts map[string]string) error {
	if len(uris) == 0 || len(suites) == 0 || len(components) == 0 || len(uris) > 8 || len(suites) > 8 || len(components) > 16 {
		return fmt.Errorf("APT 软件源范围缺失或超限")
	}
	for _, word := range append(slices.Clone(suites), components...) {
		if !aptSourceWord.MatchString(word) {
			return fmt.Errorf("APT 套件/组件仅支持普通名称；平坦源和变量未支持")
		}
	}
	trusted := "unset"
	if v, ok := opts["trusted"]; ok {
		if v == "" {
			return fmt.Errorf("APT Trusted需明确布尔值")
		}
		b, err := aptBool(v)
		if err != nil {
			return err
		}
		trusted = fmt.Sprint(b)
	}
	for _, key := range aptSourceOptions {
		if v, ok := opts[key]; ok {
			if _, err := aptBool(v); err != nil {
				return err
			}
		}
	}
	by, err := aptSignedBy(opts["signed-by"])
	if err != nil {
		return err
	}
	for _, rawURI := range uris {
		u, err := url.Parse(rawURI)
		if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.ContainsAny(rawURI, "%$[]\\?#") || strings.ToLower(u.Host) != u.Host || !strings.HasPrefix(rawURI, u.Scheme+"://") || u.String() != rawURI {
			return fmt.Errorf("APT URI仅支持有限无凭据HTTP/HTTPS地址")
		}
		if u.Path != "" && path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
			return fmt.Errorf("APT URI路径规范化未支持")
		}
		host := u.Hostname()
		if strings.Contains(u.Host, ":") {
			n, err := strconv.Atoi(u.Port())
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("APT URI端口未支持")
			}
			u.Host = host + ":" + strconv.Itoa(n)
		}
		if !aptSourceHost.MatchString(host) {
			return fmt.Errorf("APT URI主机名未支持")
		}
		normalized := strings.TrimSuffix(u.String(), "/") + "/"
		for _, suite := range suites {
			if len(s.declarations) >= 64 {
				return fmt.Errorf("APT 超过64个URI/套件声明")
			}
			s.declarations = append(s.declarations, aptSourceDeclaration{uri: normalized, suite: suite, trusted: trusted, signedBy: by, options: opts})
		}
	}
	return nil
}

func aptSignedBy(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	values := strings.FieldsFunc(raw, func(c rune) bool { return c == ' ' || c == '\t' || c == ',' })
	if len(values) == 0 || len(values) > 16 {
		return "", fmt.Errorf("APT Signed-By范围为空或超限")
	}
	seen := map[string]bool{}
	for i, v := range values {
		if strings.HasPrefix(v, "/") {
			dir := path.Dir(v)
			if dir != "/etc/apt/keyrings" && dir != "/usr/share/keyrings" || !aptKeyringName.MatchString(path.Base(v)) || path.Clean(v) != v {
				return "", fmt.Errorf("APT Signed-By仅支持两个固定keyrings目录的直接.gpg/.asc文件")
			}
		} else if aptFingerprint.MatchString(v) {
			values[i] = strings.ToUpper(v)
		} else {
			return "", fmt.Errorf("APT Signed-By嵌入密钥或未知选择器未支持")
		}
		if seen[values[i]] {
			return "", fmt.Errorf("APT Signed-By重复选择器未支持")
		}
		seen[values[i]] = true
	}
	return strings.Join(values, ","), nil
}

func evaluateAPTSources(tree aptTree, s *aptSources, checkKey func(string) error) ItemResult {
	failed := len(s.declarations) == 0
	actual := ""
	for _, binary := range []string{"apt", "apt-get"} {
		for _, key := range aptSourceBoolKeys {
			v, origin, err := tree.resolved(binary, key)
			if err != nil {
				return ItemResult{Error: true, Message: err.Error()}
			}
			failed = failed || v
			actual += fmt.Sprintf("%s.%s=%t(%s) ", binary, strings.TrimPrefix(key, "acquire::"), v, origin)
		}
	}
	keys := map[string]bool{}
	releases := map[string]aptSourceDeclaration{}
	trusted, bypass, missing := 0, 0, 0
	for _, d := range s.declarations {
		id := d.uri + "\n" + d.suite
		if old, ok := releases[id]; ok {
			if old.signedBy != d.signedBy || old.trusted != d.trusted {
				return ItemResult{Error: true, Message: "APT 同URI/套件声明的认证或Signed-By范围不一致"}
			}
			for _, key := range aptSourceOptions {
				if old.options[key] != d.options[key] {
					return ItemResult{Error: true, Message: "APT 同URI/套件声明的绕过选项不一致"}
				}
			}
		} else {
			releases[id] = d
		}
		if d.trusted == "true" {
			trusted++
		}
		for _, key := range aptSourceOptions {
			if v, ok := d.options[key]; ok {
				b, err := aptBool(v)
				if err != nil {
					return ItemResult{Error: true, Message: err.Error()}
				}
				if b {
					bypass++
				}
			}
		}
		count := 0
		for _, value := range strings.Split(d.signedBy, ",") {
			if !strings.HasPrefix(value, "/") {
				continue
			}
			count++
			if !keys[value] {
				if len(keys) >= 16 {
					return ItemResult{Error: true, Message: "APT 超过16个不同keyring文件"}
				}
				if err := checkKey(value); err != nil {
					return ItemResult{Error: true, Message: err.Error()}
				}
				keys[value] = true
			}
		}
		if count == 0 {
			missing++
		}
	}
	failed = failed || trusted > 0 || bypass > 0 || missing > 0
	actual += fmt.Sprintf("active_declarations=%d releases=%d disabled_stanzas=%d trusted_yes=%d source_bypass_yes=%d missing_explicit_keyring=%d keyring_files=%d", len(s.declarations), len(releases), s.disabled, trusted, bypass, missing, len(keys))
	r := ItemResult{Passed: !failed, Actual: actual}
	if failed {
		r.Message = "APT 软件源磁盘声明存在认证绕过、缺显式文件签名范围或无活动源，未满足参考"
	}
	return r
}

func aptSourceLoadingKey(key string, clear bool) bool {
	key = aptContextKey(strings.ToLower(key))
	for _, banned := range []string{"dir::etc::sourcelist", "dir::etc::sourceparts", "apt::sources::with"} {
		if key == banned || strings.HasPrefix(key, banned+"::") || clear && strings.HasPrefix(banned, key+"::") {
			return true
		}
	}
	return false
}
