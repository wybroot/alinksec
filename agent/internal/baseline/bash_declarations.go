package baseline

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type bashDeclaredVariable struct {
	value                        string
	assigned, readonly, exported bool
}
type bashDeclarations struct {
	variables  map[string]bashDeclaredVariable
	mask       string
	statements int
}

var bashDeclaredNumber = regexp.MustCompile(`^(?:-1|0|[1-9][0-9]*)$`)
var bashDeclaredMask = regexp.MustCompile(`^(?:[0-7]{3}|0[0-7]{3})$`)

func newBashDeclarations() *bashDeclarations {
	return &bashDeclarations{variables: map[string]bashDeclaredVariable{}}
}
func bashSelectedVariable(name string) bool {
	return name == "TMOUT" || name == "HISTTIMEFORMAT" || name == "HISTSIZE" || name == "HISTFILESIZE"
}

// A finite literal language. Never execute or ignore unknown shell commands.
func bashDeclarationWords(line string) ([]string, error) {
	var words []string
	start := -1
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c < 32 && c != '\t' || c > 126 || strings.ContainsRune("$`\\;|&()<>", rune(c)) {
			return nil, fmt.Errorf("unsupported character")
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			if start < 0 {
				start = i
			}
			quote = c
		} else if c == ' ' || c == '\t' {
			if start >= 0 {
				words = append(words, line[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated literal")
	}
	if start >= 0 {
		words = append(words, line[start:])
	}
	return words, nil
}
func bashDeclarationLiteral(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if raw[0] == '\'' || raw[0] == '"' {
		if len(raw) < 2 || raw[len(raw)-1] != raw[0] || strings.ContainsAny(raw[1:len(raw)-1], "'\"") {
			return "", fmt.Errorf("only one complete literal supported")
		}
		return raw[1 : len(raw)-1], nil
	}
	if strings.ContainsAny(raw, "'\" \t#") {
		return "", fmt.Errorf("unsupported literal")
	}
	return raw, nil
}
func (d *bashDeclarations) assign(word, attribute string) error {
	name, raw, assigned := strings.Cut(word, "=")
	if !bashSelectedVariable(name) || !assigned && attribute == "" {
		return fmt.Errorf("unsupported variable")
	}
	state := d.variables[name]
	if assigned {
		if state.readonly {
			return fmt.Errorf("assignment to readonly declaration")
		}
		value, err := bashDeclarationLiteral(raw)
		if err != nil {
			return err
		}
		if name != "HISTTIMEFORMAT" {
			if !bashDeclaredNumber.MatchString(value) {
				return fmt.Errorf("canonical decimal required")
			}
			if _, err := strconv.ParseInt(value, 10, 32); err != nil {
				return fmt.Errorf("out of range")
			}
		}
		state.value, state.assigned = value, true
	}
	if attribute == "readonly" {
		state.readonly = true
	}
	if attribute == "export" {
		state.exported = true
	}
	d.variables[name] = state
	return nil
}
func (d *bashDeclarations) parse(body string) error {
	for _, raw := range strings.Split(body, "\n") {
		if len(raw) > 1024 {
			return fmt.Errorf("line exceeds 1024 bytes")
		}
		line := strings.Trim(raw, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d.statements++
		if d.statements > 512 {
			return fmt.Errorf("more than512 statements")
		}
		words, err := bashDeclarationWords(line)
		if err != nil || len(words) == 0 {
			return fmt.Errorf("unsupported syntax")
		}
		switch words[0] {
		case "umask":
			if len(words) != 2 || !bashDeclaredMask.MatchString(words[1]) {
				return fmt.Errorf("literal octal umask required")
			}
			mask, _ := strconv.ParseUint(words[1], 8, 16)
			d.mask = fmt.Sprintf("%03o", mask)
		case "export", "readonly":
			if len(words) < 2 {
				return fmt.Errorf("selected variables required")
			}
			for _, word := range words[1:] {
				if err := d.assign(word, words[0]); err != nil {
					return err
				}
			}
		case "unset":
			if len(words) < 2 {
				return fmt.Errorf("selected variables required")
			}
			for _, name := range words[1:] {
				if !bashSelectedVariable(name) || d.variables[name].readonly {
					return fmt.Errorf("unsupported or readonly unset")
				}
				delete(d.variables, name)
			}
		default:
			if len(words) != 1 {
				return fmt.Errorf("commands unsupported")
			}
			if err := d.assign(words[0], ""); err != nil {
				return err
			}
		}
	}
	return nil
}
func (d *bashDeclarations) result(option string) ItemResult {
	text := func(name string) string {
		s := d.variables[name]
		if !s.assigned {
			return "absent"
		}
		return s.value
	}
	number := func(name string) int64 { n, _ := strconv.ParseInt(text(name), 10, 32); return n }
	timeout, format := d.variables["TMOUT"], d.variables["HISTTIMEFORMAT"]
	formatState := "absent"
	if format.assigned {
		formatState = "other"
		if format.value == "%F %T %z " {
			formatState = "iso_date_time_zone"
		}
	}
	mask := d.mask
	if mask == "" {
		mask = "absent"
	}
	passed := false
	switch option {
	case "login_timeout":
		passed = timeout.assigned && number("TMOUT") >= 1 && number("TMOUT") <= 600 && timeout.readonly && timeout.exported
	case "login_umask", "nonlogin_umask":
		passed = mask == "027" || mask == "077"
	case "history_time":
		passed = formatState == "iso_date_time_zone"
	case "history_capacity":
		passed = number("HISTSIZE") >= 1000 && number("HISTSIZE") <= 10000 && number("HISTFILESIZE") >= 1000 && number("HISTFILESIZE") <= 10000
	}
	actual := fmt.Sprintf("TMOUT=%s timeout_readonly=%t timeout_exported=%t umask=%s history_time_format=%s HISTSIZE=%s HISTFILESIZE=%s statements=%d", text("TMOUT"), timeout.readonly, timeout.exported, mask, formatState, text("HISTSIZE"), text("HISTFILESIZE"), d.statements)
	if format.assigned {
		actual += fmt.Sprintf(" format_bytes=%d format_sha256=%x", len(format.value), sha256.Sum256([]byte(format.value)))
	}
	result := ItemResult{Passed: passed, Actual: actual}
	if !passed {
		result.Message = "Bash全局启动声明未满足该项有限参考；个人配置、现存Shell及实际执行未验证"
	}
	return result
}
