package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// busctl get-property v255 emits a variant object: data is the property value,
// not a method's tuple wrapper. Preserve argv boundaries and integer precision.
func maintenanceBusData(q ItemResult, signature string) (json.RawMessage, error) {
	if q.Error || len(q.Actual) > 64*1024 {
		return nil, fmt.Errorf("维护结构化查询失败或超限")
	}
	d := json.NewDecoder(strings.NewReader(q.Actual))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("维护结构化结果不是对象")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok || (name != "type" && name != "data") {
			return nil, fmt.Errorf("维护结构化字段未知")
		}
		if _, exists := fields[name]; exists {
			return nil, fmt.Errorf("维护结构化字段重复")
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		fields[name] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF || len(fields) != 2 {
		return nil, fmt.Errorf("维护结构化结果不完整或含尾部")
	}
	var kind string
	if json.Unmarshal(fields["type"], &kind) != nil || kind != signature || string(fields["data"]) == "null" {
		return nil, fmt.Errorf("维护结构化签名或值未知")
	}
	return fields["data"], nil
}
func maintenanceUint(raw json.RawMessage, bits int) (uint64, error) {
	v, err := strconv.ParseUint(string(raw), 10, bits)
	if err != nil || strconv.FormatUint(v, 10) != string(raw) {
		return 0, fmt.Errorf("维护结构化整数非规范或越界")
	}
	return v, nil
}

type maintenanceCommand struct {
	Path         string
	Argv         []string
	Ignore       bool
	Timestamps   [4]uint64
	PID          uint32
	Code, Status int32
	Digest       string
}

func parseMaintenanceCommand(q ItemResult) (maintenanceCommand, error) {
	var result maintenanceCommand
	raw, err := maintenanceBusData(q, "a(sasbttttuii)")
	if err != nil {
		return result, err
	}
	var commands [][]json.RawMessage
	if json.Unmarshal(raw, &commands) != nil || len(commands) > 8 {
		return result, fmt.Errorf("维护ExecStart数组格式未知或超过8命令")
	}
	// Empty or multiple start commands are complete known mismatches. Each entry
	// still has to satisfy the selected typed ABI; no malformed entry is ignored.
	for i, c := range commands {
		if len(c) != 10 {
			return result, fmt.Errorf("维护ExecStart结构不完整")
		}
		var command maintenanceCommand
		if len(c[0]) == 0 || c[0][0] != '"' || json.Unmarshal(c[0], &command.Path) != nil || len(command.Path) > 1024 {
			return result, fmt.Errorf("维护命令路径未知")
		}
		var argv []json.RawMessage
		if json.Unmarshal(c[1], &argv) != nil || string(c[1]) == "null" || len(argv) > 32 {
			return result, fmt.Errorf("维护argv格式未知或超限")
		}
		for _, arg := range argv {
			var value string
			if len(arg) == 0 || arg[0] != '"' || json.Unmarshal(arg, &value) != nil || len(value) > 1024 {
				return result, fmt.Errorf("维护argv类型未知或超限")
			}
			command.Argv = append(command.Argv, value)
		}
		if string(c[2]) != "true" && string(c[2]) != "false" {
			return result, fmt.Errorf("维护命令忽略错误标记未知")
		}
		command.Ignore = string(c[2]) == "true"
		for j := 0; j < 4; j++ {
			v, e := maintenanceUint(c[3+j], 64)
			if e != nil {
				return result, e
			}
			command.Timestamps[j] = v
		}
		pid, e := maintenanceUint(c[7], 32)
		if e != nil {
			return result, e
		}
		command.PID = uint32(pid)
		for j, dst := range []*int32{&command.Code, &command.Status} {
			v, e := strconv.ParseInt(string(c[8+j]), 10, 32)
			if e != nil || strconv.FormatInt(v, 10) != string(c[8+j]) {
				return result, fmt.Errorf("维护退出状态类型未知")
			}
			*dst = int32(v)
		}
		if len(commands) == 1 && i == 0 {
			result = command
		}
	}
	result.Digest = fmt.Sprintf("%x", sha256.Sum256(raw))
	return result, nil
}
func (c maintenanceCommand) matches(option string) bool {
	if c.Ignore {
		return false
	}
	if option == "tmpfiles_clean" {
		return c.Path == "/usr/bin/systemd-tmpfiles" && len(c.Argv) == 2 && (c.Argv[0] == "systemd-tmpfiles" || c.Argv[0] == c.Path) && c.Argv[1] == "--clean"
	}
	return option == "time_sync" && c.Path == "/usr/lib/systemd/systemd-timesyncd" && len(c.Argv) == 1 && (c.Argv[0] == "systemd-timesyncd" || c.Argv[0] == c.Path)
}
