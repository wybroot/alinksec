//go:build windows

package baseline

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var securityNetapi = windows.NewLazySystemDLL("netapi32.dll")
var securityModals = securityNetapi.NewProc("NetUserModalsGet")
var securityBufferFree = securityNetapi.NewProc("NetApiBufferFree")
var securityAdvapi = windows.NewLazySystemDLL("advapi32.dll")
var securityAuditQuery = securityAdvapi.NewProc("AuditQuerySystemPolicy")
var securityAuditFree = securityAdvapi.NewProc("AuditFree")

func checkWindowsSecurity(s *CheckSpec) ItemResult {
	if s.Option == "smb1" {
		return checkCmdOutput(&CheckSpec{Type: "cmd_output", Cmd: windowsSMB1Query, Operator: "regex", Expected: "^(Disabled|DisabledWithPayloadRemoved)$", TimeoutMs: s.TimeoutMs})
	}
	passed, actual, err := observeWindowsSecurity(s.Option)
	if err != nil {
		return ItemResult{Error: true, Actual: actual, Message: err.Error()}
	}
	return ItemResult{Passed: passed, Actual: "scope=local-machine domain_fine_grained_policy=unverified application_accounts=unverified session_behavior=unverified " + actual, Message: "项目建议参考；需结合条款人工证据核验"}
}

func observeWindowsSecurity(option string) (bool, string, error) {
	if option == "password_length" || option == "password_age" || option == "password_history" || option == "lockout" {
		level := uintptr(0)
		if option == "lockout" {
			level = 3
		}
		var p uintptr
		code, _, _ := securityModals.Call(0, level, uintptr(unsafe.Pointer(&p)))
		if code != 0 {
			return false, "", fmt.Errorf("NetUserModalsGet: %d", code)
		}
		if p == 0 {
			return false, "", fmt.Errorf("NetUserModalsGet returned no policy")
		}
		defer securityBufferFree.Call(p)
		if level == 3 {
			v := *(*[3]uint32)(unsafe.Pointer(p)) // duration, observation window, threshold
			actual := fmt.Sprintf("lockout_duration_seconds=%d reset_seconds=%d threshold=%d", v[0], v[1], v[2])
			return v[2] >= 1 && v[2] <= 5 && v[0] >= 900 && v[1] >= 900 && v[1] <= v[0], actual, nil
		}
		v := *(*[5]uint32)(unsafe.Pointer(p)) // min length, max age, min age, force logoff, history
		switch option {
		case "password_length":
			return v[0] >= 12, fmt.Sprintf("minimum_length=%d", v[0]), nil
		case "password_age":
			return v[1] >= 86400 && v[1] <= 90*86400 && v[2] >= 86400 && v[2] <= v[1], fmt.Sprintf("maximum_age_seconds=%d minimum_age_seconds=%d", v[1], v[2]), nil
		default:
			return v[4] >= 5, fmt.Sprintf("password_history=%d", v[4]), nil
		}
	}
	ids := map[string]string{"audit_logon": "0cce9215", "audit_account": "0cce9235", "audit_policy": "0cce922f", "audit_integrity": "0cce9212"}
	if id, ok := ids[option]; ok {
		// Read the live advanced audit policy by GUID, independent of UI language.
		enableBaselineAuditQuery()
		guid, err := windows.GUIDFromString("{" + id + "-69ae-11d9-bed3-505054503030}")
		if err != nil {
			return false, "", err
		}
		var p uintptr
		success, _, callErr := securityAuditQuery.Call(uintptr(unsafe.Pointer(&guid)), 1, uintptr(unsafe.Pointer(&p)))
		if success == 0 {
			return false, "", fmt.Errorf("AuditQuerySystemPolicy: %w", callErr)
		}
		if p == 0 {
			return false, "", fmt.Errorf("AuditQuerySystemPolicy returned no policy")
		}
		defer securityAuditFree.Call(p)
		v := (*struct {
			Sub      windows.GUID
			Flags    uint32
			Category windows.GUID
		})(unsafe.Pointer(p))
		if v.Sub != guid {
			return false, "", fmt.Errorf("audit subcategory mismatch")
		}
		return v.Flags&3 == 3, fmt.Sprintf("subcategory=%s success=%t failure=%t", id, v.Flags&1 != 0, v.Flags&2 != 0), nil
	}
	read := func(path, name string) (uint64, error) {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			return 0, err
		}
		defer key.Close()
		value, kind, err := key.GetIntegerValue(name)
		if err == nil && kind != registry.DWORD {
			return 0, fmt.Errorf("%s is not REG_DWORD", name)
		}
		return value, err
	}
	path, name := `SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`, "UserAuthentication"
	switch option {
	case "rdp_tls":
		name = "SecurityLayer"
	case "ntlm":
		path, name = `SYSTEM\CurrentControlSet\Control\Lsa`, "LmCompatibilityLevel"
	case "idle_timeout":
		path, name = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "InactivityTimeoutSecs"
	case "rdp_nla":
	default:
		return false, "", fmt.Errorf("unsupported security option")
	}
	v, err := read(path, name)
	if err != nil {
		return false, "", fmt.Errorf("registry %s/%s unavailable: %w", path, name, err)
	}
	actual := fmt.Sprintf("%s=%d", name, v)
	switch option {
	case "rdp_nla":
		return v == 1, actual, nil
	case "rdp_tls":
		encryption, err := read(path, "MinEncryptionLevel")
		return v == 2 && encryption >= 3, actual + fmt.Sprintf(" MinEncryptionLevel=%d", encryption), err
	case "ntlm":
		return v == 5, actual, nil
	case "idle_timeout":
		return v >= 1 && v <= 900, actual, nil
	default:
		return false, actual, fmt.Errorf("unsupported security option")
	}
}

func enableBaselineAuditQuery() {
	// LocalSystem may own this privilege with its token flag disabled. Enabling
	// an already granted privilege does not change the machine's audit policy;
	// an unprivileged token cannot acquire it and the query reports that error.
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token) != nil {
		return
	}
	defer token.Close()
	name, _ := windows.UTF16PtrFromString("SeSecurityPrivilege")
	var luid windows.LUID
	if windows.LookupPrivilegeValue(nil, name, &luid) != nil {
		return
	}
	priv := windows.Tokenprivileges{PrivilegeCount: 1}
	priv.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	_ = windows.AdjustTokenPrivileges(token, false, &priv, 0, nil, nil)
}
