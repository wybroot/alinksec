//go:build windows

package windowslogin

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wevtapi = windows.NewLazySystemDLL("wevtapi.dll")
var evtQuery = wevtapi.NewProc("EvtQuery")
var evtNext = wevtapi.NewProc("EvtNext")
var evtRender = wevtapi.NewProc("EvtRender")
var evtClose = wevtapi.NewProc("EvtClose")
var advapi = windows.NewLazySystemDLL("advapi32.dll")
var auditQuery = advapi.NewProc("AuditQuerySystemPolicy")
var auditFree = advapi.NewProc("AuditFree")

type nativeReader struct{}

func newReader() Reader        { enableSecurityPrivilege(); return nativeReader{} }
func platformContract() uint32 { return 1 }
func (nativeReader) Latest() (Record, error) {
	r, err := query("*", 1, true)
	if err != nil || len(r) == 0 {
		return Record{}, err
	}
	return r[0], nil
}
func (nativeReader) Find(id uint64) (Record, error) {
	r, err := query(fmt.Sprintf("*[System[EventRecordID=%d]]", id), 1, false)
	if err != nil || len(r) == 0 {
		return Record{}, err
	}
	return r[0], nil
}
func (nativeReader) After(id, upper uint64, limit int) ([]Record, error) {
	if limit < 1 || limit > batchSize {
		return nil, fmt.Errorf("invalid batch size")
	}
	return query(fmt.Sprintf("*[System[Provider[@Name='%s'] and (EventID=4624 or EventID=4625) and EventRecordID>%d and EventRecordID<=%d]]", provider, id, upper), limit, false)
}
func query(xpath string, limit int, reverse bool) ([]Record, error) {
	// Microsoft requires every operation on a query handle on its creating thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	channel, _ := windows.UTF16PtrFromString("Security")
	q, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, err
	}
	flags := uintptr(1 | 0x100)
	if reverse {
		flags = 1 | 0x200
	}
	h, _, err := evtQuery.Call(0, uintptr(unsafe.Pointer(channel)), uintptr(unsafe.Pointer(q)), flags)
	if h == 0 {
		return nil, fmt.Errorf("EvtQuery: %w", err)
	}
	defer evtClose.Call(h)
	var result []Record
	for len(result) < limit {
		var event uintptr
		var count uint32
		ok, _, err := evtNext.Call(h, 1, uintptr(unsafe.Pointer(&event)), 1000, 0, uintptr(unsafe.Pointer(&count)))
		if ok == 0 {
			if errors.Is(err, syscall.Errno(259)) {
				break
			}
			return nil, fmt.Errorf("EvtNext: %w", err)
		}
		if count != 1 || event == 0 {
			return nil, fmt.Errorf("EvtNext invalid result")
		}
		data, err := render(event)
		evtClose.Call(event)
		if err != nil {
			return nil, err
		}
		r, err := Parse(data)
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
func render(h uintptr) ([]byte, error) {
	var needed, properties uint32
	ok, _, err := evtRender.Call(0, h, 1, 0, 0, uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 && !errors.Is(err, syscall.Errno(122)) {
		return nil, fmt.Errorf("EvtRender size: %w", err)
	}
	// UTF-16 bytes can expand up to 3/2 when rendered to UTF-8; Parse applies
	// the final 64 KiB cap too. Never allocate the untrusted requested size.
	if needed < 2 || needed > maxXML || needed%2 != 0 {
		return nil, fmt.Errorf("event_size")
	}
	buf := make([]uint16, needed/2)
	ok, _, err = evtRender.Call(0, h, 1, uintptr(needed), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return nil, fmt.Errorf("EvtRender: %w", err)
	}
	return []byte(windows.UTF16ToString(buf)), nil
}
func (nativeReader) Audit() (bool, bool, error) {
	// Audit Logon subcategory, queried without changing machine audit policy.
	guid, err := windows.GUIDFromString("{0cce9215-69ae-11d9-bed3-505054503030}")
	if err != nil {
		return false, false, err
	}
	var p uintptr
	ok, _, err := auditQuery.Call(uintptr(unsafe.Pointer(&guid)), 1, uintptr(unsafe.Pointer(&p)))
	if ok == 0 {
		return false, false, fmt.Errorf("AuditQuerySystemPolicy: %w", err)
	}
	if p == 0 {
		return false, false, fmt.Errorf("empty audit policy")
	}
	defer auditFree.Call(p)
	info := (*struct {
		Sub      windows.GUID
		Flags    uint32
		Category windows.GUID
	})(unsafe.Pointer(p))
	return info.Flags&1 != 0, info.Flags&2 != 0, nil
}

// LocalSystem owns this privilege, but it may be disabled in the service token.
// An unprivileged token cannot acquire it; Audit/Latest expose that failure.
func enableSecurityPrivilege() {
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
