//go:build windows && amd64

package filetrace

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/alinksec/alinksec-agent/internal/securestate"
	"golang.org/x/sys/windows"
)

// SDK ABI: evntrace.h / evntcons.h / tdh.h. No CGO or external collector.
var (
	advapi          = windows.NewLazySystemDLL("advapi32.dll")
	startTrace      = advapi.NewProc("StartTraceW")
	controlTrace    = advapi.NewProc("ControlTraceW")
	enableTrace     = advapi.NewProc("EnableTraceEx2")
	openTrace       = advapi.NewProc("OpenTraceW")
	processTrace    = advapi.NewProc("ProcessTrace")
	closeTrace      = advapi.NewProc("CloseTrace")
	tdh             = windows.NewLazySystemDLL("tdh.dll")
	getProperty     = tdh.NewProc("TdhGetProperty")
	enumFields      = tdh.NewProc("TdhEnumerateProviderFieldInformation")
	kernel32        = windows.NewLazySystemDLL("kernel32.dll")
	threadPID       = kernel32.NewProc("GetProcessIdOfThread")
	threadTimes     = kernel32.NewProc("GetThreadTimes")
	queryDosDevice  = kernel32.NewProc("QueryDosDeviceW")
	criticalProcess = kernel32.NewProc("IsProcessCritical")
	fileProvider    = windows.GUID{Data1: 0xedd08927, Data2: 0x9cc4, Data3: 0x4e65, Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89}}
	sessions        sync.Map
	nextSession     atomic.Uint64
	recordCallback  = windows.NewCallback(func(p uintptr) uintptr {
		r := (*eventRecord)(unsafe.Pointer(p))
		if s, ok := sessions.Load(r.Context); ok {
			s.(*winTrace).onEvent(r)
		}
		return 0
	})
	bufferCallback = windows.NewCallback(func(p uintptr) uintptr {
		// EVENT_TRACE_LOGFILEW on amd64: EventsLost=416, Context=440.
		b := unsafe.Slice((*byte)(unsafe.Pointer(p)), 448)
		if binary.LittleEndian.Uint32(b[416:]) != 0 {
			if s, ok := sessions.Load(uintptr(binary.LittleEndian.Uint64(b[440:]))); ok {
				s.(*winTrace).m.fail("etw_events_lost")
			}
		}
		return 1
	})
)

type traceProperties struct {
	WnodeSize, ProviderID                                                                         uint32
	History, Timestamp                                                                            uint64
	GUID                                                                                          windows.GUID
	ClientContext, Flags                                                                          uint32
	BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize                                   uint32
	Mode, FlushTimer, EnableFlags, AgeLimit                                                       uint32
	NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost uint32
	LoggerThread                                                                                  uintptr
	LogFileOffset, LoggerNameOffset                                                               uint32
}
type eventRecord struct {
	Size, HeaderType, Flags, Property uint16
	ThreadID, PID                     uint32
	Timestamp                         uint64
	Provider                          windows.GUID
	ID                                uint16
	Version, Channel, Level, Opcode   uint8
	Task                              uint16
	Keyword                           uint64
	ProcessorTime                     uint64
	Activity                          windows.GUID
	BufferContext                     uint32
	ExtendedCount, DataLength         uint16
	Extended, Data, Context           uintptr
}
type propertyDescriptor struct {
	Name            uint64
	Index, Reserved uint32
}
type traceOwner struct {
	Name    string `json:"name"`
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created"`
}
type pendingWrite struct {
	writes  []Write
	object  uint64
	emitter uint32
	at      time.Time
}
type openedFile struct {
	path  string
	at    uint64
	owner Identity
}
type winTrace struct {
	m         *Monitor
	workDir   string
	mu        sync.Mutex // Controller calls, not callbacks.
	handle    uint64
	consumer  uintptr
	key       uintptr
	done      chan error
	unlock    func()
	owner     traceOwner
	objects   map[uint64]openedFile // Accessed only by the serial ETW callback.
	pending   map[uint64]pendingWrite
	devices   map[string]string
	counts    [32]atomic.Uint64
	mapped    atomic.Uint64
	completed atomic.Uint64
	rejected  [4]atomic.Uint64 // Count and last rejected emitter/thread/open-owner PIDs.
	lastSweep time.Time
}

func newNative(m *Monitor, workDir string) native { return &winTrace{m: m, workDir: workDir} }
func props() []byte {
	b := make([]byte, 120+2048)
	p := (*traceProperties)(unsafe.Pointer(&b[0]))
	p.WnodeSize = uint32(len(b))
	p.ClientContext = 1
	p.Flags = 0x20000
	p.BufferSize = 64
	p.MinimumBuffers = 4
	p.MaximumBuffers = 16
	p.Mode = 0x100 | 0x10000000 // REAL_TIME | NO_PER_PROCESSOR_BUFFERING (<=1 MiB requested).
	p.FlushTimer = 1
	p.LoggerNameOffset = 120
	return b
}
func apiError(name string, code uintptr) error {
	if code == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", name, windows.Errno(code))
}
func (s *winTrace) ownerPath() string { return filepath.Join(s.workDir, "ransom-etw", "owner.json") }
func (s *winTrace) prefix() string {
	abs, _ := filepath.Abs(s.workDir)
	sum := sha256.Sum256([]byte(strings.ToLower(abs)))
	return "ALinkSec-Ransom-" + hex.EncodeToString(sum[:8]) + "-"
}
func (s *winTrace) start() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != 0 {
		return fmt.Errorf("session already started")
	}
	s.unlock, err = securestate.Lock(filepath.Dir(s.ownerPath()))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = s.closeLocked()
		}
	}()
	var previous traceOwner
	if e := securestate.ReadJSON(s.ownerPath(), &previous); e == nil {
		if !strings.HasPrefix(previous.Name, s.prefix()) || len(previous.Name) != len(s.prefix())+32 || previous.PID <= 4 || previous.Created == 0 {
			return fmt.Errorf("invalid session ownership")
		}
		if h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, previous.PID); e == nil {
			birth, e := creation(h)
			wait, waitErr := windows.WaitForSingleObject(h, 0)
			windows.CloseHandle(h)
			if e != nil || waitErr != nil || (birth == previous.Created && wait != windows.WAIT_OBJECT_0) {
				return fmt.Errorf("session owner is still present")
			}
		} else if !errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
			return fmt.Errorf("cannot verify previous session owner: %w", e)
		}
		if e := stopNamed(previous.Name); e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return err
	}
	birth, e := creation(windows.CurrentProcess())
	if e != nil {
		return e
	}
	s.owner = traceOwner{Name: s.prefix() + hex.EncodeToString(random[:]), PID: uint32(os.Getpid()), Created: birth}
	// Record ownership before allocating the session, so crash recovery never
	// needs to enumerate, attach to or stop somebody else's trace session.
	if err = securestate.WriteJSON(s.ownerPath(), s.owner); err != nil {
		return err
	}
	name, _ := windows.UTF16PtrFromString(s.owner.Name)
	b := props()
	r, _, _ := startTrace.Call(uintptr(unsafe.Pointer(&s.handle)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&b[0])))
	if err = apiError("StartTraceW", r); err != nil {
		s.handle = 0
		return err
	}
	keywords, e := fileKeywords()
	if e != nil {
		return e
	}
	r, _, _ = enableTrace.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&fileProvider)), 1, 4, uintptr(keywords), 0, 0, 0)
	if err = apiError("EnableTraceEx2", r); err != nil {
		return err
	}
	s.objects = make(map[uint64]openedFile)
	s.pending = make(map[uint64]pendingWrite)
	s.devices = devicePaths()
	s.key = uintptr(nextSession.Add(1))
	sessions.Store(s.key, s)
	// Keep the complete SDK structure, including its output-only headers.
	logfile := make([]uint64, 56)
	lb := unsafe.Slice((*byte)(unsafe.Pointer(&logfile[0])), 448)
	binary.LittleEndian.PutUint64(lb[8:], uint64(uintptr(unsafe.Pointer(name))))
	binary.LittleEndian.PutUint32(lb[28:], 0x100|0x10000000) // REAL_TIME | EVENT_RECORD
	binary.LittleEndian.PutUint64(lb[400:], uint64(bufferCallback))
	binary.LittleEndian.PutUint64(lb[424:], uint64(recordCallback))
	binary.LittleEndian.PutUint64(lb[440:], uint64(s.key))
	s.consumer, _, e = openTrace.Call(uintptr(unsafe.Pointer(&logfile[0])))
	runtime.KeepAlive(name)
	if s.consumer == ^uintptr(0) {
		s.consumer = 0
		return fmt.Errorf("OpenTraceW: %w", e)
	}
	s.done = make(chan error, 1)
	consumer := s.consumer
	done := s.done
	go func() {
		r, _, _ := processTrace.Call(uintptr(unsafe.Pointer(&consumer)), 1, 0, 0)
		done <- apiError("ProcessTrace", r)
	}()
	return nil
}

func stopNamed(name string) error {
	n, _ := windows.UTF16PtrFromString(name)
	b := props()
	r, _, _ := controlTrace.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&b[0])), 1)
	if r == uintptr(windows.ERROR_WMI_INSTANCE_NOT_FOUND) || r == uintptr(windows.ERROR_MORE_DATA) {
		return nil
	}
	return apiError("ControlTrace(stop)", r)
}
func (s *winTrace) check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == 0 {
		return fmt.Errorf("session inactive")
	}
	select {
	case e := <-s.done:
		s.done <- e
		return fmt.Errorf("consumer ended: %v", e)
	default:
	}
	b := props()
	r, _, _ := controlTrace.Call(uintptr(s.handle), 0, uintptr(unsafe.Pointer(&b[0])), 0)
	if e := apiError("ControlTrace(query)", r); e != nil {
		return e
	}
	p := (*traceProperties)(unsafe.Pointer(&b[0]))
	if p.EventsLost != 0 || p.RealTimeBuffersLost != 0 || p.LogBuffersLost != 0 {
		return fmt.Errorf("etw_events_lost")
	}
	return nil
}
func (s *winTrace) close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.closeLocked() }
func (s *winTrace) closeLocked() error {
	var err error
	if s.handle != 0 {
		r, _, _ := enableTrace.Call(uintptr(s.handle), uintptr(unsafe.Pointer(&fileProvider)), 0, 0, 0, 0, 0, 0)
		_ = r // Always attempt stop even when disabling fails.
		err = stopNamed(s.owner.Name)
		if err == nil {
			s.handle = 0
		}
	}
	if s.consumer != 0 {
		closeTrace.Call(s.consumer)
		s.consumer = 0
	}
	if s.done != nil {
		select {
		case <-s.done:
			s.done = nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("consumer shutdown timed out")
		}
	}
	if s.key != 0 {
		sessions.Delete(s.key)
		s.key = 0
	}
	if err == nil && s.owner.Name != "" {
		_ = os.Remove(s.ownerPath())
		s.owner = traceOwner{}
	}
	if s.unlock != nil {
		s.unlock()
		s.unlock = nil
	}
	return err
}

func fileKeywords() (uint64, error) {
	var size uint32
	r, _, _ := enumFields.Call(uintptr(unsafe.Pointer(&fileProvider)), 0, 0, uintptr(unsafe.Pointer(&size)))
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size < 8 || size > 65536 {
		return 0, fmt.Errorf("kernel-file keyword schema unavailable: %d", r)
	}
	b := make([]byte, size)
	r, _, _ = enumFields.Call(uintptr(unsafe.Pointer(&fileProvider)), 0, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)))
	if e := apiError("TdhEnumerateProviderFieldInformation", r); e != nil {
		return 0, e
	}
	wanted := map[string]bool{"KERNEL_FILE_KEYWORD_FILEIO": false, "KERNEL_FILE_KEYWORD_CREATE": false, "KERNEL_FILE_KEYWORD_WRITE": false, "KERNEL_FILE_KEYWORD_OP_END": false}
	var bits uint64
	for i, n := uint32(0), binary.LittleEndian.Uint32(b); i < n; i++ {
		o := 8 + int(i)*16
		if o+16 > len(b) {
			return 0, fmt.Errorf("invalid keyword schema")
		}
		name := utf16At(b, binary.LittleEndian.Uint32(b[o:]))
		if _, ok := wanted[name]; ok {
			wanted[name] = true
			bits |= binary.LittleEndian.Uint64(b[o+8:])
		}
	}
	for name, found := range wanted {
		if !found {
			return 0, fmt.Errorf("missing kernel-file keyword %s", name)
		}
	}
	return bits, nil
}
func utf16At(b []byte, off uint32) string {
	if off >= uint32(len(b)) || off%2 != 0 {
		return ""
	}
	u := make([]uint16, 0, (len(b)-int(off))/2)
	for i := int(off); i+1 < len(b); i += 2 {
		v := binary.LittleEndian.Uint16(b[i:])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return windows.UTF16ToString(u)
}
func property(r *eventRecord, name string, out []byte) bool {
	n, _ := windows.UTF16PtrFromString(name)
	d := propertyDescriptor{Name: uint64(uintptr(unsafe.Pointer(n))), Index: 0xffffffff}
	v, _, _ := getProperty.Call(uintptr(unsafe.Pointer(r)), 0, 0, 1, uintptr(unsafe.Pointer(&d)), uintptr(len(out)), uintptr(unsafe.Pointer(&out[0])))
	runtime.KeepAlive(n)
	return v == 0
}
func number(r *eventRecord, names ...string) (uint64, bool) {
	for _, name := range names {
		var b [8]byte
		if property(r, name, b[:]) {
			return binary.LittleEndian.Uint64(b[:]), true
		}
	}
	return 0, false
}
func devicePaths() map[string]string {
	out := map[string]string{}
	for drive := 'A'; drive <= 'Z'; drive++ {
		name, _ := windows.UTF16PtrFromString(string(drive) + ":")
		b := make([]uint16, 4096)
		r, _, _ := queryDosDevice.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		if r > 0 {
			out[strings.ToLower(windows.UTF16ToString(b))] = strings.ToLower(string(drive) + ":")
		}
	}
	return out
}
func (s *winTrace) dosPath(path string) string {
	path = cleanPath(path)
	for device, drive := range s.devices {
		if strings.HasPrefix(path, device+`\`) {
			return drive + strings.TrimPrefix(path, device)
		}
	}
	return path
}

func (s *winTrace) onEvent(r *eventRecord) {
	if r.Provider != fileProvider || r.Flags&0x10c != 0 { // Manifest records only; no classic/string/WPP records.
		return
	}
	if r.ID < 32 {
		s.counts[r.ID].Add(1)
	}
	if r.ID != 12 && r.ID != 30 && r.ID != 14 && r.ID != 16 && r.ID != 19 && r.ID != 24 {
		return
	}
	var obj uint64
	var ok bool
	if r.ID != 24 {
		obj, ok = number(r, "FileObject")
	}
	switch r.ID {
	case 12, 30: // Create includes the canonical file name, also for read opens.
		if !ok {
			return
		}
		if old, found := s.objects[obj]; found && old.at > r.Timestamp {
			return
		}
		delete(s.objects, obj)
		var b [8192]byte
		if !property(r, "FileName", b[:]) {
			return
		}
		path := s.dosPath(utf16At(b[:], 0))
		if !s.m.watched(path) {
			return
		}
		if len(s.objects) >= maxObjects {
			s.m.fail("file_object_capacity_exceeded")
			return
		}
		tid, hasThread := number(r, "IssuingThreadId", "ThreadId")
		if !hasThread {
			tid = uint64(r.ThreadID)
		}
		owner, _ := writer(uint32(tid), r.PID, r.Timestamp)
		s.objects[obj] = openedFile{path: path, at: r.Timestamp, owner: owner}
		s.mapped.Add(1)
	case 14:
		if old, found := s.objects[obj]; ok && found && r.Timestamp >= old.at {
			delete(s.objects, obj)
		} // Close prevents object-address reuse.
	case 16, 19: // Accept modifying operations only after successful OperationEnd.
		if !ok {
			return
		}
		opened, found := s.objects[obj]
		if !found || r.Timestamp < opened.at {
			return
		}
		irp, found := number(r, "Irp")
		if !found {
			return
		}
		tid, found := number(r, "IssuingThreadId", "ThreadId")
		if !found {
			return
		}
		at := filetime(r.Timestamp)
		id, _ := writer(uint32(tid), r.PID, r.Timestamp)
		// Cross-process shared handles and unverified opens cannot establish a
		// trusted path-to-writer binding. Do not trust a payload PID alone.
		if id != opened.owner {
			id = Identity{}
		}
		if id.PID == 0 {
			s.rejected[0].Add(1)
			s.rejected[1].Store(uint64(r.PID))
			s.rejected[2].Store(tid)
			s.rejected[3].Store(uint64(opened.owner.PID))
		}
		if len(s.pending) >= maxWrites {
			s.m.fail("pending_write_capacity_exceeded")
			return
		}
		operation := "write"
		if r.ID != 16 {
			operation = "rename"
		}
		pending := pendingWrite{writes: []Write{{Path: opened.path, At: at, Process: id, Operation: operation}}, object: obj, emitter: r.PID, at: time.Now()}
		s.pending[irp] = pending
	case 24:
		irp, found := number(r, "Irp")
		if !found {
			return
		}
		pending, found := s.pending[irp]
		if !found {
			return
		}
		delete(s.pending, irp)
		if r.PID != 4 && r.PID != 0xffffffff && r.PID != pending.emitter && (len(pending.writes) == 0 || r.PID != pending.writes[0].Process.PID) {
			return
		}
		if len(pending.writes) == 0 || filetime(r.Timestamp).Before(pending.writes[0].At) || filetime(r.Timestamp).Sub(pending.writes[0].At) > 5*time.Second {
			return
		}
		status, found := number(r, "NtStatus", "Status")
		if found && uint32(status) == 0 {
			s.completed.Add(1)
			for _, w := range pending.writes {
				s.m.observe(w)
			}
			// After rename, the original path must not label later writes through
			// the same file object. A new open can establish a fresh mapping.
			if pending.writes[0].Operation == "rename" {
				if opened, ok := s.objects[pending.object]; ok && !filetime(opened.at).After(pending.writes[0].At) {
					delete(s.objects, pending.object)
				}
			}
		}
	}
	// Completion loss must not grow storage or associate a recycled IRP.
	if len(s.pending) > 0 && time.Since(s.lastSweep) >= time.Second {
		s.lastSweep = time.Now()
		for irp, w := range s.pending {
			if time.Since(w.at) > 5*time.Second {
				delete(s.pending, irp)
			}
		}
	}
}

func (s *winTrace) counters() map[string]uint64 {
	out := map[string]uint64{"matched_file_opens": s.mapped.Load(), "completed_modifications": s.completed.Load()}
	for i, name := range []string{"unverified_operations", "last_unverified_emitter", "last_unverified_thread", "last_unverified_open_owner"} {
		out[name] = s.rejected[i].Load()
	}
	for _, id := range []int{12, 14, 16, 19, 24, 27, 30} {
		out[fmt.Sprintf("event_%d", id)] = s.counts[id].Load()
	}
	return out
}
func filetime(v uint64) time.Time { return time.Unix(0, int64(v-116444736000000000)*100) }
func creation(h windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), nil
}
func image(h windows.Handle) (string, error) {
	b := make([]uint16, 32768)
	n := uint32(len(b))
	if err := windows.QueryFullProcessImageName(h, 0, &b[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b[:n]), nil
}
func writer(tid, emitter uint32, at uint64) (Identity, error) {
	var id Identity
	thread, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION, false, tid)
	if err != nil {
		return id, err
	}
	defer windows.CloseHandle(thread)
	var c, e, k, u windows.Filetime
	r, _, err := threadTimes.Call(uintptr(thread), uintptr(unsafe.Pointer(&c)), uintptr(unsafe.Pointer(&e)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	if r == 0 {
		return id, err
	}
	if uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) > at {
		return id, fmt.Errorf("thread reused")
	}
	pid, _, _ := threadPID.Call(uintptr(thread))
	// Cache-manager/system writes cannot establish an original user writer.
	if pid <= 4 || uint32(pid) == uint32(os.Getpid()) {
		return id, fmt.Errorf("writer context unavailable")
	}
	if emitter != uint32(pid) && emitter != 4 && emitter != 0xffffffff {
		return id, fmt.Errorf("event source does not match issuing thread")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return id, err
	}
	defer windows.CloseHandle(h)
	birth, err := creation(h)
	if err != nil || birth > at {
		return id, fmt.Errorf("process reused or unavailable")
	}
	exe, err := image(h)
	if err != nil {
		return id, err
	}
	return Identity{PID: uint32(pid), Created: birth, Image: exe}, nil
}

// Terminate rechecks creation time AND image using the same handle that is
// passed to TerminateProcess. It never recursively targets inferred relatives.
func Terminate(id Identity) error {
	if id.PID <= 4 || id.PID == uint32(os.Getpid()) || id.Created == 0 || id.Image == "" {
		return fmt.Errorf("unsafe process identity")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, id.PID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	birth, err := creation(h)
	if err != nil {
		return err
	}
	exe, err := image(h)
	if err != nil {
		return err
	}
	if birth != id.Created || !strings.EqualFold(exe, id.Image) {
		return fmt.Errorf("process identity changed")
	}
	var critical uint32
	if err := criticalProcess.Find(); err != nil {
		return fmt.Errorf("critical process protection unavailable: %w", err)
	}
	r, _, e := criticalProcess.Call(uintptr(h), uintptr(unsafe.Pointer(&critical)))
	if r == 0 {
		return fmt.Errorf("cannot verify critical process protection: %w", e)
	}
	if critical != 0 {
		return fmt.Errorf("critical process termination refused")
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	wait, err := windows.WaitForSingleObject(h, 1000)
	if err != nil {
		return err
	}
	if wait != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process termination not yet confirmed")
	}
	return nil
}
