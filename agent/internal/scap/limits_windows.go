//go:build windows

package scap

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"
)

func workerLimits() error        { return nil }
func configureProcess(*exec.Cmd) {}
func makeNativeWorkspace() (string, error) {
	// Set the protected, inheritable DACL at creation time. Windows ignores
	// Unix 0700 bits, and a shared service TEMP must not expose cloned modules
	// or results, even between directory creation and a later ACL rewrite.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for attempt := 0; attempt < 10; attempt++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		path := filepath.Join(nativeTempRoot(), "alinksec-scap-"+hex.EncodeToString(nonce[:]))
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return "", err
		}
		err = windows.CreateDirectory(name, &attributes)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) && !errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return "", err
		}
	}
	return "", issue("scap_worker_failed")
}
func nativeWorkspacePath(path string) (string, error) {
	// GetTempPath may return a DOS 8.3 alias (e.g. RUNNER~1). SCC's trusted
	// options schema rejects '~'; resolve the existing private directory using
	// the OS API rather than modifying the vendor schema or validation flags.
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 32768)
	n, err := windows.GetLongPathName(name, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buffer)) {
		return "", issue("scap_worker_failed")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}
func limitProcess(process *os.Process) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_JOB_MEMORY | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	info.BasicLimitInformation.ActiveProcessLimit = 16
	info.JobMemoryLimit = 384 << 20
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err == nil {
		handle, openErr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(process.Pid))
		err = openErr
		if err == nil {
			err = windows.AssignProcessToJobObject(job, handle)
			windows.CloseHandle(handle)
		}
	}
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	return func() { windows.CloseHandle(job) }, nil
}
