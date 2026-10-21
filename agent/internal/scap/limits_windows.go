//go:build windows

package scap

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"unsafe"
)

func workerLimits() error        { return nil }
func configureProcess(*exec.Cmd) {}
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
