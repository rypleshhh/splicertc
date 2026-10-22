package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// clientJob holds client.exe. It is created with KILL_ON_JOB_CLOSE and
// its handle stays open for the tray's lifetime, so when the tray dies
// (even a crash or a kill from Task Manager) Windows closes the handle
// and kills client.exe too, and its TUN and default route go away.
var clientJob windows.Handle

func createClientJob() error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return err
	}
	clientJob = job
	return nil
}

// addToClientJob puts a just started process into clientJob.
func addToClientJob(pid int) error {
	if clientJob == 0 {
		return fmt.Errorf("no job object")
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(clientJob, h)
}
