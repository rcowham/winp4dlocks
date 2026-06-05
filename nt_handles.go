//go:build windows

// nt_handles.go
package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SystemExtendedHandleInformation = 64
)

type SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX struct {
	Object                uintptr
	UniqueProcessId       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
	UniqueThreadId        uintptr
}

type SYSTEM_HANDLE_INFORMATION_EX struct {
	NumberOfHandles uintptr
	Reserved        uintptr
	Handles         [1]SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
}

type DBHandleInfo struct {
	Path     string
	ThreadID uint32
}

var (
	ntdll                 = windows.NewLazyDLL("ntdll.dll")
	procNtQuerySystemInfo = ntdll.NewProc("NtQuerySystemInformation")
)

func enumP4DBHandlesByThread(p4pid uint32) []DBHandleInfo {
	bufSize := uint32(1 << 20)
	buf := make([]byte, bufSize)

	for {
		r, _, _ := procNtQuerySystemInfo.Call(
			SystemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&bufSize)),
		)
		if r == 0 {
			break
		}
		bufSize *= 2
		buf = make([]byte, bufSize)
	}

	info := (*SYSTEM_HANDLE_INFORMATION_EX)(unsafe.Pointer(&buf[0]))
	count := info.NumberOfHandles

	var result []DBHandleInfo

	srcProc, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, p4pid)
	if err != nil {
		return result
	}
	defer windows.CloseHandle(srcProc)

	for i := uintptr(0); i < count; i++ {
		h := (*SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)(
			unsafe.Pointer(uintptr(unsafe.Pointer(&info.Handles[0])) +
				i*unsafe.Sizeof(info.Handles[0])),
		)

		if uint32(h.UniqueProcessId) != p4pid {
			continue
		}

		// duplicate handle into our process
		var dup windows.Handle
		err = windows.DuplicateHandle(
			srcProc,
			windows.Handle(h.HandleValue),
			windows.CurrentProcess(),
			&dup,
			0,
			false,
			windows.DUPLICATE_SAME_ACCESS,
		)
		if err != nil {
			continue
		}

		name := getFileNameFromHandle(dup)
		windows.CloseHandle(dup)

		if strings.Contains(strings.ToLower(name), `\db.`) {
			result = append(result, DBHandleInfo{
				Path:     name,
				ThreadID: uint32(h.UniqueThreadId),
			})
		}
	}
	return result
}
