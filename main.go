//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	WCT_OBJNAME_LENGTH = 128
	WctThreadType      = 1
)

type WAITCHAIN_NODE_INFO struct {
	ObjectType      uint32
	ObjectStatus    uint32
	Union           [16]byte
	ObjectId        [2]uintptr
	ContextSwitches uint32
	WaitTime        uint32
	Timeout         uint32
}

var (
	kernel32                        = windows.NewLazyDLL("kernel32.dll")
	advapi32                        = windows.NewLazyDLL("advapi32.dll")
	procOpenThreadWaitChainSession  = advapi32.NewProc("OpenThreadWaitChainSession")
	procGetThreadWaitChain          = advapi32.NewProc("GetThreadWaitChain")
	procCloseThreadWaitChainSession = advapi32.NewProc("CloseThreadWaitChainSession")
)

func findProcessByName(name string) uint32 {
	snap, _ := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	for windows.Process32First(snap, &pe) == nil {
		if windows.UTF16ToString(pe.ExeFile[:]) == name {
			return pe.ProcessID
		}
		if windows.Process32Next(snap, &pe) != nil {
			break
		}
	}
	return 0
}

func getFileNameFromHandle(h windows.Handle) string {
	buf := make([]uint16, 1024)
	n, _ := windows.GetFinalPathNameByHandle(
		h,
		&buf[0],
		uint32(len(buf)),
		0,
	)
	if n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func enumThreads(pid uint32) []uint32 {
	snap, _ := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	defer windows.CloseHandle(snap)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	var threads []uint32
	for windows.Thread32First(snap, &te) == nil {
		if te.OwnerProcessID == pid {
			threads = append(threads, te.ThreadID)
		}
		if windows.Thread32Next(snap, &te) != nil {
			break
		}
	}
	return threads
}

func checkThreadBlockers(tid uint32, session uintptr) {
	const WCT_MAX_NODE_COUNT = 16
	var nodes [WCT_MAX_NODE_COUNT]WAITCHAIN_NODE_INFO
	var count uint32 = WCT_MAX_NODE_COUNT
	var cycle uint32

	r, _, _ := procGetThreadWaitChain.Call(
		session,
		0,
		uintptr(tid),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&nodes[0])),
		uintptr(unsafe.Pointer(&cycle)),
	)

	if r == 0 || count < 2 {
		return
	}

	for i := 1; i < int(count); i++ {
		if nodes[i].ObjectType == WctThreadType {
			blocker := uint32(nodes[i].ObjectId[0])
			println("Thread", tid, "blocked by thread", blocker)
		}
	}
}

func main() {
	p4pid := findProcessByName("p4s.exe")
	if p4pid == 0 {
		panic("p4s.exe not running")
	}

	handles := enumP4DBHandles(p4pid)
	println("db.* handles:", len(handles))

	session, _, _ := procOpenThreadWaitChainSession.Call(1, 0)
	defer procCloseThreadWaitChainSession.Call(session)

	threads := enumThreads(p4pid)
	for _, tid := range threads {
		checkThreadBlockers(tid, session)
	}
}
