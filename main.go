//go:build windows

package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	WCT_OBJNAME_LENGTH = 128
	WctThreadType      = 7
)

type WAITCHAIN_NODE_INFO struct {
	ObjectType   uint32
	ObjectStatus uint32
	// This mirrors the C union payload for WAITCHAIN_NODE_INFO on 64-bit builds.
	// The largest arm is LockObject: WCHAR[128] + LARGE_INTEGER + BOOL (+ alignment).
	ObjectInfo [272]byte
}

var (
	// kernel32                        = windows.NewLazyDLL("kernel32.dll")
	advapi32                        = windows.NewLazyDLL("advapi32.dll")
	procOpenThreadWaitChainSession  = advapi32.NewProc("OpenThreadWaitChainSession")
	procGetThreadWaitChain          = advapi32.NewProc("GetThreadWaitChain")
	procCloseThreadWaitChainSession = advapi32.NewProc("CloseThreadWaitChainSession")
)

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

func checkThreadBlockers(tid uint32, session uintptr) bool {
	const WCT_MAX_NODE_COUNT = 16
	var nodes [WCT_MAX_NODE_COUNT]WAITCHAIN_NODE_INFO
	var count uint32 = WCT_MAX_NODE_COUNT
	var cycle uint32

	r, _, _ := procGetThreadWaitChain.Call(
		session,
		0,
		0,
		uintptr(tid),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&nodes[0])),
		uintptr(unsafe.Pointer(&cycle)),
	)

	if r == 0 || count < 2 {
		return true // thread is not blocked
	}

	// Check primary blocker (nodes[1])
	if nodes[1].ObjectType == WctThreadType {
		pid := *(*uint32)(unsafe.Pointer(&nodes[1].ObjectInfo[0]))
		blocker := *(*uint32)(unsafe.Pointer(&nodes[1].ObjectInfo[4]))
		println("Thread", tid, "blocked by thread", blocker, "(pid", pid, ")")
		return false // thread is blocked
	}

	// Lock object name is WCHAR[WCT_OBJNAME_LENGTH] at ObjectInfo[0].
	name := windows.UTF16ToString((*[WCT_OBJNAME_LENGTH]uint16)(unsafe.Pointer(&nodes[1].ObjectInfo[0]))[:])
	if name != "" {
		println("Thread", tid, "waiting on", name, "(type", nodes[1].ObjectType, "status", nodes[1].ObjectStatus, ")")
	} else {
		println("Thread", tid, "waiting on object type", nodes[1].ObjectType, "status", nodes[1].ObjectStatus)
	}
	return false
}

// WindowsProcess is an implementation of Process for Windows.
type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

func processes() ([]WindowsProcess, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	// get the first process
	err = windows.Process32First(handle, &entry)
	if err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)
	for {
		results = append(results, newWindowsProcess(&entry))

		err = windows.Process32Next(handle, &entry)
		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}
			return nil, err
		}
	}
}

func findProcessByName(processes []WindowsProcess, name string) *WindowsProcess {
	for _, p := range processes {
		if strings.EqualFold(p.Exe, name) {
			return &p
		}
	}
	return nil
}

func findFirstProcessByNames(processes []WindowsProcess, names ...string) *WindowsProcess {
	for _, name := range names {
		if p := findProcessByName(processes, name); p != nil {
			return p
		}
	}
	return nil
}

func getThreadBlocker(tid uint32, session uintptr) (blocked bool, blockerPID uint32, blockerTID uint32, waitObj string) {
	const WCT_MAX_NODE_COUNT = 16
	var nodes [WCT_MAX_NODE_COUNT]WAITCHAIN_NODE_INFO
	var count uint32 = WCT_MAX_NODE_COUNT
	var cycle uint32

	r, _, _ := procGetThreadWaitChain.Call(
		session,
		0,
		0,
		uintptr(tid),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&nodes[0])),
		uintptr(unsafe.Pointer(&cycle)),
	)

	if r == 0 || count < 2 {
		return false, 0, 0, ""
	}

	if nodes[1].ObjectType == WctThreadType {
		pid := *(*uint32)(unsafe.Pointer(&nodes[1].ObjectInfo[0]))
		blocker := *(*uint32)(unsafe.Pointer(&nodes[1].ObjectInfo[4]))
		return true, pid, blocker, ""
	}

	name := windows.UTF16ToString((*[WCT_OBJNAME_LENGTH]uint16)(unsafe.Pointer(&nodes[1].ObjectInfo[0]))[:])
	return true, 0, 0, name
}

func getThreadBlockerWithTimeout(tid uint32, session uintptr, timeout time.Duration) (blocked bool, blockerPID uint32, blockerTID uint32, waitObj string, timedOut bool) {
	type result struct {
		blocked    bool
		blockerPID uint32
		blockerTID uint32
		waitObj    string
	}

	ch := make(chan result, 1)
	go func() {
		b, pid, bt, obj := getThreadBlocker(tid, session)
		ch <- result{blocked: b, blockerPID: pid, blockerTID: bt, waitObj: obj}
	}()

	select {
	case r := <-ch:
		return r.blocked, r.blockerPID, r.blockerTID, r.waitObj, false
	case <-time.After(timeout):
		return false, 0, 0, "", true
	}
}

func newWindowsProcess(e *windows.ProcessEntry32) WindowsProcess {
	// Find when the string ends for decoding
	end := 0
	for {
		if e.ExeFile[end] == 0 {
			break
		}
		end++
	}

	return WindowsProcess{
		ProcessID:       int(e.ProcessID),
		ParentProcessID: int(e.ParentProcessID),
		Exe:             syscall.UTF16ToString(e.ExeFile[:end]),
	}
}

func main() {
	const enableWaitChainAnalysis = false

	procs, err := processes()
	if err != nil {
		log.Fatal(err)
	}
	p4p := findFirstProcessByNames(procs, "p4d.exe", "p4s.exe")
	if p4p == nil {
		log.Fatal("p4d.exe/p4s.exe not running")
	}
	// found it
	fmt.Printf("%s pid: %d\n", p4p.Exe, p4p.ProcessID)
	p4pid := uint32(p4p.ProcessID)
	handleInfos := enumP4DBHandlesByThread(p4pid)
	println("db.* handles:", len(handleInfos))
	for _, info := range handleInfos {
		fmt.Printf("db handle: %s\n", info.Path)
	}

	if !enableWaitChainAnalysis {
		fmt.Println("\nThread-level wait-chain analysis is disabled because this API can hang on some systems.")
		return
	}

	session, _, _ := procOpenThreadWaitChainSession.Call(1, 0)
	defer procCloseThreadWaitChainSession.Call(session)

	threads := enumThreads(p4pid)
	fmt.Println("\n--- Thread Lock Status ---")
	blockerCounts := make(map[uint32]int)
	timeoutCount := 0

	for _, tid := range threads {
		blocked, blockerPID, blockerTID, waitObj, timedOut := getThreadBlockerWithTimeout(tid, session, 250*time.Millisecond)
		if timedOut {
			timeoutCount++
			fmt.Printf("Thread %d wait-chain query timed out\n", tid)
			continue
		}
		if !blocked {
			continue
		}

		if blockerTID != 0 {
			fmt.Printf("Thread %d blocked by thread %d (pid %d)\n", tid, blockerTID, blockerPID)
			if blockerPID == p4pid {
				blockerCounts[blockerTID]++
			}
			continue
		}

		if waitObj != "" {
			fmt.Printf("Thread %d waiting on %s\n", tid, waitObj)
		} else {
			fmt.Printf("Thread %d waiting on unknown object\n", tid)
		}
	}

	if len(blockerCounts) > 0 {
		fmt.Println("\nThreads likely holding contested locks (they block other p4 threads):")
		tids := make([]uint32, 0, len(blockerCounts))
		for tid := range blockerCounts {
			tids = append(tids, tid)
		}
		sort.Slice(tids, func(i, j int) bool { return blockerCounts[tids[i]] > blockerCounts[tids[j]] })
		for _, tid := range tids {
			fmt.Printf("  Thread %d (blocking %d waiter(s))\n", tid, blockerCounts[tid])
		}
	} else {
		fmt.Println("\nNo contested lock holder threads found in wait-chain data.")
	}

	if timeoutCount > 0 {
		fmt.Printf("\nSkipped %d thread(s) because wait-chain queries timed out.\n", timeoutCount)
	}
}
