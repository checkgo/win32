package win32

import (
	"syscall"
	"unsafe"
)

var (
	modpsapi = syscall.NewLazyDLL("psapi.dll")

	procEnumProcesses        = modpsapi.NewProc("EnumProcesses")
	procEnumProcessModulesEx = modpsapi.NewProc("EnumProcessModulesEx")
)

func EnumProcesses(processIds []uint32, cb uint32, bytesReturned *uint32) bool {
	ret, _, _ := procEnumProcesses.Call(
		uintptr(unsafe.Pointer(&processIds[0])),
		uintptr(cb),
		uintptr(unsafe.Pointer(bytesReturned)))

	return ret != 0
}

func EnumProcessModules(hProcess HANDLE, lphModule *HMODULE, cb DWORD, lpcbNeeded LPDWORD, dwFilterFlag DWORD) bool {
	ret, _, _ := procEnumProcessModulesEx.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(lphModule)),
		uintptr(cb),
		uintptr(lpcbNeeded),
		uintptr(dwFilterFlag))
	return ret != 0
}
