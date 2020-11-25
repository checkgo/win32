package win32

import (
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCreateProcessAsUserW      = modadvapi32.NewProc("CreateProcessAsUserW")
	procCryptAcquireContextW      = modadvapi32.NewProc("CryptAcquireContextW")
	procCryptReleaseContext       = modadvapi32.NewProc("CryptReleaseContext")
	procCryptGenRandom            = modadvapi32.NewProc("CryptGenRandom")
	procRegOpenKeyExW             = modadvapi32.NewProc("RegOpenKeyExW")
	procRegCloseKey               = modadvapi32.NewProc("RegCloseKey")
	procRegQueryInfoKeyW          = modadvapi32.NewProc("RegQueryInfoKeyW")
	procRegEnumKeyExW             = modadvapi32.NewProc("RegEnumKeyExW")
	procRegQueryValueExW          = modadvapi32.NewProc("RegQueryValueExW")
	procLookupAccountSidW         = modadvapi32.NewProc("LookupAccountSidW")
	procLookupAccountNameW        = modadvapi32.NewProc("LookupAccountNameW")
	procConvertSidToStringSidW    = modadvapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSidToSidW    = modadvapi32.NewProc("ConvertStringSidToSidW")
	procGetLengthSid              = modadvapi32.NewProc("GetLengthSid")
	procCopySid                   = modadvapi32.NewProc("CopySid")
	procOpenProcessToken          = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation       = modadvapi32.NewProc("GetTokenInformation")
	procRegCreateKeyExW           = modadvapi32.NewProc("RegCreateKeyExW")
	procRegDeleteKeyW             = modadvapi32.NewProc("RegDeleteKeyW")
	procRegSetValueExW            = modadvapi32.NewProc("RegSetValueExW")
	procRegEnumValueW             = modadvapi32.NewProc("RegEnumValueW")
	procRegDeleteValueW           = modadvapi32.NewProc("RegDeleteValueW")
	procRegLoadMUIStringW         = modadvapi32.NewProc("RegLoadMUIStringW")
	procRegConnectRegistryW       = modadvapi32.NewProc("RegConnectRegistryW")
	procExpandEnvironmentStringsW = modkernel32.NewProc("ExpandEnvironmentStringsW")
	procRegCreateKeyEx            = modadvapi32.NewProc("RegCreateKeyExW")
	procRegOpenKeyEx              = modadvapi32.NewProc("RegOpenKeyExW")
	procRegGetValue               = modadvapi32.NewProc("RegGetValueW")
	procRegEnumKeyEx              = modadvapi32.NewProc("RegEnumKeyExW")
	procRegSetValueEx             = modadvapi32.NewProc("RegSetValueExW")
	procRegDeleteKeyValue         = modadvapi32.NewProc("RegDeleteKeyValueW")
	procRegDeleteValue            = modadvapi32.NewProc("RegDeleteValueW")
	procRegDeleteTree             = modadvapi32.NewProc("RegDeleteTreeW")
	procOpenEventLog              = modadvapi32.NewProc("OpenEventLogW")
	procReadEventLog              = modadvapi32.NewProc("ReadEventLogW")
	procCloseEventLog             = modadvapi32.NewProc("CloseEventLog")
	procOpenSCManager             = modadvapi32.NewProc("OpenSCManagerW")
	procCloseServiceHandle        = modadvapi32.NewProc("CloseServiceHandle")
	procOpenService               = modadvapi32.NewProc("OpenServiceW")
	procStartService              = modadvapi32.NewProc("StartServiceW")
	procControlService            = modadvapi32.NewProc("ControlService")
)

func CreateProcessAsUser(token syscall.Token, appName *uint16, commandLine *uint16, procSecurity *syscall.SecurityAttributes, threadSecurity *syscall.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *syscall.StartupInfo, outProcInfo *syscall.ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _, e1 := syscall.Syscall12(procCreateProcessAsUserW.Addr(), 11, uintptr(token), uintptr(unsafe.Pointer(appName)), uintptr(unsafe.Pointer(commandLine)), uintptr(unsafe.Pointer(procSecurity)), uintptr(unsafe.Pointer(threadSecurity)), uintptr(_p0), uintptr(creationFlags), uintptr(unsafe.Pointer(env)), uintptr(unsafe.Pointer(currentDir)), uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(outProcInfo)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CryptAcquireContext(provhandle *syscall.Handle, container *uint16, provider *uint16, provtype uint32, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procCryptAcquireContextW.Addr(), 5, uintptr(unsafe.Pointer(provhandle)), uintptr(unsafe.Pointer(container)), uintptr(unsafe.Pointer(provider)), uintptr(provtype), uintptr(flags), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CryptReleaseContext(provhandle syscall.Handle, flags uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procCryptReleaseContext.Addr(), 2, uintptr(provhandle), uintptr(flags), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func CryptGenRandom(provhandle syscall.Handle, buflen uint32, buf *byte) (err error) {
	r1, _, e1 := syscall.Syscall(procCryptGenRandom.Addr(), 3, uintptr(provhandle), uintptr(buflen), uintptr(unsafe.Pointer(buf)))
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func RegOpenKeyEx(key syscall.Handle, subkey *uint16, options uint32, desiredAccess uint32, result *syscall.Handle) (regerrno error) {
	r0, _, _ := syscall.Syscall6(procRegOpenKeyExW.Addr(), 5, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(options), uintptr(desiredAccess), uintptr(unsafe.Pointer(result)), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegCloseKey(key syscall.Handle) (regerrno error) {
	r0, _, _ := syscall.Syscall(procRegCloseKey.Addr(), 1, uintptr(key), 0, 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegQueryInfoKey(key syscall.Handle, class *uint16, classLen *uint32, reserved *uint32, subkeysLen *uint32, maxSubkeyLen *uint32, maxClassLen *uint32, valuesLen *uint32, maxValueNameLen *uint32, maxValueLen *uint32, saLen *uint32, lastWriteTime *syscall.Filetime) (regerrno error) {
	r0, _, _ := syscall.Syscall12(procRegQueryInfoKeyW.Addr(), 12, uintptr(key), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(classLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(subkeysLen)), uintptr(unsafe.Pointer(maxSubkeyLen)), uintptr(unsafe.Pointer(maxClassLen)), uintptr(unsafe.Pointer(valuesLen)), uintptr(unsafe.Pointer(maxValueNameLen)), uintptr(unsafe.Pointer(maxValueLen)), uintptr(unsafe.Pointer(saLen)), uintptr(unsafe.Pointer(lastWriteTime)))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegEnumKeyEx(key syscall.Handle, index uint32, name *uint16, nameLen *uint32, reserved *uint32, class *uint16, classLen *uint32, lastWriteTime *syscall.Filetime) (regerrno error) {
	r0, _, _ := syscall.Syscall9(procRegEnumKeyExW.Addr(), 8, uintptr(key), uintptr(index), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(nameLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(classLen)), uintptr(unsafe.Pointer(lastWriteTime)), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegQueryValueEx(key syscall.Handle, name *uint16, reserved *uint32, valtype *uint32, buf *byte, buflen *uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall6(procRegQueryValueExW.Addr(), 6, uintptr(key), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(valtype)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(buflen)))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func LookupAccountSid(systemName *uint16, sid *syscall.SID, name *uint16, nameLen *uint32, refdDomainName *uint16, refdDomainNameLen *uint32, use *uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procLookupAccountSidW.Addr(), 7, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(nameLen)), uintptr(unsafe.Pointer(refdDomainName)), uintptr(unsafe.Pointer(refdDomainNameLen)), uintptr(unsafe.Pointer(use)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func LookupAccountName(systemName *uint16, accountName *uint16, sid *syscall.SID, sidLen *uint32, refdDomainName *uint16, refdDomainNameLen *uint32, use *uint32) (err error) {
	r1, _, e1 := syscall.Syscall9(procLookupAccountNameW.Addr(), 7, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(accountName)), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(sidLen)), uintptr(unsafe.Pointer(refdDomainName)), uintptr(unsafe.Pointer(refdDomainNameLen)), uintptr(unsafe.Pointer(use)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func ConvertSidToStringSid(sid *syscall.SID, stringSid **uint16) (err error) {
	r1, _, e1 := syscall.Syscall(procConvertSidToStringSidW.Addr(), 2, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(stringSid)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func ConvertStringSidToSid(stringSid *uint16, sid **syscall.SID) (err error) {
	r1, _, e1 := syscall.Syscall(procConvertStringSidToSidW.Addr(), 2, uintptr(unsafe.Pointer(stringSid)), uintptr(unsafe.Pointer(sid)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetLengthSid(sid *syscall.SID) (len uint32) {
	r0, _, _ := syscall.Syscall(procGetLengthSid.Addr(), 1, uintptr(unsafe.Pointer(sid)), 0, 0)
	len = uint32(r0)
	return
}

func CopySid(destSidLen uint32, destSid *syscall.SID, srcSid *syscall.SID) (err error) {
	r1, _, e1 := syscall.Syscall(procCopySid.Addr(), 3, uintptr(destSidLen), uintptr(unsafe.Pointer(destSid)), uintptr(unsafe.Pointer(srcSid)))
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func OpenProcessToken(h syscall.Handle, access uint32, token *syscall.Token) (err error) {
	r1, _, e1 := syscall.Syscall(procOpenProcessToken.Addr(), 3, uintptr(h), uintptr(access), uintptr(unsafe.Pointer(token)))
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetTokenInformation(t syscall.Token, infoClass uint32, info *byte, infoLen uint32, returnedLen *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procGetTokenInformation.Addr(), 5, uintptr(t), uintptr(infoClass), uintptr(unsafe.Pointer(info)), uintptr(infoLen), uintptr(unsafe.Pointer(returnedLen)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func regCreateKeyEx(key syscall.Handle, subkey *uint16, reserved uint32, class *uint16, options uint32, desired uint32, sa *syscall.SecurityAttributes, result *syscall.Handle, disposition *uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall9(procRegCreateKeyExW.Addr(), 9, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(reserved), uintptr(unsafe.Pointer(class)), uintptr(options), uintptr(desired), uintptr(unsafe.Pointer(sa)), uintptr(unsafe.Pointer(result)), uintptr(unsafe.Pointer(disposition)))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func regDeleteKey(key syscall.Handle, subkey *uint16) (regerrno error) {
	r0, _, _ := syscall.Syscall(procRegDeleteKeyW.Addr(), 2, uintptr(key), uintptr(unsafe.Pointer(subkey)), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func regSetValueEx(key syscall.Handle, valueName *uint16, reserved uint32, vtype uint32, buf *byte, bufsize uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall6(procRegSetValueExW.Addr(), 6, uintptr(key), uintptr(unsafe.Pointer(valueName)), uintptr(reserved), uintptr(vtype), uintptr(unsafe.Pointer(buf)), uintptr(bufsize))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func regEnumValue(key syscall.Handle, index uint32, name *uint16, nameLen *uint32, reserved *uint32, valtype *uint32, buf *byte, buflen *uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall9(procRegEnumValueW.Addr(), 8, uintptr(key), uintptr(index), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(nameLen)), uintptr(unsafe.Pointer(reserved)), uintptr(unsafe.Pointer(valtype)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(buflen)), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func regDeleteValue(key syscall.Handle, name *uint16) (regerrno error) {
	r0, _, _ := syscall.Syscall(procRegDeleteValueW.Addr(), 2, uintptr(key), uintptr(unsafe.Pointer(name)), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func regLoadMUIString(key syscall.Handle, name *uint16, buf *uint16, buflen uint32, buflenCopied *uint32, flags uint32, dir *uint16) (regerrno error) {
	r0, _, _ := syscall.Syscall9(procRegLoadMUIStringW.Addr(), 7, uintptr(key), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(buf)), uintptr(buflen), uintptr(unsafe.Pointer(buflenCopied)), uintptr(flags), uintptr(unsafe.Pointer(dir)), 0, 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func regConnectRegistry(machinename *uint16, key syscall.Handle, result *syscall.Handle) (regerrno error) {
	r0, _, _ := syscall.Syscall(procRegConnectRegistryW.Addr(), 3, uintptr(unsafe.Pointer(machinename)), uintptr(key), uintptr(unsafe.Pointer(result)))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func expandEnvironmentStrings(src *uint16, dst *uint16, size uint32) (n uint32, err error) {
	r0, _, e1 := syscall.Syscall(procExpandEnvironmentStringsW.Addr(), 3, uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), uintptr(size))
	n = uint32(r0)
	if n == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func RegCreateKey(hKey HKEY, subKey string) HKEY {
	var result HKEY
	ret, _, _ := procRegCreateKeyEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(KEY_ALL_ACCESS),
		uintptr(0),
		uintptr(unsafe.Pointer(&result)),
		uintptr(0))
	_ = ret
	return result
}

func RegGetRaw(hKey HKEY, subKey string, value string) []byte {
	var bufLen uint32
	var valptr unsafe.Pointer
	if len(value) > 0 {
		valptr = unsafe.Pointer(syscall.StringToUTF16Ptr(value))
	}
	procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(valptr),
		uintptr(RRF_RT_ANY),
		0,
		0,
		uintptr(unsafe.Pointer(&bufLen)))

	if bufLen == 0 {
		return nil
	}

	buf := make([]byte, bufLen)
	ret, _, _ := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(valptr),
		uintptr(RRF_RT_ANY),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)))

	if ret != ERROR_SUCCESS {
		return nil
	}

	return buf
}

func RegSetBinary(hKey HKEY, subKey string, value []byte) (errno int) {
	var lptr, vptr unsafe.Pointer
	if len(subKey) > 0 {
		lptr = unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))
	}
	if len(value) > 0 {
		vptr = unsafe.Pointer(&value[0])
	}
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(lptr),
		uintptr(0),
		uintptr(REG_BINARY),
		uintptr(vptr),
		uintptr(len(value)))

	return int(ret)
}

func RegSetString(hKey HKEY, subKey string, value string) (errno int) {
	var lptr, vptr unsafe.Pointer
	if len(subKey) > 0 {
		lptr = unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))
	}
	var buf []uint16
	if len(value) > 0 {
		buf, err := syscall.UTF16FromString(value)
		if err != nil {
			return ERROR_BAD_FORMAT
		}
		vptr = unsafe.Pointer(&buf[0])
	}
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(lptr),
		uintptr(0),
		uintptr(REG_SZ),
		uintptr(vptr),
		uintptr(unsafe.Sizeof(buf)+2)) // 2 is the size of the terminating null character

	return int(ret)
}

func RegSetUint32(hKey HKEY, subKey string, value uint32) (errno int) {
	var lptr unsafe.Pointer
	if len(subKey) > 0 {
		lptr = unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))
	}
	vptr := unsafe.Pointer(&value)
	ret, _, _ := procRegSetValueEx.Call(
		uintptr(hKey),
		uintptr(lptr),
		uintptr(0),
		uintptr(REG_DWORD),
		uintptr(vptr),
		uintptr(unsafe.Sizeof(value)))

	return int(ret)
}

func RegGetString(hKey HKEY, subKey string, value string) string {
	var bufLen uint32
	procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_SZ),
		0,
		0,
		uintptr(unsafe.Pointer(&bufLen)))

	if bufLen == 0 {
		return ""
	}

	buf := make([]uint16, bufLen)
	ret, _, _ := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_SZ),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufLen)))

	if ret != ERROR_SUCCESS {
		return ""
	}

	return syscall.UTF16ToString(buf)
}

func RegGetUint32(hKey HKEY, subKey string, value string) (data uint32, errno int) {
	var dataLen uint32 = uint32(unsafe.Sizeof(data))
	ret, _, _ := procRegGetValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(value))),
		uintptr(RRF_RT_REG_DWORD),
		0,
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataLen)))
	errno = int(ret)
	return
}

/*
func RegSetKeyValue(hKey HKEY, subKey string, valueName string, dwType uint32, data uintptr, cbData uint16) (errno int) {
	ret, _, _ := procRegSetKeyValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueName))),
		uintptr(dwType),
		data,
		uintptr(cbData))

	return int(ret)
}
*/

func RegDeleteKeyValue(hKey HKEY, subKey string, valueName string) (errno int) {
	ret, _, _ := procRegDeleteKeyValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueName))))

	return int(ret)
}

func RegDeleteValue(hKey HKEY, valueName string) (errno int) {
	ret, _, _ := procRegDeleteValue.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(valueName))))

	return int(ret)
}

func RegDeleteTree(hKey HKEY, subKey string) (errno int) {
	ret, _, _ := procRegDeleteTree.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(subKey))))

	return int(ret)
}

func OpenEventLog(servername string, sourcename string) HANDLE {
	ret, _, _ := procOpenEventLog.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(servername))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(sourcename))))

	return HANDLE(ret)
}

func ReadEventLog(eventlog HANDLE, readflags, recordoffset uint32, buffer []byte, numberofbytestoread uint32, bytesread, minnumberofbytesneeded *uint32) bool {
	ret, _, _ := procReadEventLog.Call(
		uintptr(eventlog),
		uintptr(readflags),
		uintptr(recordoffset),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(numberofbytestoread),
		uintptr(unsafe.Pointer(bytesread)),
		uintptr(unsafe.Pointer(minnumberofbytesneeded)))

	return ret != 0
}

func CloseEventLog(eventlog HANDLE) bool {
	ret, _, _ := procCloseEventLog.Call(
		uintptr(eventlog))

	return ret != 0
}

func OpenSCManager(lpMachineName, lpDatabaseName string, dwDesiredAccess uint32) (HANDLE, error) {
	var p1, p2 uintptr
	if len(lpMachineName) > 0 {
		p1 = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpMachineName)))
	}
	if len(lpDatabaseName) > 0 {
		p2 = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpDatabaseName)))
	}
	ret, _, _ := procOpenSCManager.Call(
		p1,
		p2,
		uintptr(dwDesiredAccess))

	if ret == 0 {
		return 0, syscall.GetLastError()
	}

	return HANDLE(ret), nil
}

func CloseServiceHandle(hSCObject HANDLE) error {
	ret, _, _ := procCloseServiceHandle.Call(uintptr(hSCObject))
	if ret == 0 {
		return syscall.GetLastError()
	}
	return nil
}

func OpenService(hSCManager HANDLE, lpServiceName string, dwDesiredAccess uint32) (HANDLE, error) {
	ret, _, _ := procOpenService.Call(
		uintptr(hSCManager),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpServiceName))),
		uintptr(dwDesiredAccess))

	if ret == 0 {
		return 0, syscall.GetLastError()
	}

	return HANDLE(ret), nil
}

func StartService(hService HANDLE, lpServiceArgVectors []string) error {
	l := len(lpServiceArgVectors)
	var ret uintptr
	if l == 0 {
		ret, _, _ = procStartService.Call(
			uintptr(hService),
			0,
			0)
	} else {
		lpArgs := make([]uintptr, l)
		for i := 0; i < l; i++ {
			lpArgs[i] = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpServiceArgVectors[i])))
		}

		ret, _, _ = procStartService.Call(
			uintptr(hService),
			uintptr(l),
			uintptr(unsafe.Pointer(&lpArgs[0])))
	}

	if ret == 0 {
		return syscall.GetLastError()
	}

	return nil
}

func ControlService(hService HANDLE, dwControl uint32, lpServiceStatus *SERVICE_STATUS) bool {
	if lpServiceStatus == nil {
		panic("ControlService:lpServiceStatus cannot be nil")
	}

	ret, _, _ := procControlService.Call(
		uintptr(hService),
		uintptr(dwControl),
		uintptr(unsafe.Pointer(lpServiceStatus)))

	return ret != 0
}
