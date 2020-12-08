package win32

import (
	"encoding/binary"
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetModuleHandle             = modkernel32.NewProc("GetModuleHandleW")
	procMulDiv                      = modkernel32.NewProc("MulDiv")
	procGetConsoleWindow            = modkernel32.NewProc("GetConsoleWindow")
	procGetCurrentThread            = modkernel32.NewProc("GetCurrentThread")
	procGetLogicalDrives            = modkernel32.NewProc("GetLogicalDrives")
	procGetUserDefaultLCID          = modkernel32.NewProc("GetUserDefaultLCID")
	procLstrlen                     = modkernel32.NewProc("lstrlenW")
	procLstrcpy                     = modkernel32.NewProc("lstrcpyW")
	procGlobalAlloc                 = modkernel32.NewProc("GlobalAlloc")
	procGlobalFree                  = modkernel32.NewProc("GlobalFree")
	procGlobalLock                  = modkernel32.NewProc("GlobalLock")
	procGlobalUnlock                = modkernel32.NewProc("GlobalUnlock")
	procMoveMemory                  = modkernel32.NewProc("RtlMoveMemory")
	procFindResource                = modkernel32.NewProc("FindResourceW")
	procSizeofResource              = modkernel32.NewProc("SizeofResource")
	procLockResource                = modkernel32.NewProc("LockResource")
	procLoadResource                = modkernel32.NewProc("LoadResource")
	procGetLastError                = modkernel32.NewProc("GetLastError")
	procOpenProcess                 = modkernel32.NewProc("OpenProcess")
	procTerminateProcess            = modkernel32.NewProc("TerminateProcess")
	procCloseHandle                 = modkernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot    = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32First               = modkernel32.NewProc("Module32FirstW")
	procModule32Next                = modkernel32.NewProc("Module32NextW")
	procGetSystemTimes              = modkernel32.NewProc("GetSystemTimes")
	procGetConsoleScreenBufferInfo  = modkernel32.NewProc("GetConsoleScreenBufferInfo")
	procSetConsoleTextAttribute     = modkernel32.NewProc("SetConsoleTextAttribute")
	procGetDiskFreeSpaceEx          = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetProcessTimes             = modkernel32.NewProc("GetProcessTimes")
	procSetSystemTime               = modkernel32.NewProc("SetSystemTime")
	procGetSystemTime               = modkernel32.NewProc("GetSystemTime")
	procReadProcessMemory           = modkernel32.NewProc("ReadProcessMemory")
	procWriteProcessMemory          = modkernel32.NewProc("WriteProcessMemory")
	procSetConsoleCtrlHandler       = modkernel32.NewProc("SetConsoleCtrlHandler")
	procIsWow64Process              = modkernel32.NewProc("IsWow64Process")
	procVirtualAllocEx              = modkernel32.NewProc("VirtualAllocEx")
	procVirtualAlloc                = modkernel32.NewProc("VirtualAlloc")
	procGetProcAddress              = modkernel32.NewProc("GetProcAddress")
	procCreateRemoteThread          = modkernel32.NewProc("CreateRemoteThread")
	procLoadLibraryA                = modkernel32.NewProc("LoadLibraryA")
	procCreateProcessA              = modkernel32.NewProc("CreateProcessA")
	procVirtualFreeEx               = modkernel32.NewProc("VirtualFreeEx")
	procVirtualProtect              = modkernel32.NewProc("VirtualProtect")
	procVirtualQuery                = modkernel32.NewProc("VirtualQuery")
	procVirtualQueryEx              = modkernel32.NewProc("VirtualQueryEx")
	procWaitForSingleObject         = modkernel32.NewProc("WaitForSingleObject")
	procWaitForMultipleObjects      = modkernel32.NewProc("WaitForMultipleObjects")
	procWriteFile                   = modkernel32.NewProc("WriteFile")
	procFindFirstChangeNotification = modkernel32.NewProc("FindFirstChangeNotificationW")
	procFindNextChangeNotification  = modkernel32.NewProc("FindNextChangeNotification")
	procFindCloseChangeNotification = modkernel32.NewProc("FindCloseChangeNotification")
	procGetDiskFreeSpaceExW         = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procGetLogicalDriveStringsW     = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveType                = modkernel32.NewProc("GetDriveTypeW")
	procGetVolumeInformation        = modkernel32.NewProc("GetVolumeInformationW")
	procOutputDebugStringW          = modkernel32.NewProc("OutputDebugStringW")
)

func OutputDebugStringW(s string) {
	p, err := syscall.UTF16PtrFromString(s)
	if err == nil {
		procOutputDebugStringW.Call(uintptr(unsafe.Pointer(p)))
	}
}

func GetVolumeInformation(volpath *uint16, lpVolumeNameBuffer []byte, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags int64, lpFileSystemNameBuffer []byte) (bool, error) {
	ret, _, err := procGetVolumeInformation.Call(
		uintptr(unsafe.Pointer(volpath)),
		uintptr(unsafe.Pointer(&lpVolumeNameBuffer[0])),
		uintptr(len(lpVolumeNameBuffer)),
		uintptr(unsafe.Pointer(&lpVolumeSerialNumber)),
		uintptr(unsafe.Pointer(&lpMaximumComponentLength)),
		uintptr(unsafe.Pointer(&lpFileSystemFlags)),
		uintptr(unsafe.Pointer(&lpFileSystemNameBuffer[0])),
		uintptr(len(lpFileSystemNameBuffer)))
	return ret != 0, err
}

func GetDriveType(path *uint16) (uint, error) {
	typeret, _, err := procGetDriveType.Call(uintptr(unsafe.Pointer(path)))
	return uint(typeret), err
}

//package device
//
//import (
//	"bytes"
//	"context"
//	"fmt"
//	"github.com/shirou/gopsutil/disk"
//	"syscall"
//	"unsafe"
//	"golang.org/x/sys/windows"
//)
//
//var (
//	FileFileCompression = int64(16)     // 0x00000010
//	FileReadOnlyVolume  = int64(524288) // 0x00080000
//)
//
//// diskPerformance is an equivalent representation of DISK_PERFORMANCE in the Windows API.
//// https://docs.microsoft.com/fr-fr/windows/win32/api/winioctl/ns-winioctl-disk_performance
//type diskPerformance struct {
//	BytesRead           int64
//	BytesWritten        int64
//	ReadTime            int64
//	WriteTime           int64
//	IdleTime            int64
//	ReadCount           uint32
//	WriteCount          uint32
//	QueueDepth          uint32
//	SplitCount          uint32
//	QueryTime           int64
//	StorageDeviceNumber uint32
//	StorageManagerName  [8]uint16
//	alignmentPadding    uint32 // necessary for 32bit support, see https://github.com/elastic/beats/pull/16553
//}
//
//func Usage(path string) (*disk.UsageStat, error) {
//	return UsageWithContext(context.Background(), path)
//}
//
//func UsageWithContext(ctx context.Context, path string) (*disk.UsageStat, error) {
//	lpFreeBytesAvailable := int64(0)
//	lpTotalNumberOfBytes := int64(0)
//	lpTotalNumberOfFreeBytes := int64(0)
//	diskret, _, err := procGetDiskFreeSpaceExW.Call(
//		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(path))),
//		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
//		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
//		uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)))
//	if diskret == 0 {
//		return nil, err
//	}
//	ret := &disk.UsageStat{
//		Path:        path,
//		Total:       uint64(lpTotalNumberOfBytes),
//		Free:        uint64(lpTotalNumberOfFreeBytes),
//		Used:        uint64(lpTotalNumberOfBytes) - uint64(lpTotalNumberOfFreeBytes),
//		UsedPercent: (float64(lpTotalNumberOfBytes) - float64(lpTotalNumberOfFreeBytes)) / float64(lpTotalNumberOfBytes) * 100,
//		// InodesTotal: 0,
//		// InodesFree: 0,
//		// InodesUsed: 0,
//		// InodesUsedPercent: 0,
//	}
//	return ret, nil
//}
//func Partitions(all bool) ([]disk.PartitionStat, error) {
//	return PartitionsWithContext(context.Background(), all)
//}
//func PartitionsWithContext(ctx context.Context, all bool) ([]disk.PartitionStat, error) {
//	var ret []disk.PartitionStat
//	lpBuffer := make([]byte, 254)
//	diskret, _, err := procGetLogicalDriveStringsW.Call(
//		uintptr(len(lpBuffer)),
//		uintptr(unsafe.Pointer(&lpBuffer[0])))
//	if diskret == 0 {
//		return ret, err
//	}
//	for _, v := range lpBuffer {
//		if v >= 65 && v <= 90 {
//			path := string(v) + ":"
//			typepath, _ := windows.UTF16PtrFromString(path)
//			typeret, _, _ := procGetDriveType.Call(uintptr(unsafe.Pointer(typepath)))
//			if typeret == 0 {
//				return ret, windows.GetLastError()
//			}
//			// 2: DRIVE_REMOVABLE 3: DRIVE_FIXED 4: DRIVE_REMOTE 5: DRIVE_CDROM
//			if typeret == 2 || typeret == 3 || typeret == 4 || typeret == 5 {
//				lpVolumeNameBuffer := make([]byte, 256)
//				lpVolumeSerialNumber := int64(0)
//				lpMaximumComponentLength := int64(0)
//				lpFileSystemFlags := int64(0)
//				lpFileSystemNameBuffer := make([]byte, 256)
//				volpath, _ := windows.UTF16PtrFromString(string(v) + ":/")
//				driveret, _, err := procGetVolumeInformation.Call(
//					uintptr(unsafe.Pointer(volpath)),
//					uintptr(unsafe.Pointer(&lpVolumeNameBuffer[0])),
//					uintptr(len(lpVolumeNameBuffer)),
//					uintptr(unsafe.Pointer(&lpVolumeSerialNumber)),
//					uintptr(unsafe.Pointer(&lpMaximumComponentLength)),
//					uintptr(unsafe.Pointer(&lpFileSystemFlags)),
//					uintptr(unsafe.Pointer(&lpFileSystemNameBuffer[0])),
//					uintptr(len(lpFileSystemNameBuffer)))
//				if driveret == 0 {
//					if typeret == 5 || typeret == 2 {
//						continue //device is not ready will happen if there is no disk in the drive
//					}
//					return ret, err
//				}
//				opts := "rw"
//				if lpFileSystemFlags&FileReadOnlyVolume != 0 {
//					opts = "ro"
//				}
//				if lpFileSystemFlags&FileFileCompression != 0 {
//					opts += ".compress"
//				}
//				d := disk.PartitionStat{
//					Mountpoint: path,
//					Device:     path,
//					Fstype:     string(bytes.Replace(lpFileSystemNameBuffer, []byte("\x00"), []byte(""), -1)),
//					Opts:       opts,
//				}
//				ret = append(ret, d)
//			}
//		}
//	}
//	return ret, nil
//}
//func IOCounters(names ...string) (map[string]disk.IOCountersStat, error) {
//	return IOCountersWithContext(context.Background(), names...)
//}
//func IOCountersWithContext(ctx context.Context, names ...string) (map[string]disk.IOCountersStat, error) {
//	// https://github.com/giampaolo/psutil/blob/544e9daa4f66a9f80d7bf6c7886d693ee42f0a13/psutil/arch/windows/disk.c#L83
//	drivemap := make(map[string]disk.IOCountersStat, 0)
//	var diskPerformance diskPerformance
//	lpBuffer := make([]uint16, 254)
//	lpBufferLen, err := windows.GetLogicalDriveStrings(uint32(len(lpBuffer)), &lpBuffer[0])
//	if err != nil {
//		return drivemap, err
//	}
//	for _, v := range lpBuffer[:lpBufferLen] {
//		if 'A' <= v && v <= 'Z' {
//			path := string(v) + ":"
//			typepath, _ := windows.UTF16PtrFromString(path)
//			typeret := windows.GetDriveType(typepath)
//			if typeret == 0 {
//				return drivemap, windows.GetLastError()
//			}
//			if typeret != windows.DRIVE_FIXED {
//				continue
//			}
//			szDevice := fmt.Sprintf(`\\.\%s`, path)
//			const IOCTL_DISK_PERFORMANCE = 0x70020
//			h, err := windows.CreateFile(syscall.StringToUTF16Ptr(szDevice), 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
//			if err != nil {
//				if err == windows.ERROR_FILE_NOT_FOUND {
//					continue
//				}
//				return drivemap, err
//			}
//			defer windows.CloseHandle(h)
//			var diskPerformanceSize uint32
//			err = windows.DeviceIoControl(h, IOCTL_DISK_PERFORMANCE, nil, 0, (*byte)(unsafe.Pointer(&diskPerformance)), uint32(unsafe.Sizeof(diskPerformance)), &diskPerformanceSize, nil)
//			if err != nil {
//				return drivemap, err
//			}
//			drivemap[path] = disk.IOCountersStat{
//				ReadBytes:  uint64(diskPerformance.BytesRead),
//				WriteBytes: uint64(diskPerformance.BytesWritten),
//				ReadCount:  uint64(diskPerformance.ReadCount),
//				WriteCount: uint64(diskPerformance.WriteCount),
//				ReadTime:   uint64(diskPerformance.ReadTime / 10000 / 1000), // convert to ms: https://github.com/giampaolo/psutil/issues/1012
//				WriteTime:  uint64(diskPerformance.WriteTime / 10000 / 1000),
//				Name:       path,
//			}
//		}
//	}
//	return drivemap, nil
//}
func GetLogicalDriveStringsW(lpBuffer []byte) (uint32, error) {
	diskret, _, err := procGetLogicalDriveStringsW.Call(uintptr(len(lpBuffer)), uintptr(unsafe.Pointer(&lpBuffer[0])))
	return uint32(diskret), err
}

func GetDiskFreeSpaceExW(path string, lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes *int64) (bool, error) {
	diskret, _, err := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(path))),
		uintptr(unsafe.Pointer(lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(lpTotalNumberOfBytes)),
		uintptr(unsafe.Pointer(lpTotalNumberOfFreeBytes)))
	return diskret != 0, err
}

func FindCloseChangeNotification(hHandle syscall.Handle) bool {
	ret, _, _ := procFindCloseChangeNotification.Call(uintptr(hHandle))
	return ret != 0
}

func FindNextChangeNotification(hHandle syscall.Handle) bool {
	ret, _, _ := procFindNextChangeNotification.Call(uintptr(hHandle))
	return ret != 0
}

func WaitForMultipleObjects(nCount int, hHandle HANDLE, bWaitAll bool, dwMilliseconds int) DWORD {
	bWait := 0
	if bWaitAll {
		bWait = 1
	}
	ret, _, _ := procWaitForMultipleObjects.Call(
		uintptr(nCount),
		uintptr(hHandle),
		uintptr(bWait),
		uintptr(dwMilliseconds),
	)

	return DWORD(ret)
}

func FindFirstChangeNotification(lpPathName *uint16, bWatchSubtree bool, dwNotifyFilter uint32) (HANDLE, error) {
	bWatch := 0
	if bWatchSubtree {
		bWatch = 1
	}
	ret, _, err := procFindFirstChangeNotification.Call(uintptr(unsafe.Pointer(lpPathName)), uintptr(bWatch), uintptr(dwNotifyFilter))

	return HANDLE(ret), err
}

func IsWow64Process(handle HANDLE, isWow64 *bool) (err error) {
	var _p0 uint32
	if *isWow64 {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _, e1 := syscall.Syscall(procIsWow64Process.Addr(), 2, uintptr(handle), uintptr(unsafe.Pointer(&_p0)), 0)
	*isWow64 = _p0 != 0
	if r1 == 0 {
		if e1 != 0 {
			err = syscall.Errno(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
func CreateProcessA(lpApplicationName *string,
	lpCommandLine string,
	lpProcessAttributes *syscall.SecurityAttributes,
	lpThreadAttributes *syscall.SecurityAttributes,
	bInheritHandles bool,
	dwCreationFlags uint32,
	lpEnvironment *string,
	lpCurrentDirectory *uint16,
	lpStartupInfo *syscall.StartupInfo,
	lpProcessInformation *syscall.ProcessInformation) {

	inherit := 0
	if bInheritHandles {
		inherit = 1
	}

	procCreateProcessA.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(*lpApplicationName))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpCommandLine))),
		uintptr(unsafe.Pointer(lpProcessAttributes)),
		uintptr(unsafe.Pointer(lpThreadAttributes)),
		uintptr(inherit),
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpEnvironment)),
		uintptr(unsafe.Pointer(lpCurrentDirectory)),
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)))
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx
func VirtualAllocEx(hProcess HANDLE, lpAddress int, dwSize int, flAllocationType int, flProtect int) (addr uintptr, err error) {
	ret, _, err := procVirtualAllocEx.Call(
		uintptr(hProcess),  // The handle to a process.
		uintptr(lpAddress), // The pointer that specifies a desired starting address for the region of pages that you want to allocate.
		uintptr(dwSize),    // The size of the region of memory to allocate, in bytes.
		uintptr(flAllocationType),
		uintptr(flProtect))
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366887(v=vs.85).aspx
func VirtualAlloc(lpAddress int, dwSize int, flAllocationType int, flProtect int) (addr uintptr, err error) {
	ret, _, err := procVirtualAlloc.Call(
		uintptr(lpAddress), // The starting address of the region to allocate
		uintptr(dwSize),    // The size of the region of memory to allocate, in bytes.
		uintptr(flAllocationType),
		uintptr(flProtect))
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}
 
func VirtualFreeEx(hProcess HANDLE, lpAddress, dwSize uintptr, dwFreeType uint32) bool {
	ret, _, _ := procVirtualFreeEx.Call(
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(dwFreeType),
	)

	return ret != 0
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms683212(v=vs.85).aspx
func GetProcAddress(hProcess HANDLE, procname string) (addr uintptr, err error) {
	var pn uintptr

	if procname == "" {
		pn = 0
	} else {
		pn = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(procname)))
	}

	ret, _, err := procGetProcAddress.Call(uintptr(hProcess), pn)
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx 
//func CreateRemoteThread(hprocess HANDLE, sa *syscall.SecurityAttributes, stackSize uint32, startAddress uintptr, parameter uintptr, creationFlags uint32, threadId uint32) (HANDLE, error) {
//	r1, _, e1 := procCreateRemoteThread.Call(
//		uintptr(hprocess),
//		uintptr(unsafe.Pointer(sa)),
//		uintptr(stackSize),
//		uintptr(startAddress),
//		uintptr(parameter),
//		uintptr(creationFlags),
//		uintptr(unsafe.Pointer(&threadId)))
//
//	return HANDLE(r1), e1
//}

func CreateRemoteThread(process syscall.Handle, sa *syscall.SecurityAttributes, stackSize uint32, startAddress,
	parameter uintptr, creationFlags uint32) (syscall.Handle, uint32, error) {
	var threadId uint32
	r1, _, e1 := procCreateRemoteThread.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(sa)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&threadId)))

	if int(r1) == 0 {
		return syscall.InvalidHandle, 0, os.NewSyscallError("CreateRemoteThread", e1)
	}
	return syscall.Handle(r1), threadId, nil
}

func GetModuleHandle(modulename string) HINSTANCE {
	var mn uintptr
	if modulename == "" {
		mn = 0
	} else {
		mn = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(modulename)))
	}
	ret, _, _ := procGetModuleHandle.Call(mn)
	return HINSTANCE(ret)
}

func MulDiv(number, numerator, denominator int) int {
	ret, _, _ := procMulDiv.Call(
		uintptr(number),
		uintptr(numerator),
		uintptr(denominator))

	return int(ret)
}

func GetConsoleWindow() HWND {
	ret, _, _ := procGetConsoleWindow.Call()

	return HWND(ret)
}

func GetCurrentThread() HANDLE {
	ret, _, _ := procGetCurrentThread.Call()

	return HANDLE(ret)
}

func GetLogicalDrives() uint32 {
	ret, _, _ := procGetLogicalDrives.Call()

	return uint32(ret)
}

func GetUserDefaultLCID() uint32 {
	ret, _, _ := procGetUserDefaultLCID.Call()

	return uint32(ret)
}

func Lstrlen(lpString *uint16) int {
	ret, _, _ := procLstrlen.Call(uintptr(unsafe.Pointer(lpString)))

	return int(ret)
}

func Lstrcpy(buf []uint16, lpString *uint16) {
	procLstrcpy.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(lpString)))
}

func GlobalAlloc(uFlags uint, dwBytes uint32) HGLOBAL {
	ret, _, _ := procGlobalAlloc.Call(
		uintptr(uFlags),
		uintptr(dwBytes))

	if ret == 0 {
		panic("GlobalAlloc failed")
	}

	return HGLOBAL(ret)
}

func GlobalFree(hMem HGLOBAL) {
	ret, _, _ := procGlobalFree.Call(uintptr(hMem))

	if ret != 0 {
		panic("GlobalFree failed")
	}
}

func GlobalLock(hMem HGLOBAL) unsafe.Pointer {
	ret, _, _ := procGlobalLock.Call(uintptr(hMem))

	if ret == 0 {
		panic("GlobalLock failed")
	}

	return unsafe.Pointer(ret)
}

func GlobalUnlock(hMem HGLOBAL) bool {
	ret, _, _ := procGlobalUnlock.Call(uintptr(hMem))

	return ret != 0
}

func MoveMemory(destination, source unsafe.Pointer, length uint32) {
	procMoveMemory.Call(
		uintptr(unsafe.Pointer(destination)),
		uintptr(source),
		uintptr(length))
}

func FindResource(hModule HMODULE, lpName, lpType *uint16) (HRSRC, error) {
	ret, _, _ := procFindResource.Call(
		uintptr(hModule),
		uintptr(unsafe.Pointer(lpName)),
		uintptr(unsafe.Pointer(lpType)))

	if ret == 0 {
		return 0, syscall.GetLastError()
	}

	return HRSRC(ret), nil
}

func SizeofResource(hModule HMODULE, hResInfo HRSRC) uint32 {
	ret, _, _ := procSizeofResource.Call(
		uintptr(hModule),
		uintptr(hResInfo))

	if ret == 0 {
		panic("SizeofResource failed")
	}

	return uint32(ret)
}

func LockResource(hResData HGLOBAL) unsafe.Pointer {
	ret, _, _ := procLockResource.Call(uintptr(hResData))

	if ret == 0 {
		panic("LockResource failed")
	}

	return unsafe.Pointer(ret)
}

func LoadResource(hModule HMODULE, hResInfo HRSRC) HGLOBAL {
	ret, _, _ := procLoadResource.Call(
		uintptr(hModule),
		uintptr(hResInfo))

	if ret == 0 {
		panic("LoadResource failed")
	}

	return HGLOBAL(ret)
}

func GetLastError() uint32 {
	ret, _, _ := procGetLastError.Call()
	return uint32(ret)
}

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle HANDLE, err error) {
	inherit := 0
	if inheritHandle {
		inherit = 1
	}

	ret, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(inherit),
		uintptr(processId))
	if err != nil && err.Error() == "The operation completed successfully." {
		err = nil
	}
	handle = HANDLE(ret)
	return
}

func TerminateProcess(hProcess HANDLE, uExitCode uint) bool {
	ret, _, _ := procTerminateProcess.Call(
		uintptr(hProcess),
		uintptr(uExitCode))
	return ret != 0
}

func CloseHandle(object HANDLE) bool {
	ret, _, _ := procCloseHandle.Call(
		uintptr(object))
	return ret != 0
}

func CreateToolhelp32Snapshot(flags, processId uint32) HANDLE {
	ret, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(flags),
		uintptr(processId))

	if ret <= 0 {
		return HANDLE(0)
	}

	return HANDLE(ret)
}

func Module32First(snapshot HANDLE, me *MODULEENTRY32) bool {
	ret, _, _ := procModule32First.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(me)))

	return ret != 0
}

func Module32Next(snapshot HANDLE, me *MODULEENTRY32) bool {
	ret, _, _ := procModule32Next.Call(
		uintptr(snapshot),
		uintptr(unsafe.Pointer(me)))

	return ret != 0
}

func GetSystemTimes(lpIdleTime, lpKernelTime, lpUserTime *FILETIME) bool {
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(lpIdleTime)),
		uintptr(unsafe.Pointer(lpKernelTime)),
		uintptr(unsafe.Pointer(lpUserTime)))

	return ret != 0
}

func GetProcessTimes(hProcess HANDLE, lpCreationTime, lpExitTime, lpKernelTime, lpUserTime *FILETIME) bool {
	ret, _, _ := procGetProcessTimes.Call(
		uintptr(hProcess),
		uintptr(unsafe.Pointer(lpCreationTime)),
		uintptr(unsafe.Pointer(lpExitTime)),
		uintptr(unsafe.Pointer(lpKernelTime)),
		uintptr(unsafe.Pointer(lpUserTime)))

	return ret != 0
}

func GetConsoleScreenBufferInfo(hConsoleOutput HANDLE) *CONSOLE_SCREEN_BUFFER_INFO {
	var csbi CONSOLE_SCREEN_BUFFER_INFO
	ret, _, _ := procGetConsoleScreenBufferInfo.Call(
		uintptr(hConsoleOutput),
		uintptr(unsafe.Pointer(&csbi)))
	if ret == 0 {
		return nil
	}
	return &csbi
}

func SetConsoleTextAttribute(hConsoleOutput HANDLE, wAttributes uint16) bool {
	ret, _, _ := procSetConsoleTextAttribute.Call(
		uintptr(hConsoleOutput),
		uintptr(wAttributes))
	return ret != 0
}

func GetDiskFreeSpaceEx(dirName string) (r bool,
	freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64) {
	ret, _, _ := procGetDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(dirName))),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)))
	return ret != 0,
		freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes
}

func GetSystemTime() (time SYSTEMTIME, err error) {
	_, _, err = procGetSystemTime.Call(
		uintptr(unsafe.Pointer(&time)))
	if err.Error() != ErrSuccess {
		return
	}
	err = nil
	return
}

func SetSystemTime(time *SYSTEMTIME) (err error) {
	_, _, err = procSetSystemTime.Call(
		uintptr(unsafe.Pointer(time)))
	if err.Error() != ErrSuccess {
		return
	}
	err = nil
	return
}

//Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms681674(v=vs.85).aspx
//func WriteProcessMemory(hProcess HANDLE, lpBaseAddress uint32, data []byte, size uint) (err error) {
//	var numBytesRead uintptr
//
//	_, _, err = procWriteProcessMemory.Call(uintptr(hProcess),
//		uintptr(lpBaseAddress),
//		uintptr(unsafe.Pointer(&data[0])),
//		uintptr(size),
//		uintptr(unsafe.Pointer(&numBytesRead)))
//	if err.Error() != ErrSuccess {
//		return
//	}
//	err = nil
//	return
//}

func WriteProcessMemory(hProcess HANDLE, lpBaseAddress, lpBuffer, nSize uintptr) bool {
	var nBytesWritten int
	ret, _, _ := procWriteProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		lpBuffer,
		nSize,
		uintptr(unsafe.Pointer(&nBytesWritten)),
	)

	return ret != 0
}

//
////Write process memory with a source of uint32
//func WriteProcessMemoryAsUint32(hProcess HANDLE, lpBaseAddress uint32, data uint32) (err error) {
//
//	bData := make([]byte, 4)
//	binary.LittleEndian.PutUint32(bData, data)
//	err = WriteProcessMemory(hProcess, lpBaseAddress, bData, 4)
//	if err != nil {
//		return
//	}
//	return
//}

//Reads data from an area of memory in a specified process. The entire area to be read must be accessible or the operation fails.
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms680553(v=vs.85).aspx
func ReadProcessMemory(hProcess HANDLE, lpBaseAddress uint32, size uint) (data []byte, err error) {
	var numBytesRead uintptr
	data = make([]byte, size)

	_, _, err = procReadProcessMemory.Call(uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&numBytesRead)))
	if err.Error() != ErrSuccess {
		return
	}
	err = nil
	return
}

//Read process memory and convert the returned data to uint32
func ReadProcessMemoryAsUint32(hProcess HANDLE, lpBaseAddress uint32) (buffer uint32, err error) {
	data, err := ReadProcessMemory(hProcess, lpBaseAddress, 4)
	if err != nil {
		return
	}
	buffer = binary.LittleEndian.Uint32(data)
	return
}

//Adds or removes an application-defined HandlerRoutine function from the list of handler functions for the calling process.
//https://msdn.microsoft.com/en-us/library/windows/desktop/ms686016(v=vs.85).aspx
func SetConsoleCtrlHandler(handlerRoutine func(DWORD) int32, add uint) (err error) {
	_, _, err = procSetConsoleCtrlHandler.Call(uintptr(unsafe.Pointer(&handlerRoutine)),
		uintptr(add))
	if err.Error() != ErrSuccess {
		return
	}
	err = nil
	return
}
