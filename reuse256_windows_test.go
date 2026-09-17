package cycletls

import (
	"syscall"
	"unsafe"
)

func init() {
	getHandleCount := syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	reuse256HandleCount = func() uint32 {
		process, err := syscall.GetCurrentProcess()
		if err != nil {
			panic(err)
		}
		var count uint32
		ok, _, err := getHandleCount.Call(uintptr(process), uintptr(unsafe.Pointer(&count)))
		if ok == 0 {
			panic(err)
		}
		return count
	}
}
