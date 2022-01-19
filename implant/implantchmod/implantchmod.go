package implantchmod

import (
	"syscall"
)

func Chmod(filename string, mode int) bool {
	err := syscall.Chmod(filename, uint32(mode))
	if err == nil {
		return true
	}
	return false
}
