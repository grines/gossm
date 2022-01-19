package implantkill

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func Kill(procid string) string {
	pid, err := strconv.Atoi(procid)

	if err != nil {
		return err.Error()
	}

	p, err := os.FindProcess(pid)

	if err != nil {
		return err.Error()
	}

	p.Signal(syscall.SIGKILL)
	out := fmt.Sprintf("Killed process with PID %s", procid)

	return out

}
