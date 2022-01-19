package implantexec

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func Exec(c string, args []string) string {
	cmd, err := exec.LookPath(c)
	if err != nil {
		fmt.Println(err)
	}
	syscall.Exec(cmd, args, os.Environ())
	out := fmt.Sprintf("Executed %s %v", c, args)
	fmt.Println(out)

	return out
}
