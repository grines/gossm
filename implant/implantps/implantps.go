package implantps

import (
	"fmt"

	"github.com/keybase/go-ps"
)

func Ps() []string {
	var processes []string
	processList, _ := ps.Processes()

	for x := range processList {
		var process ps.Process
		process = processList[x]
		//path, _ := process.Path()
		data := fmt.Sprintf("%d\t%d\t%s", process.Pid(), process.PPid(), process.Executable())
		processes = append(processes, data)

	}
	return processes
}
