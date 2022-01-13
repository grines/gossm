package implantps

import (
	"fmt"

	"github.com/mitchellh/go-ps"
)

func Ps() []string {
	var processes []string
	processList, _ := ps.Processes()

	for x := range processList {
		var process ps.Process
		process = processList[x]
		data := fmt.Sprintf("%d\t%s\n", process.Pid(), process.Executable())
		processes = append(processes, data)

	}
	return processes
}
