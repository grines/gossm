package awsssm

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
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
		fmt.Println("Got Token.")
	}
	return data
}

func GetRunCommandMessages(tokens awsrsa.AwsToken, managedInstanceID string) awsrsa.DocMessage {
	req, body := awsauth.BuildRequest("ec2messages", "us-east-1", `{"Destination":"`+managedInstanceID+`","MessagesRequestId":"`+awsrsa.UniqueID()+`","VisibilityTimeoutInSeconds":10}`)

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
