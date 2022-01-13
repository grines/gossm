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

# get command output
aws ssm get-command-invocation \                                                                                               130 ↵
    --command-id "8c4a6c6e-236e-416b-8b77-d9b3a0e73c8f" \
    --instance-id "mi-0d416eb76fdc3f731" --profile sliver --region us-east-1 --no-verify-ssl

