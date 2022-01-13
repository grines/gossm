package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/grines/ssmmm/awsauth"
)

const managedInstanceID string = "mi-0d416eb76fdc3f731"
const publicKey string = "MIIEowIBAAKCAQEAwCWYd69ADZjlmqvP+NtnWQi82cq+TmpHMlvNzHm2VXmxgEikNUDGcK9JxsgrIDw6T0EzRFXbl2X2vpqAtX3lV+ALs+sSwNkYrPUtBFwxydxwUHuq+4QJcIfRMsRjwPLOEon5zYBdvbu3AWhq4OHcqmYyTg3kQFW+UeH5Zsh96aDAejlHELtXYxUi12K+roefDQY5G5ePgL3+7UXGfxo/etuNOy9nNPRcNCLTt3dDNP8kc478t50PNpgDmXTataIZahte5IvUeTaaLlYqIl65NJ7RgM2PIDF1yEymnMTWUva1lG5q1Z03r9qpMxuSc2IP5+QVwueTf5OugXVwHCA8wwIDAQABAoIBAQCz3L1rE2ZPFBehgEEOfzqvsiktacZYms2Iiz0KscgHHQIVxmnH25ml87+IzujnpNkkRTEbP49tmimt4+yld3LOnk/2HA8S7GVXya1ZDoAgqDOOcyTriX5Ykxo1fnauL9rMqdFnF0koiOXW8IpTdblc3IssW36U5m5gMbqHBxguLwZQ2LOL0v0w2qDJ6nGE2kAtARVLVnB9YXVy+ouTQ4UH/UeMyZp2SVws0I96vUUZa3GaN8lYQzEKZDeLJU4HzoCvffx5ju3a6OdkS1il5SvoRgdKw/8XiOGlLgqFQLW5/nMQxEzmO9AZxFLxG1RoY8PslrNnk/Ha5azgZpqRfl5hAoGBAMy+EY+/ShJ8uS087sMwVfEEimkxmlFOFWyAvtx9D2ZddEXMn4EbTrFcm6dLawEbrzE67vEvdIS+/ps/ZLQeNCNJZBS6BmriD+2xknPDWPhvqV6gl1Dmc/AESC1OmVCVu/QubveXOFgU5/yBFW0rSVbGnlqCloPwj/uBaWRcPVwTAoGBAPBARqC+iNaM1THDUW/Gq+CN7AsVzXAfy/wPqVWwPS5wDnE7fQLIFB2ugjoxEFX8BAS1GGVNBmNPRT0jmRLtjsRyzdlX0kTMRAvQbPGcHq/5tbEIhHyycrmoD07j0hD2seb4l92YGhNUxfZYxWdg8Rlw4ce6L+m3/Jw6V3S8u1KRAoGAXFKYuKkZTZzQI4YGZB23oybZAvZLD76WCodDiUkbWJ1rgM30XtNheLi5t4ZaifVh2mEovbkYYYN+a6L6Vf4IpKDDcFUx76Bgbl5UG79Krzwqs3DWyrQgM2q64TNADwZ16nXFs/+MeKt0sHfEoaWTPH3zify4wmYHhvGkBI1TXeECgYB+c3Y5GM/xDQMRRBpS2KCSemBonTsZ7sJwktWvsikhjf0sAAGWOzTLQpRsiHJur0x2JdMHTnk0P/7TZS8mVT61iy9pW93iNBkEltkgeel0+dt1qGQDNfFIYnpcLXDdWNreFK3qBiqDTjU7qhGMjeuYVl+fvhGF1D7zA4oQeV2m4QKBgE20jUPRq6u5v6mFqojilGOFuIvGwNMyfcsTE6huImZ+3Mvxh1uvbd4LzV4XfrIlCRbmCQEcgIEx12YjtRalkna506GIIxH8Kl++39Zd7VDAal2MQH5j+IfUGqSsFg1cxWEOOboJRBSDntM47MT9803XEFSU00nSmoFsN1lRWHjP"
const fingerPrint string = "90312ec8-c247-47eb-823f-ad6e8ae1fff5"

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
	header, err := signer3.Presign(req, body, "ec2messages", "us-east-1", 0, time.Now())

	fmt.Println(header)
	fmt.Println(req)
	client2 := &http.Client{}
	resp3, _ := client2.Do(req)
	defer resp3.Body.Close()
	//client3 := &http.Client{}
	//resp3, _ := client2.Do(header)
	//defer resp2.Body.Close()

}
