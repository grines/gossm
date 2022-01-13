package pwd

import (
	"os"
)

func Pwd() (string, error) {

	return os.Getwd()
}
