package implantenv

import (
	"os"
	"strings"
)

func Env() string {

	return strings.Join(os.Environ(), "\n")
}
