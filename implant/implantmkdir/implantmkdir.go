package implantmkdir

import (
	"fmt"
	"os"
)

func Mkdir(directory string) string {
	err := os.Mkdir(directory, 0777)
	if err != nil {
		return err.Error()
	}
	out := fmt.Sprintf("Created directory: %s", directory)

	return out
}
