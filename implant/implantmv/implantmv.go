package implantmv

import (
	"fmt"
	"os"
)

type Arguments struct {
	SourceFile      string
	DestinationFile string
}

func Mv(args Arguments) string {
	if _, err := os.Stat(args.SourceFile); os.IsNotExist(err) {
		return err.Error()
	}

	err := os.Rename(args.SourceFile, args.DestinationFile)

	if err != nil {
		return err.Error()
	}

	out := fmt.Sprintf("Moved %s to %s", args.SourceFile, args.DestinationFile)
	return out
}
