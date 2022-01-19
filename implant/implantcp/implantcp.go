package implantcp

import (
	"fmt"
	"io"
	"os"
)

func Copy(src, dst string) (string, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return "", err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	out := fmt.Sprintf("Copied file %s to %s with size:%d", src, dst, nBytes)

	return out, err
}
