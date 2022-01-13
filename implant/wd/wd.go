package wd

import "os"

func WorkingDir() string {
	path, _ := os.Getwd()
	return path
}
