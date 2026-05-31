package handler

import (
	"io/ioutil"
	"os"
)

// VULN-6: Double close / resource leak
func ProcessFiles(fileA, fileB string) {
	f1, err := os.Open(fileA)
	if err != nil {
		return
	}
	defer f1.Close()

	f2, err := os.Open(fileB)
	if err != nil {
		// double close on f1
		f1.Close()
		f1.Close()
		return
	}
	defer f2.Close()

	_, _ = ioutil.ReadAll(f1)
	_, _ = ioutil.ReadAll(f2)
}