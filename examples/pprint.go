package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Sojamann/pcapreader"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s file\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	path, err := filepath.Abs(filepath.Clean(os.Args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, "The provided filepath is invalid")
		os.Exit(1)
	}
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "Could not get file information of %s. Make sure it exists!\n", path)
		os.Exit(1)
	}

	traffic, err := pcapreader.OpenFile(os.Args[1])

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could read the traffic. Reason %v\n", err)
		os.Exit(1)
	}

	for {
		info, _, err := traffic.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "Could not fetch the next packet. Reason: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%v\t%d\n", info.CaptureTime.Format("2006-01-02 15:04:05.000000"), info.Size)
	}
}
