package pcapreader

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrUnkownExtension error = errors.New("unknown extension")

func OpenFile(name string) (Traffic, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	switch filepath.Ext(name) {
	case ".pcap":
		return readPcap(f)
	case ".pcapng":
		return readPcapNg(f)
	}

	f.Close()
	return nil, ErrUnkownExtension
}
