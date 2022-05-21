package pcapreader

import (
	"errors"
	"time"
)

type Packet []byte
type PacketInfo struct {
	CaptureTime time.Time
	Size        uint32
}

type LinkLayerType uint32

var ErrTrafficSourceAlreadyStopped = errors.New("the traffic source has already been stopped")

type Traffic interface {
	// Returns the some information of the packet
	// and the packet. io.EOF when done.
	// The returned data is only valid until
	// the next call to Next(). The data can be
	// modified if required but this is generally
	// not adviced. When a copy of the data is
	// really necessary, the user of this library
	// has to do so.
	// When an error occurs, the data source
	// is stopped automatically.
	Next() (*PacketInfo, Packet, error)

	// Returns the LinkLayerType of the traffic.
	// This for example can be ethernet if
	// the traffic stems from a ethernet network card.
	// See: https://www.tcpdump.org/linktypes.html
	LinkLayerType() LinkLayerType

	// Closes open files or stops reading
	// from network interfaces
	Stop()
}

var (
	ErrMalformedPcap           = errors.New("PCAP(ng) file is malformed")
	ErrPcapVersionNotSupported = errors.New("invalid PCAP(NG) version")
	ErrEmptyPcap               = errors.New("PCAP(NG) file is empty")
)
