package pcapreader

import (
	"encoding/binary"
	"io"
	"time"
)

const magicMicroseconds = 0xA1B2C3D4
const magicNanoseconds = 0xA1B23C4D
const magicMicrosecondsBigendian = 0xD4C3B2A1
const magicNanosecondsBigendian = 0x4D3CB2A1

func checkMagic(header []byte) (binary.ByteOrder, uint32, error) {
	// always read in little endian so that the
	// order is not determined by the machine
	// that this code runs on
	magic := binary.LittleEndian.Uint32(header[0:4])
	switch magic {
	case magicNanoseconds:
		return binary.LittleEndian, 1, nil
	case magicNanosecondsBigendian:
		return binary.BigEndian, 1, nil
	case magicMicroseconds:
		return binary.LittleEndian, 1000, nil
	case magicMicrosecondsBigendian:
		return binary.BigEndian, 1000, nil
	default:
		return nil, 0, ErrMalformedPcap
	}
}

type pcap struct {
	// weather the traffic source has been stopped
	// in this case this means that the pcap file
	// has been closed already
	dead bool
	// the source stream to read from.
	// this stems from an opened file
	reader io.ReadCloser
	// the byte order of the data in the pcap.
	// The magic in the pcap header tells what
	// byte order the pcap is in.
	byteOrder binary.ByteOrder
	// the largest packet size
	snaplen uint32
	// what protocol is the data in
	// i.e. was the data recorded from an
	// ethernet network card
	llt LinkLayerType

	// this is used for more precise timestamps
	// the magic in the global header determines
	// what time factor is used
	nanoSecsFactor uint32
	// only one packet at a time is being read
	// so store the data in here so only one
	// allocation is required but multiple
	// pcaps can be opened at the same time
	// (non-static allocation)

	packetHeader []byte
	packetData   []byte
}

/* Convenience functions for getting certain packet header data */

func (p *pcap) timeStampSecs() uint32 {
	return p.byteOrder.Uint32(p.packetHeader[:4])
}

func (p *pcap) timeStampMSecs() uint32 {
	return p.byteOrder.Uint32(p.packetHeader[4:8])
}

func (p *pcap) packetSavedSize() uint32 {
	return p.byteOrder.Uint32(p.packetHeader[8:12])
}

func (p *pcap) packetActualSize() uint32 {
	return p.byteOrder.Uint32(p.packetHeader[12:16])
}

/* Interface functions */

func (p *pcap) LinkLayerType() LinkLayerType {
	return p.llt
}

func (p *pcap) Next() (*PacketInfo, Packet, error) {
	if p.dead {
		return nil, nil, ErrTrafficSourceAlreadyStopped
	}

	var err error

	// read header
	_, err = io.ReadFull(p.reader, p.packetHeader)
	switch {
	// no more data to read
	case err == io.EOF:
		p.Stop()
		return nil, nil, io.EOF
	case err == io.ErrUnexpectedEOF:
		p.Stop()
		return nil, nil, ErrMalformedPcap
	case err != nil:
		p.Stop()
		return nil, nil, err
	default:
	}

	// read data
	savedSize := p.packetSavedSize()

	if savedSize > p.snaplen {
		p.Stop()
		return nil, nil, ErrMalformedPcap
	}

	err = binary.Read(p.reader, p.byteOrder, p.packetData[0:savedSize])
	switch {
	case err == io.EOF && savedSize == 0:
		p.Stop()
		return nil, nil, io.EOF
	case err == io.ErrUnexpectedEOF || err == io.EOF:
		p.Stop()
		return nil, nil, ErrMalformedPcap
	case err != nil:
		p.Stop()
		return nil, nil, err
	}

	return &PacketInfo{
		CaptureTime: time.Unix(int64(p.timeStampSecs()), int64(p.timeStampMSecs()*p.nanoSecsFactor)).UTC(),
		// size is the size of the packet not how it is saved
		Size: p.packetActualSize(),
	}, p.packetData[0:savedSize], nil
}

func (p *pcap) Stop() {
	if !p.dead {
		p.reader.Close()
	}
	p.dead = true
}

/*  */

func readPcap(reader io.ReadCloser) (Traffic, error) {
	header := make([]byte, 24)
	n, err := io.ReadFull(reader, header)

	// accept eof as err as it indicates
	// invalid pcap header
	if err != nil && err != io.EOF {
		reader.Close()
		return nil, err
	}
	if n != len(header) {
		reader.Close()
		return nil, ErrMalformedPcap
	}
	switch err {
	case io.EOF:
		reader.Close()
		return nil, ErrEmptyPcap
	case io.ErrUnexpectedEOF:
		reader.Close()
		return nil, ErrMalformedPcap
	case nil:
		// nothing to do here
	default:
		return nil, err
	}

	byteOrder, nanoSecsFactor, err := checkMagic(header)
	if err != nil {
		reader.Close()
		return nil, err
	}

	// only version 2.4 is supported. This format
	// considered current since 1998. See:
	// https://wiki.wireshark.org/Development/LibpcapFileFormat
	major := byteOrder.Uint16(header[4:6])
	minor := byteOrder.Uint16(header[6:8])
	if major != 2 || minor != 4 {
		reader.Close()
		return nil, ErrPcapVersionNotSupported
	}

	snaplen := byteOrder.Uint32(header[16:20])
	return &pcap{
		reader:         reader,
		nanoSecsFactor: nanoSecsFactor,
		byteOrder:      byteOrder,
		snaplen:        snaplen,
		llt:            LinkLayerType(byteOrder.Uint32(header[20:24])),
		packetHeader:   make([]byte, 16),
		packetData:     make([]byte, snaplen),
	}, nil
}
