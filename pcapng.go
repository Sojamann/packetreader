package pcapreader

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
	"time"
)

// TODO: error check all io.discard ops
// TODO: save state instead of function pointers
// 			and do lookups in a map. This can also
// 			improve the redundant function signature of
// 			the readers. And might make debugging easier

const ngByteOrderMagic uint32 = 0x1A2B3C4D
const ngUnsetIfId uint32 = 0xFFFFFFFF // max

// Block types that are are worth reading
const (
	// Section Header Block
	// recognizable in big and little endian order
	ngSHB uint32 = 0x0A0D0D0A
	// Interface Description Block
	ngIDB uint32 = 0x00000001
	// Simple Packet Block
	ngSPB uint32 = 0x00000003
	// Enhanced Packet Block
	ngEPB uint32 = 0x00000006
)

// records what state we are currently in
// while reading the pcapng, this is just a name for
// the actual block reader function.
type ngReaderState uint

// The next thing we will read is ...
const (
	// ... nothing because we are either
	// 		done or an error occurred
	ngRSDone ngReaderState = 1 << iota
	// ... a block that we dont care about
	ngRSIgnoreBlock ngReaderState = 1 << iota
	// ... a section that we want to ignore
	ngRSIgnoreSection ngReaderState = 1 << iota
	// ... the block type
	ngRSBlockType ngReaderState = 1 << iota
	// ... the interface description block
	ngRSIDB ngReaderState = 1 << iota
	// ... the section header block
	ngRSSHB ngReaderState = 1 << iota

	// ... the simple packet block
	ngRSSPB ngReaderState = 1 << iota
	// ... the enhanced packet block
	ngRSEPB ngReaderState = 1 << iota

	// ... generally a block that has has data
	// 		that we want to pass along
	ngRSData ngReaderState = ngRSSPB | ngRSEPB
)

type ngReader func(*pcapng) (ngReaderState, error)

var stateToReader map[ngReaderState]ngReader = map[ngReaderState]ngReader{
	ngRSIgnoreBlock:   ngIgnoreBlockReader,
	ngRSIgnoreSection: ngIgnoreSectionReader,
	ngRSBlockType:     pcapngBlockTypeReader,
	ngRSIDB:           ngIDBReader,
	ngRSSHB:           ngSHBReader,
	ngRSSPB:           ngSPBReader,
	ngRSEPB:           ngEPBReader,
}

// this pcapng reader reads the block type and returns the appropriate
// reader for the rest of the block
// this reader starts without requireing any previous informatuin
func pcapngBlockTypeReader(p *pcapng) (ngReaderState, error) {
	var err error
	buff := make([]byte, 4)

	err = p.readFull(buff)

	// as we dont expect any other errors
	// no others are being addressed here
	switch err {
	case io.EOF:
		return ngRSDone, io.EOF
	case io.ErrUnexpectedEOF:
		return ngRSDone, ErrMalformedPcap
	}

	blockType := p.byteOrder.Uint32(buff)

	switch blockType {
	case ngSHB:
		return ngRSSHB, nil
	case ngIDB:
		return ngRSIDB, nil
	case ngSPB:
		return ngRSSPB, nil
	case ngEPB:
		return ngRSEPB, nil
	// if not handled we are just going to ignore this block
	default:
		return ngRSIgnoreBlock, nil
	}
}

// reads the block total length and discards the rest of the block.
// this reader starts reading after the block type has been read
func ngIgnoreBlockReader(p *pcapng) (ngReaderState, error) {
	var err error

	buff := make([]byte, 4)
	err = p.readFull(buff)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	totalLength := p.byteOrder.Uint16(buff)

	// discard the rest of it which is the block len minus what
	// we have already read (block type and block total length)
	err = p.writeNInto(io.Discard, int64(totalLength)-8)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	return ngRSBlockType, nil
}

// discards an entire section by looking at sectionLen and sectionOffset
// it does not matter where this reader starts from as long as all
// reads from p.reader are done using the methods
// p.writeNInto and p.readFull
func ngIgnoreSectionReader(p *pcapng) (ngReaderState, error) {
	_, err := io.CopyN(io.Discard, p.reader, int64(p.sectionLen-p.sectionOffset))
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	return ngRSBlockType, nil
}

// reads section header block and stores this in the pcapng struct.
// this reader starts reading after the block type has been read
func ngSHBReader(p *pcapng) (ngReaderState, error) {
	p.ifCounter = 0
	p.ifId = ngUnsetIfId
	p.snaplen = 0
	p.secondMask = 0
	p.timeZone = 0
	p.timeOffset = 0
	p.sectionOffset = 0

	// this buff in only for
	// - block total length
	// - byte order
	// - major, minor
	// - section length
	buff := make([]byte, 20)

	err := p.readFull(buff)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	// determine byte order
	switch {
	case binary.BigEndian.Uint32(buff[4:8]) == ngByteOrderMagic:
		p.byteOrder = binary.BigEndian
	case binary.LittleEndian.Uint32(buff[4:8]) == ngByteOrderMagic:
		p.byteOrder = binary.LittleEndian
	default:
		return ngRSDone, ErrMalformedPcap
	}

	// size of SHB
	blockLen := p.byteOrder.Uint32(buff[0:4])

	p.sectionLen = p.byteOrder.Uint64(buff[12:20])

	// discard the rest of the block as we dont
	// require the information which is everything
	// except of the header start 8 but and the 4bit
	// block type that has been written before
	discardAmount := int64(blockLen) - (int64(len(buff)) + 4)

	// as per spec, one should treat a minor of 2 as being 0
	major := p.byteOrder.Uint16(buff[8:10])
	minor := p.byteOrder.Uint16(buff[10:12])
	if major != 1 || (minor != 0 && minor != 2) {

		// if the section length is not specified
		// (-1 int64(sectionLen))
		// we can not discard the entire section
		if p.sectionLen != 0xFFFFFFFFFFFFFFFF {
			// discard the entire section + the remaining block
			discardAmount += int64(p.sectionLen)
		}

	}

	p.writeNInto(io.Discard, discardAmount)
	return ngRSBlockType, nil
}

// reads the interface description block.
// the reader starts after the block type has been read.
func ngIDBReader(p *pcapng) (ngReaderState, error) {
	// all variables that on sucess are copied to the struct
	var (
		linkLayerType  LinkLayerType
		snaplen        uint32
		nameHash       uint16
		timeResolution byte = 6
		timeZone       uint32
		timeOffset     uint64
	)

	headerStart := make([]byte, 12)

	err := p.readFull(headerStart)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	// we have to kee everything here, because we still
	// dont know if this interface can even be trusted
	blockLength := p.byteOrder.Uint32(headerStart[0:4])
	linkLayerType = LinkLayerType(p.byteOrder.Uint16(headerStart[4:6]))
	snaplen = p.byteOrder.Uint32(headerStart[8:12])

	// read in options before handling them so from now on we
	// can ignore the interface whenever we want
	options := make([]byte, int(blockLength)-(len(headerStart)+8))
	err = p.readFull(options)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	// data from other link layer are ignored
	if p.linkLayerType != 0 && p.linkLayerType != LinkLayerType(linkLayerType) {
		goto ignoreInterface
	}

optionLoop:
	for optionOffset := 0; optionOffset < len(options); {
		optionCode := p.byteOrder.Uint16(options[optionOffset : optionOffset+2])
		optionValueLen := p.byteOrder.Uint16(options[optionOffset+2 : optionOffset+4])
		optionValue := options[optionOffset+4 : optionOffset+4+int(optionValueLen)]
		switch optionCode {
		case 0: // official end of options
			break optionLoop
		case 2: // if_name
			hash := md5.Sum(optionValue)
			nameHash = binary.BigEndian.Uint16(hash[:])
			if p.ifNameHash != 0 && p.ifNameHash != nameHash {
				goto ignoreInterface
			}

		case 9: // if_tsresol
			timeResolution = optionValue[0]
		case 10: // if_tszone
			timeZone = p.byteOrder.Uint32(optionValue)
		case 14: // if_tsoffset
			timeOffset = p.byteOrder.Uint64(optionValue)
		}

		// check if the option value is aligned to 32 bit (4 byte)
		// If not, advance by the amount of padding bits.
		if optionValueLen%4 != 0 {
			optionOffset += 4 - (int(optionValueLen) % 4)
		}

		optionOffset += 4 + int(optionValueLen) // size of code + size of value
	}

	// copy all into the pcapng struct
	p.ifId = p.ifCounter
	p.ifNameHash = nameHash
	p.snaplen = snaplen
	p.linkLayerType = linkLayerType
	p.timeZone = int32(timeZone)
	p.timeOffset = timeOffset
	// ensure the cap of the data buffer as the
	// largest size is known. But we can grow
	// the buffer when we switch interfaces
	p.packetDataRaw.Grow(int(snaplen))

	if timeResolution>>7 == 1 { // second resolution
		p.secondMask = 1 << timeResolution
	} else { // microsecond resolution
		p.secondMask = 1
		for i := uint8(0); i < timeResolution; i++ {
			p.secondMask *= 10
		}
	}
	p.tsScaleDown = 1
	p.tsScaleUp = 1
	if p.secondMask < 1e9 {
		p.tsScaleUp = 1e9 / p.secondMask
	} else {
		p.tsScaleDown = p.secondMask / 1e9
	}

ignoreInterface:
	// discard final block total length
	err = p.writeNInto(io.Discard, 4)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	p.ifCounter += 1

	return ngRSBlockType, nil
}

// reads a simple packet block
// the reader starts after the block type has been read
func ngSPBReader(p *pcapng) (ngReaderState, error) {
	buff := make([]byte, 8)
	err := p.readFull(buff)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	blockLen := p.byteOrder.Uint32(buff[0:4])
	origPacketLen := p.byteOrder.Uint32(buff[4:8])

	// if no valid interface was found we can ignore the entire section
	if p.ifId == ngUnsetIfId && p.ifCounter > 0 {
		err = p.writeNInto(io.Discard, int64(blockLen)-int64(len(buff)+4)) // header start + block type
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return ngRSDone, ErrMalformedPcap
		}
		return ngRSIgnoreSection, nil
	}

	p.packetDataRaw.Reset()

	// read data into the buffer
	err = p.writeNInto(&p.packetDataRaw, int64(blockLen)-16)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	err = p.writeNInto(io.Discard, 4)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	// set metadata of packet
	p.packetInfo = PacketInfo{
		Size: origPacketLen,
	}

	return ngRSBlockType, nil
}

// reads an extended packet block
// the reader starts after the block type has been read
func ngEPBReader(p *pcapng) (ngReaderState, error) {
	p.packetDataRaw.Reset()

	buff := make([]byte, 24)

	err := p.readFull(buff)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	blockLen := p.byteOrder.Uint32(buff[0:4])
	ifId := p.byteOrder.Uint32(buff[4:8])

	// discard packet as this is not for the interface
	// that we are interested in
	if ifId != p.ifId {
		err = p.writeNInto(io.Discard, int64(blockLen)-int64(len(buff)+4))
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return ngRSDone, ErrMalformedPcap
		}
	}

	packetLen := p.byteOrder.Uint32(buff[16:20])
	err = p.writeNInto(&p.packetDataRaw, int64(packetLen))
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	tsUpper := uint32(p.byteOrder.Uint32(buff[8:12]))
	tsLower := uint32(p.byteOrder.Uint32(buff[12:16]))
	ts := uint64(tsUpper)<<32 | uint64(tsLower)

	p.packetInfo.Size = p.byteOrder.Uint32(buff[20:24])
	p.packetInfo.CaptureTime = time.Unix(int64(ts/p.secondMask+p.timeOffset), int64(ts%p.secondMask*p.tsScaleUp/p.tsScaleDown))

	// discard options and final block total len
	err = p.writeNInto(io.Discard, int64(blockLen)-int64(len(buff)+int(packetLen)+4))
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ngRSDone, ErrMalformedPcap
	}

	return ngRSBlockType, nil
}

type pcapng struct {
	dead   bool
	reader io.ReadCloser

	readState ngReaderState

	// stems from SHB

	byteOrder     binary.ByteOrder
	sectionLen    uint64 // used to skip over the entire section
	sectionOffset uint64 // ^    ^  ^

	// stems from IDB

	// counter for IDBs per section
	ifCounter     uint32
	ifNameHash    uint16        // created just once
	linkLayerType LinkLayerType // created just once
	ifId          uint32        // can be set once per SHB
	snaplen       uint32        // can be set once per SHB
	secondMask    uint64        // can be set once per SHB
	timeZone      int32         // can be set once per SHB
	timeOffset    uint64        // can be set once per SHB
	tsScaleUp     uint64
	tsScaleDown   uint64

	// a struct where we store the packet info.
	// We only allocate space once and place everything
	// in here. This also plays well with the reader
	// logic employed here as they cannot return the
	// extra data.
	packetInfo    PacketInfo
	packetDataRaw bytes.Buffer
}

func (p *pcapng) writeNInto(dst io.Writer, amount int64) (err error) {
	n, err := io.CopyN(dst, p.reader, amount)
	p.sectionOffset += uint64(n)
	return
}

func (p *pcapng) readFull(buff []byte) (err error) {
	n, err := io.ReadFull(p.reader, buff)
	p.sectionOffset += uint64(n)
	return
}

func (p *pcapng) Next() (*PacketInfo, Packet, error) {
	if p.dead {
		return nil, nil, ErrTrafficSourceAlreadyStopped
	}

	// as long as there is no data, read all the blocks that come
	var err error
	err = p.readTo(ngRSData)
	if err != nil {
		return nil, nil, err
	}

	err = p.readTo(^ngRSData)
	if err != nil {
		return nil, nil, err
	}

	return &p.packetInfo, Packet(p.packetDataRaw.Bytes()), nil
}

// When reading a pcapng the LinkLayerType might
// change after reading a different section header block.
// This happens when multiple recordings from different
// interfaces with different LinkLayerTypes are concatenated.
func (p *pcapng) LinkLayerType() LinkLayerType {
	return p.linkLayerType
}

func (p *pcapng) Stop() {
	if !p.dead {
		p.reader.Close()
	}
	p.dead = true
}

// reads until the current state matches the state mask
// or we cannot process any further. This only works
// for aslong the readState is only true at one field
// like a one-hot encoding.
func (p *pcapng) readTo(stateMask ngReaderState) (err error) {
	for p.readState&stateMask == 0 && p.readState != ngRSDone {
		p.readState, err = stateToReader[p.readState](p)
	}

	return
}

func readPcapNg(reader io.ReadCloser) (Traffic, error) {
	var err error
	// for
	// read section header block
	// read interface description block
	// read enhances packet block
	// read simple packet block
	p := &pcapng{
		reader:    reader,
		readState: ngRSSHB,
	}

	// read the first block type
	buff := make([]byte, 4)
	_, err = io.ReadFull(reader, buff)
	if err != nil {
		reader.Close()

		switch err {
		case io.EOF:
			return nil, ErrEmptyPcap
		case io.ErrUnexpectedEOF:
			return nil, ErrMalformedPcap
		default:
			return nil, err
		}
	}

	// the file must start with a section header block
	if binary.BigEndian.Uint32(buff) != ngSHB {
		return nil, ErrMalformedPcap // TODO: actually it is the block type
	}

	// jump ahead until the next thing is some
	// data carrying block
	err = p.readTo(ngRSData)
	if err != nil {
		return nil, err
	}

	return p, nil
}
