package gopdb

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	msf7Signature    = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
	msf7SignatureLen = 32
)

type Stream struct {
	Size  uint32
	Pages []uint32
}

type MSFFile struct {
	file     *os.File
	PageSize uint32
	NumPages uint32
	Streams  []Stream
}

func OpenMSF(path string) (*MSFFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open msf: %w", err)
	}

	m := &MSFFile{file: f}
	if err := m.parseHeader(); err != nil {
		f.Close()
		return nil, err
	}

	return m, nil
}

func (m *MSFFile) Close() error {
	if m.file != nil {
		return m.file.Close()
	}
	return nil
}

func (m *MSFFile) parseHeader() error {
	header := make([]byte, msf7SignatureLen+20)
	if _, err := io.ReadFull(m.file, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	sig := string(header[:msf7SignatureLen])
	if sig != msf7Signature {
		return fmt.Errorf("invalid MSF7 signature: %q", sig[:min(len(sig), 20)])
	}

	le := binary.LittleEndian
	m.PageSize = le.Uint32(header[msf7SignatureLen:])
	_ = le.Uint32(header[msf7SignatureLen+4:])
	m.NumPages = le.Uint32(header[msf7SignatureLen+8:])
	rootSize := le.Uint32(header[msf7SignatureLen+12:])
	_ = le.Uint32(header[msf7SignatureLen+16:])

	if m.PageSize == 0 {
		return fmt.Errorf("invalid page size")
	}

	numRootPages := (rootSize + m.PageSize - 1) / m.PageSize
	numRootIndexPages := (numRootPages*4 + m.PageSize - 1) / m.PageSize

	rootIndexPages := make([]uint32, numRootIndexPages)
	for i := range rootIndexPages {
		var buf [4]byte
		if _, err := io.ReadFull(m.file, buf[:]); err != nil {
			return fmt.Errorf("read root index pages: %w", err)
		}
		rootIndexPages[i] = le.Uint32(buf[:])
	}

	rootIndexData := make([]byte, 0, int(numRootIndexPages)*int(m.PageSize))
	for _, pn := range rootIndexPages {
		segment, err := m.readPage(pn)
		if err != nil {
			return fmt.Errorf("read root index page %d: %w", pn, err)
		}
		rootIndexData = append(rootIndexData, segment...)
	}

	if len(rootIndexData) < int(numRootPages)*4 {
		return fmt.Errorf("root index data too small: %d < %d", len(rootIndexData), numRootPages*4)
	}

	rootPageList := make([]uint32, numRootPages)
	for i := uint32(0); i < numRootPages; i++ {
		rootPageList[i] = le.Uint32(rootIndexData[i*4:])
	}

	rootData := make([]byte, 0, int(numRootPages)*int(m.PageSize))
	for _, pn := range rootPageList {
		segment, err := m.readPage(pn)
		if err != nil {
			return fmt.Errorf("read root page %d: %w", pn, err)
		}
		rootData = append(rootData, segment...)
	}
	rootData = rootData[:rootSize]

	if len(rootData) < 4 {
		return fmt.Errorf("root directory too small")
	}

	numStreams := le.Uint32(rootData[0:4])
	offset := uint32(4)

	if numStreams > uint32(len(rootData))/4 {
		return fmt.Errorf("invalid number of streams: %d", numStreams)
	}

	sizes := make([]uint32, numStreams)
	for i := uint32(0); i < numStreams; i++ {
		sz := le.Uint32(rootData[offset : offset+4])
		offset += 4
		if sz == 0xFFFFFFFF {
			sz = 0
		}
		sizes[i] = sz
	}

	m.Streams = make([]Stream, numStreams)
	for i := uint32(0); i < numStreams; i++ {
		if sizes[i] == 0 {
			continue
		}
		np := (sizes[i] + m.PageSize - 1) / m.PageSize
		pages := make([]uint32, np)
		for j := uint32(0); j < np; j++ {
			pages[j] = le.Uint32(rootData[offset : offset+4])
			offset += 4
		}
		m.Streams[i] = Stream{Size: sizes[i], Pages: pages}
	}

	return nil
}

func (m *MSFFile) readPage(pageNum uint32) ([]byte, error) {
	buf := make([]byte, m.PageSize)
	if _, err := m.file.Seek(int64(pageNum)*int64(m.PageSize), io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(m.file, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (m *MSFFile) ReadStream(idx int) ([]byte, error) {
	if idx < 0 || idx >= len(m.Streams) {
		return nil, fmt.Errorf("stream index %d out of range [0, %d)", idx, len(m.Streams))
	}

	s := m.Streams[idx]
	if s.Size == 0 {
		return nil, nil
	}

	result := make([]byte, 0, s.Size)
	for _, pn := range s.Pages {
		page, err := m.readPage(pn)
		if err != nil {
			return nil, fmt.Errorf("read page %d for stream %d: %w", pn, idx, err)
		}
		result = append(result, page...)
	}

	return result[:s.Size], nil
}
