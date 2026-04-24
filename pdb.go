package gopdb

import (
	"encoding/binary"
	"fmt"
)

const (
	streamRoot = 0
	streamPDB  = 1
	streamTPI  = 2
	streamDBI  = 3
)

const (
	symPub32V2 = 0x1009
	symPub32V3 = 0x110E
)

type ImageSectionHeader struct {
	Name           string
	VirtualAddress uint32
	SizeOfRawData  uint32
}

type PublicSymbol struct {
	Name     string
	Offset   uint32
	Segment  uint16
	SymType  uint32
}

type DBIHeader struct {
	Version       uint32
	Age           uint32
	GSSymStream   int16
	PSSymStream   int16
	SymRecStream  int16
	ModuleSize    uint32
	SecConSize    uint32
	SecMapSize    uint32
	FilInfSize    uint32
	TSMapSize     uint32
	MFCIndex      uint32
	DbgHdrSize    uint32
	ECInfoSize    uint32
	Flags         uint16
	Machine       uint16
}

type DBIDbgHeader struct {
	SnFPO           int16
	SnException     int16
	SnFixup         int16
	SnOmapToSrc     int16
	SnOmapFromSrc   int16
	SnSectionHdr    int16
	SnTokenRidMap   int16
	SnXdata         int16
	SnPdata         int16
	SnNewFPO        int16
	SnSectionHdrOrig int16
}

type OMAPEntry struct {
	From uint32
	To   uint32
}

type PDB struct {
	msf         *MSFFile
	Sections    []ImageSectionHeader
	OrigSections []ImageSectionHeader
	OMapFromSrc []OMAPEntry
	Symbols     []PublicSymbol
	dbi         DBIHeader
	dbgHdr      DBIDbgHeader
}

func OpenPDB(path string) (*PDB, error) {
	msf, err := OpenMSF(path)
	if err != nil {
		return nil, fmt.Errorf("open pdb: %w", err)
	}

	p := &PDB{msf: msf}
	if err := p.parse(); err != nil {
		msf.Close()
		return nil, err
	}

	return p, nil
}

func (p *PDB) Close() error {
	return p.msf.Close()
}

func (p *PDB) parse() error {
	if err := p.parseDBI(); err != nil {
		return fmt.Errorf("parse dbi: %w", err)
	}

	if err := p.parseSections(); err != nil {
		return fmt.Errorf("parse sections: %w", err)
	}

	if err := p.parseOMap(); err != nil {
		return fmt.Errorf("parse omap: %w", err)
	}

	if err := p.parseSymbols(); err != nil {
		return fmt.Errorf("parse symbols: %w", err)
	}

	return nil
}

func (p *PDB) parseDBI() error {
	data, err := p.msf.ReadStream(streamDBI)
	if err != nil {
		return err
	}
	if len(data) < 64 {
		return fmt.Errorf("dbi stream too small: %d bytes", len(data))
	}

	le := binary.LittleEndian

	if le.Uint32(data[0:4]) != 0xFFFFFFFF {
		return fmt.Errorf("invalid dbi magic")
	}

	p.dbi.Version = le.Uint32(data[4:8])
	p.dbi.Age = le.Uint32(data[8:12])
	p.dbi.GSSymStream = int16(le.Uint16(data[12:14]))
	p.dbi.PSSymStream = int16(le.Uint16(data[16:18]))
	p.dbi.SymRecStream = int16(le.Uint16(data[20:22]))
	p.dbi.ModuleSize = le.Uint32(data[24:28])
	p.dbi.SecConSize = le.Uint32(data[28:32])
	p.dbi.SecMapSize = le.Uint32(data[32:36])
	p.dbi.FilInfSize = le.Uint32(data[36:40])
	p.dbi.TSMapSize = le.Uint32(data[40:44])
	p.dbi.MFCIndex = le.Uint32(data[44:48])
	p.dbi.DbgHdrSize = le.Uint32(data[48:52])
	p.dbi.ECInfoSize = le.Uint32(data[52:56])
	p.dbi.Flags = le.Uint16(data[56:58])
	p.dbi.Machine = le.Uint16(data[58:60])

	dbgOffset := uint32(64) + p.dbi.ModuleSize + p.dbi.SecConSize +
		p.dbi.SecMapSize + p.dbi.FilInfSize + p.dbi.TSMapSize + p.dbi.ECInfoSize

	if int(dbgOffset)+22 > len(data) {
		return fmt.Errorf("dbi debug header out of bounds at offset %d, data len %d", dbgOffset, len(data))
	}

	p.dbgHdr.SnFPO = int16(le.Uint16(data[dbgOffset:]))
	p.dbgHdr.SnException = int16(le.Uint16(data[dbgOffset+2:]))
	p.dbgHdr.SnFixup = int16(le.Uint16(data[dbgOffset+4:]))
	p.dbgHdr.SnOmapToSrc = int16(le.Uint16(data[dbgOffset+6:]))
	p.dbgHdr.SnOmapFromSrc = int16(le.Uint16(data[dbgOffset+8:]))
	p.dbgHdr.SnSectionHdr = int16(le.Uint16(data[dbgOffset+10:]))
	p.dbgHdr.SnTokenRidMap = int16(le.Uint16(data[dbgOffset+12:]))
	p.dbgHdr.SnXdata = int16(le.Uint16(data[dbgOffset+14:]))
	p.dbgHdr.SnPdata = int16(le.Uint16(data[dbgOffset+16:]))
	p.dbgHdr.SnNewFPO = int16(le.Uint16(data[dbgOffset+18:]))
	p.dbgHdr.SnSectionHdrOrig = int16(le.Uint16(data[dbgOffset+20:]))

	return nil
}

func (p *PDB) parseSectionHeaders(streamIdx int16) ([]ImageSectionHeader, error) {
	if streamIdx < 0 {
		return nil, nil
	}

	data, err := p.msf.ReadStream(int(streamIdx))
	if err != nil {
		return nil, err
	}

	const sectionSize = 40
	if len(data)%sectionSize != 0 {
		return nil, fmt.Errorf("section header data size %d not multiple of %d", len(data), sectionSize)
	}

	numSections := len(data) / sectionSize
	sections := make([]ImageSectionHeader, numSections)
	le := binary.LittleEndian

	for i := 0; i < numSections; i++ {
		off := i * sectionSize
		rawName := data[off : off+8]
		nulIdx := len(rawName)
		for j, b := range rawName {
			if b == 0 {
				nulIdx = j
				break
			}
		}
		sections[i].Name = string(rawName[:nulIdx])
		sections[i].VirtualAddress = le.Uint32(data[off+12 : off+16])
		sections[i].SizeOfRawData = le.Uint32(data[off+8 : off+12])
	}

	return sections, nil
}

func (p *PDB) parseSections() error {
	sects, err := p.parseSectionHeaders(p.dbgHdr.SnSectionHdr)
	if err != nil {
		return err
	}
	p.Sections = sects

	origSects, err := p.parseSectionHeaders(p.dbgHdr.SnSectionHdrOrig)
	if err != nil {
		return err
	}
	p.OrigSections = origSects

	return nil
}

func (p *PDB) parseOMap() error {
	if p.dbgHdr.SnOmapFromSrc < 0 {
		return nil
	}

	data, err := p.msf.ReadStream(int(p.dbgHdr.SnOmapFromSrc))
	if err != nil {
		return err
	}

	entrySize := 8
	numEntries := len(data) / entrySize
	p.OMapFromSrc = make([]OMAPEntry, numEntries)

	le := binary.LittleEndian
	for i := 0; i < numEntries; i++ {
		off := i * entrySize
		p.OMapFromSrc[i].From = le.Uint32(data[off:])
		p.OMapFromSrc[i].To = le.Uint32(data[off+4:])
	}

	return nil
}

func (p *PDB) Remap(addr uint32) uint32 {
	if len(p.OMapFromSrc) == 0 {
		return addr
	}

	lo, hi := 0, len(p.OMapFromSrc)
	for lo < hi {
		mid := (lo + hi) / 2
		if p.OMapFromSrc[mid].From <= addr {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	idx := lo - 1
	if idx < 0 {
		return 0
	}

	if p.OMapFromSrc[idx].To == 0 {
		return 0
	}

	return p.OMapFromSrc[idx].To + (addr - p.OMapFromSrc[idx].From)
}

func (p *PDB) parseSymbols() error {
	if p.dbi.SymRecStream < 0 {
		return fmt.Errorf("no symbol record stream")
	}

	data, err := p.msf.ReadStream(int(p.dbi.SymRecStream))
	if err != nil {
		return err
	}

	le := binary.LittleEndian
	pos := 0

	for pos < len(data) {
		if pos+2 > len(data) {
			break
		}
		recLen := int(le.Uint16(data[pos:]))
		if recLen == 0 {
			break
		}
		if pos+2+recLen > len(data) {
			break
		}

		leafType := le.Uint16(data[pos+2:])
		recordData := data[pos+4 : pos+2+recLen]

		switch leafType {
		case symPub32V3:
			p.parsePub32V3(recordData, le)
		case symPub32V2:
			p.parsePub32V2(recordData, le)
		}

		pos += 2 + recLen
	}

	return nil
}

func (p *PDB) parsePub32V3(data []byte, le binary.ByteOrder) {
	if len(data) < 12 {
		return
	}

	sym := PublicSymbol{}
	sym.SymType = le.Uint32(data[0:4])
	sym.Offset = le.Uint32(data[4:8])
	sym.Segment = le.Uint16(data[8:10])

	nameData := data[10:]
	nulIdx := len(nameData)
	for i, b := range nameData {
		if b == 0 {
			nulIdx = i
			break
		}
	}
	sym.Name = string(nameData[:nulIdx])

	p.Symbols = append(p.Symbols, sym)
}

func (p *PDB) parsePub32V2(data []byte, le binary.ByteOrder) {
	if len(data) < 11 {
		return
	}

	sym := PublicSymbol{}
	sym.SymType = le.Uint32(data[0:4])
	sym.Offset = le.Uint32(data[4:8])
	sym.Segment = le.Uint16(data[8:10])

	nameLen := int(data[10])
	if 11+nameLen > len(data) {
		return
	}
	sym.Name = string(data[11 : 11+nameLen])

	p.Symbols = append(p.Symbols, sym)
}

func (p *PDB) ActiveSections() []ImageSectionHeader {
	if len(p.OrigSections) > 0 {
		return p.OrigSections
	}
	return p.Sections
}
