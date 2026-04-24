# gopdb

Pure Go library and CLI tool for parsing Microsoft PDB (Program Database) symbol files (MSF 7.00 format).

Ported from [pdb_map.py](https://github.com/moyix/pdbparse) — outputs symbol maps identical to the Python version.

## Features

- Parse PDB v7 (MSF 7.00) container format
- Extract section headers (IMAGE_SECTION_HEADER)
- Parse global/public symbols (S_PUB32_V2 / S_PUB32_V3)
- OMAP address remapping support
- Zero external dependencies (pure Go standard library)

## Usage

### CLI

```bash
go run ./cmd/gopdb <pdb_file> <base_address>
```

Example:

```bash
go run ./cmd/gopdb win32kbase.pdb 0x180000000
```

Output format (CSV, one symbol per line):

```
symbol_name,virtual_address,symtype,section_name
```

### Library

```go
pdb, err := gopdb.OpenPDB("path/to/file.pdb")
if err != nil { ... }
defer pdb.Close()

for _, sym := range pdb.Symbols {
    fmt.Printf("%s: offset=%#x segment=%d type=%d\n",
        sym.Name, sym.Offset, sym.Segment, sym.SymType)
}
```

## Building

```bash
go build ./...
go build -o gopdb ./cmd/gopdb
```

## Testing

```bash
go test -v ./...
```

Tests require `/home/qwe/syz1/vm/win32kbase.pdb` to be present (skipped otherwise).

## Implementation

The parser handles these PDB internal structures:

| Component | Description |
|-----------|-------------|
| MSF Container | Multi-stream file format with page-based I/O |
| Root Directory | Two-level indirection for stream page tables |
| DBI Stream | Debug info header with sub-stream references |
| Section Headers | COFF-style IMAGE_SECTION_HEADER (40 bytes each) |
| Symbol Records | S_PUB32_V2 (0x1009) and S_PUB32_V3 (0x110E) |
| OMAP | Address re-mapping table with binary search |
