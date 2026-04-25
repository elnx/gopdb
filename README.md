# gopdb

Pure Go library and CLI tools for Windows PDB symbol files.

## Tools

### `gopdb` — PDB symbol parser

Parses PDB (MSF 7.00) files and outputs symbol maps.

```bash
go run ./cmd/gopdb win32kbase.pdb 0x180000000
```

Output: `symbol_name,virtual_address,symtype,section_name`

### `symchk` — PE scanner + PDB downloader

Scans PE files for debug info, downloads matching PDBs from symbol servers.

```bash
go run ./cmd/symchk -r -o /tmp/symbols ./bin
```

## Packages

### `github.com/elnx/gopdb`

PDB parser API:

```go
pdb, err := gopdb.OpenPDB("path/to/file.pdb")
if err != nil { ... }
defer pdb.Close()

for _, sym := range pdb.Symbols {
    fmt.Printf("%s: offset=%#x segment=%d\n", sym.Name, sym.Offset, sym.Segment)
}
```

### `github.com/elnx/gopdb/symdl`

PE parsing + PDB download API:

```go
info, err := symdl.ReadPDBInfo("kernel32.dll")
// info.Name = "kernel32.pdb", info.GUIDAge = "..."

cfg, _ := symdl.LoadConfig("/tmp/symbols")
checker := symdl.Checker{Config: cfg, Ctx: ctx}
result := checker.Check("kernel32.dll")
// result.Status = "downloaded"
```

## Building

```bash
make build       # gopdb binary
make build-all   # gopdb + symchk binaries
```

## Testing

```bash
make test
make test GOPDB_TEST_FILE=/path/to/file.pdb
```
