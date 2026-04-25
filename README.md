# gopdb

Pure Go library and CLI tools for Windows PDB symbol files. Zero external dependencies.

[![Go Reference](https://pkg.go.dev/badge/github.com/elnx/gopdb.svg)](https://pkg.go.dev/github.com/elnx/gopdb)

## Install

```bash
go install github.com/elnx/gopdb/cmd/gopdb@latest
go install github.com/elnx/gopdb/cmd/symchk@latest
```

## CLI Usage

```bash
# From a PDB file (fast, no network)
gopdb kernel32.pdb 0x180000000

# From a PE file (auto-downloads PDB, then parses)
gopdb kernel32.dll 0x180000000

# Scan directory, download missing PDBs
symchk -r -v ./system32
```

## Library Usage

### Import

```go
import (
    "github.com/elnx/gopdb"         // PDB parse
    "github.com/elnx/gopdb/symdl"    // PE scan + PDB download
)
```

### From a PDB file

```go
pdb, err := gopdb.OpenPDB("kernel32.pdb")
if err != nil {
    log.Fatal(err)
}
defer pdb.Close()

for _, sym := range pdb.Symbols {
    fmt.Printf("%s,%#x,%d,%s\n",
        sym.Name, sym.Offset, sym.SymType, sym.Segment)
}
```

### From a PE file (auto-download + parse)

```go
// Simple — defaults: .cache/symbols/, msdl.microsoft.com
pdb, err := gopdb.OpenPE("kernel32.dll")
if err != nil {
    log.Fatal(err)
}
defer pdb.Close()

for _, sym := range pdb.Symbols {
    fmt.Printf("%s,%#x,%d,%s\n", sym.Name, sym.Offset, sym.SymType, sym.Segment)
}
```

```go
// Custom — specific cache dir, context, HTTP client
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

pdb, err := gopdb.OpenPE("kernel32.dll", &gopdb.OpenPEOptions{
    CacheDir: "/tmp/symbols",
    Context:  ctx,
})
if err != nil {
    log.Fatal(err)
}
defer pdb.Close()
```

### Extract PDB info from PE without downloading

```go
info, err := symdl.ReadPDBInfo("kernel32.dll")
if err != nil {
    log.Fatal(err)
}
fmt.Println(info.Name)    // "kernel32.pdb"
fmt.Println(info.GUIDAge) // "12345678..."
```

### Batch check/download PDBs for many PE files

```go
cfg, _ := symdl.LoadConfig("")
checker := symdl.Checker{
    Ctx:    context.Background(),
    Config: cfg,
    Client: &http.Client{Timeout: 30 * time.Second},
}

files, _ := symdl.CollectTargets("./bin", true)
results, summary := symdl.RunChecks(checker, files, 4)

fmt.Printf("done: %d cached, %d downloaded\n",
    summary.Cached, summary.Downloaded)
```

## Packages

| Package | Purpose |
|---------|---------|
| `gopdb` | PDB parser: MSF container, DBI stream, section headers, symbol records, OMAP |
| `symdl` | PE scanner + PDB downloader: CodeView parsing, symbol server, temp file mgmt |

## CLI Tools

| Binary | What it does |
|--------|--------------|
| `cmd/gopdb` | `gopdb <file> <base_addr>` — parse PDB or PE into CSV symbol map |
| `cmd/symchk` | `symchk [-r] [-v] [-t n] [-o dir] <file\|dir>` — scan PE, download PDB |

## Build

```bash
make build-all       # gopdb + symchk binaries
go build ./...       # all packages
```

## Test

```bash
GOPDB_TEST_FILE=/path/to/file.pdb GOPDB_TEST_PE_FILE=/path/to/file.dll go test -v ./...
```
