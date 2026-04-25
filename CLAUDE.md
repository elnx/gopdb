# CLAUDE.md

## Project Overview

Pure Go PDB (MSF 7.00) symbol parser and PE symbol downloader. Zero external dependencies.

## Commands

```bash
go build ./...              # build all
go test -v ./...            # run tests
go build -o gopdb ./cmd/gopdb   # build PDB parser CLI
go build -o symchk ./cmd/symchk # build PE scanner CLI
make build-all              # build both binaries
```

## Architecture

| Package | Purpose |
|---------|---------|
| `gopdb/` (root) | PDB parser: MSF container, DBI stream, section headers, symbol records, OMAP |
| `gopdb/symdl` | PE scanner + PDB downloader: CodeView parsing, symbol server download, temp file management |
| `cmd/gopdb` | CLI: `gopdb <pdb> <base_addr>` → `name,hex_addr,symtype,section` |
| `cmd/symchk` | CLI: `symchk [-r] [-v] [-t n] [-o dir] <file|dir>` → PE scan + PDB download |

## Key Design Notes

- All byte order is little-endian (`binary.LittleEndian`).
- MSF root directory uses two levels of indirection: root index pages → root page list → root data.
- OMAP remap uses binary search.
- `ActiveSections()` returns `OrigSections` if present (for OMAP scenarios), else `Sections`.
- Symbol types: `S_PUB32_V3 = 0x110E` (null-terminated name), `S_PUB32_V2 = 0x1009` (length-prefixed name).
- Addresses are 64-bit in the CLI (`uint64`) but offsets within PDB are 32-bit (`uint32`).
- `symdl` package supports `NT_SYMBOL_PATH` env var parsing (`srv*cache*upstream` format).

## Test Data

Set `GOPDB_TEST_FILE` to a PDB file path to run PDB-dependent tests. Without it, those tests are skipped (only basic error-handling tests run).

```bash
GOPDB_TEST_FILE=/path/to/file.pdb go test -v ./...
```

## Reference

PDB parser ported from Python `pdbparse` library. Reference output verified byte-identical via `diff`.
Symbol downloader ported from `symchk.go` project.
