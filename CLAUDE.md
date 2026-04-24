# CLAUDE.md

## Project Overview

Pure Go PDB (MSF 7.00) symbol parser. No external dependencies.

## Commands

```bash
go build ./...          # build all
go test -v ./...        # run tests
go build -o gopdb ./cmd/gopdb  # build CLI binary
```

## Architecture

- `msf.go` — MSF container parser (page-based multi-stream file). Handles two-level root directory indirection.
- `pdb.go` — PDB stream parser: DBI header, section headers, OMAP remapping, symbol record enumeration (S_PUB32_V2/V3).
- `cmd/gopdb/main.go` — CLI entry point. Output format: `name,hex_addr,symtype,section`.

## Key Design Notes

- All byte order is little-endian (`binary.LittleEndian`).
- MSF root directory uses two levels of indirection: root index pages → root page list → root data.
- OMAP remap uses binary search (`sort.Search` equivalent).
- `ActiveSections()` returns `OrigSections` if present (for OMAP scenarios), else `Sections`.
- Symbol types: `S_PUB32_V3 = 0x110E` (null-terminated name), `S_PUB32_V2 = 0x1009` (length-prefixed name).
- Addresses are 64-bit in the CLI (`uint64`) but offsets within PDB are 32-bit (`uint32`).

## Test Data

Set `GOPDB_TEST_FILE` to a PDB file path to run PDB-dependent tests. Without it, those tests are skipped (only basic error-handling tests run).

```bash
GOPDB_TEST_FILE=/path/to/file.pdb go test -v ./...
```

## Reference

Ported from Python `pdbparse` library. Reference output verified byte-identical via `diff`.
