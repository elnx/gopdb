# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

---

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
- `symdl` package supports `_NT_SYMBOL_PATH` env var parsing (`srv*cache*upstream` format).

## Test Data

Set `GOPDB_TEST_FILE` to a PDB file path to run PDB-dependent tests. Without it, those tests are skipped (only basic error-handling tests run).

```bash
GOPDB_TEST_FILE=/path/to/file.pdb go test -v ./...
```

Set `GOPDB_TEST_PE_FILE` to a PE file path to run PE-dependent tests (ReadPDBInfo end-to-end).

```bash
GOPDB_TEST_PE_FILE=/path/to/file.dll GOPDB_TEST_FILE=/path/to.pdb go test -v ./...
```

## Reference

PDB parser ported from Python `pdbparse` library. Reference output verified byte-identical via `diff`.
Symbol downloader ported from `symchk.go` project.
