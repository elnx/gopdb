package gopdb

import (
	"io"
	"os"
	"testing"
)

func benchPDBPath(b *testing.B) string {
	b.Helper()
	p := os.Getenv("GOPDB_TEST_FILE")
	if p == "" {
		b.Skip("GOPDB_TEST_FILE not set, skipping benchmark")
	}
	f, err := os.Open(p)
	if err != nil {
		b.Fatalf("cannot open GOPDB_TEST_FILE: %v", err)
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err == nil && magic[0] == 'M' && magic[1] == 'Z' {
		b.Skipf("GOPDB_TEST_FILE appears to be a PE file, not a PDB: %s", p)
	}
	return p
}

func BenchmarkOpenMSF(b *testing.B) {
	path := benchPDBPath(b)
	for b.Loop() {
		msf, err := OpenMSF(path)
		if err != nil {
			b.Fatal(err)
		}
		msf.Close()
	}
}

func BenchmarkOpenPDB(b *testing.B) {
	path := benchPDBPath(b)
	for b.Loop() {
		pdb, err := OpenPDB(path)
		if err != nil {
			b.Fatal(err)
		}
		pdb.Close()
	}
}

func BenchmarkParseSymbols(b *testing.B) {
	path := benchPDBPath(b)
	pdb, err := OpenPDB(path)
	if err != nil {
		b.Fatal(err)
	}
	defer pdb.Close()

	for b.Loop() {
		pdb.Symbols = nil
		if err := pdb.parseSymbols(); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(pdb.Symbols)), "symbols/op")
}

func BenchmarkReadAllStreams(b *testing.B) {
	path := benchPDBPath(b)
	msf, err := OpenMSF(path)
	if err != nil {
		b.Fatal(err)
	}
	defer msf.Close()

	for b.Loop() {
		for idx := range msf.Streams {
			if msf.Streams[idx].Size == 0 {
				continue
			}
			data, err := msf.ReadStream(idx)
			if err != nil {
				b.Fatalf("stream %d: %v", idx, err)
			}
			_ = data
		}
	}
}
