package gopdb

import (
	"os"
	"testing"
)

func benchPDBPath(b *testing.B) string {
	b.Helper()
	p := os.Getenv("GOPDB_TEST_FILE")
	if p == "" {
		b.Skip("GOPDB_TEST_FILE not set, skipping benchmark")
	}
	return p
}

func BenchmarkOpenMSF(b *testing.B) {
	path := benchPDBPath(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msf, err := OpenMSF(path)
		if err != nil {
			b.Fatal(err)
		}
		msf.Close()
	}
}

func BenchmarkOpenPDB(b *testing.B) {
	path := benchPDBPath(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
