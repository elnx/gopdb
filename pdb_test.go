package gopdb

import (
	"os"
	"path/filepath"
	"testing"
)

func testPDBPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv("GOPDB_TEST_FILE")
	if p == "" {
		t.Skip("GOPDB_TEST_FILE not set, skipping PDB-dependent test")
	}
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skipf("GOPDB_TEST_FILE not found: %s", p)
	}
	return p
}

func TestOpenMSF(t *testing.T) {
	testPDB := testPDBPath(t)
	msf, err := OpenMSF(testPDB)
	if err != nil {
		t.Fatalf("OpenMSF: %v", err)
	}
	defer msf.Close()

	if msf.PageSize == 0 || msf.PageSize&(msf.PageSize-1) != 0 {
		t.Errorf("PageSize = %d, want power of 2", msf.PageSize)
	}
	if msf.NumPages == 0 {
		t.Errorf("NumPages = 0")
	}
	if len(msf.Streams) == 0 {
		t.Errorf("no streams found")
	}
}

func TestReadStream(t *testing.T) {
	testPDB := testPDBPath(t)
	msf, err := OpenMSF(testPDB)
	if err != nil {
		t.Fatal(err)
	}
	defer msf.Close()

	data, err := msf.ReadStream(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("DBI stream is empty")
	}
}

func TestOpenPDBSections(t *testing.T) {
	testPDB := testPDBPath(t)
	pdb, err := OpenPDB(testPDB)
	if err != nil {
		t.Fatalf("OpenPDB: %v", err)
	}
	defer pdb.Close()

	if len(pdb.Sections) == 0 {
		t.Fatal("no sections found")
	}

	for i, s := range pdb.Sections {
		if s.Name == "" {
			t.Errorf("Section[%d] has empty name", i)
		}
	}
}

func TestSymbols(t *testing.T) {
	testPDB := testPDBPath(t)
	pdb, err := OpenPDB(testPDB)
	if err != nil {
		t.Fatal(err)
	}
	defer pdb.Close()

	if len(pdb.Symbols) == 0 {
		t.Fatal("no symbols parsed")
	}

	for _, sym := range pdb.Symbols {
		if sym.Name == "" {
			t.Error("symbol with empty name")
		}
		if sym.Segment == 0 {
			t.Errorf("symbol %q has segment 0", sym.Name)
		}
	}
}

func TestRemapNoOMap(t *testing.T) {
	testPDB := testPDBPath(t)
	pdb, err := OpenPDB(testPDB)
	if err != nil {
		t.Fatal(err)
	}
	defer pdb.Close()

	if len(pdb.OMapFromSrc) > 0 {
		t.Skip("PDB has OMAP, test expects no OMAP")
	}

	addr := uint32(0x1234)
	if got := pdb.Remap(addr); got != addr {
		t.Errorf("Remap(%#x) = %#x, want %#x", addr, got, addr)
	}
}

func TestActiveSections(t *testing.T) {
	testPDB := testPDBPath(t)
	pdb, err := OpenPDB(testPDB)
	if err != nil {
		t.Fatal(err)
	}
	defer pdb.Close()

	sects := pdb.ActiveSections()
	if len(sects) == 0 {
		t.Fatal("ActiveSections() returned empty")
	}
	expected := pdb.Sections
	if len(pdb.OrigSections) > 0 {
		expected = pdb.OrigSections
	}
	if len(sects) != len(expected) {
		t.Errorf("ActiveSections() = %d sections, want %d", len(sects), len(expected))
	}
}

func TestInvalidPath(t *testing.T) {
	_, err := OpenPDB("/nonexistent/path/test.pdb")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestInvalidSignature(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "bad.pdb")
	if err := os.WriteFile(tmpFile, []byte("NOT_A_PDB_FILE_1234567890123456"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := OpenPDB(tmpFile)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}
