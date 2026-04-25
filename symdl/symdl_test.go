package symdl

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseSymbolPath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Config
		ok      bool
		wantErr bool
	}{
		{
			name:  "srv cache upstream",
			input: "srv*/tmp/cache*https://msdl.microsoft.com/download/symbols",
			want:  Config{CacheDir: "/tmp/cache", Upstream: "https://msdl.microsoft.com/download/symbols"},
			ok:    true,
		},
		{
			name:  "srv cache only",
			input: "srv*/tmp/cache",
			want:  Config{CacheDir: "/tmp/cache"},
			ok:    true,
		},
		{
			name:  "bare cache path",
			input: "/tmp/cache",
			want:  Config{CacheDir: "/tmp/cache"},
			ok:    true,
		},
		{
			name:    "invalid srv entry",
			input:   "srv*",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := ParseSymbolPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSymbolPath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if ok != tt.ok {
				t.Fatalf("ParseSymbolPath() ok = %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("ParseSymbolPath() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestFormatGUIDAge(t *testing.T) {
	guid := []byte{0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	got := FormatGUIDAge(guid, 3)
	want := "123456789ABCDEF011223344556677883"
	if got != want {
		t.Fatalf("FormatGUIDAge() = %q, want %q", got, want)
	}
}

func TestLocalSymbolPath(t *testing.T) {
	info := PDBInfo{Name: "foo.pdb", GUIDAge: "ABC1234"}
	got := LocalSymbolPath("/tmp/cache", info)
	want := filepath.Join("/tmp/cache", "foo.pdb", "ABC1234", "foo.pdb")
	if got != want {
		t.Fatalf("LocalSymbolPath() = %q, want %q", got, want)
	}
}

func TestCollectTargetsRecursive(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "a.exe"),
		filepath.Join(dir, "b.txt"),
		filepath.Join(dir, "nested", "c.dll"),
	}
	for _, name := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := CollectTargets(dir, true)
	if err != nil {
		t.Fatalf("CollectTargets() error = %v", err)
	}
	want := []string{filepath.Join(dir, "a.exe"), filepath.Join(dir, "nested", "c.dll")}
	if len(got) != len(want) {
		t.Fatalf("CollectTargets() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CollectTargets()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRunChecksWithSequential(t *testing.T) {
	files := []string{"a.exe", "b.dll", "c.sys"}
	results, summary := runChecksWith(context.Background(), func(path string) Result {
		return Result{Path: path, Status: "cached"}
	}, files, 1)

	if len(results) != len(files) {
		t.Fatalf("runChecksWith() len = %d, want %d", len(results), len(files))
	}
	for i, path := range files {
		if results[i].Path != path {
			t.Fatalf("runChecksWith()[%d].Path = %q, want %q", i, results[i].Path, path)
		}
	}
	if summary.Processed != 3 || summary.Cached != 3 || summary.Downloaded != 0 || summary.Missing != 0 || summary.Failures != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestRunChecksWithParallelKeepsOrderAndSummary(t *testing.T) {
	files := []string{"slow.exe", "fast.dll", "mid.sys", "missing.ocx"}
	results, summary := runChecksWith(context.Background(), func(path string) Result {
		switch path {
		case "slow.exe":
			time.Sleep(40 * time.Millisecond)
			return Result{Path: path, Status: "downloaded"}
		case "fast.dll":
			time.Sleep(5 * time.Millisecond)
			return Result{Path: path, Status: "cached"}
		case "mid.sys":
			time.Sleep(20 * time.Millisecond)
			return Result{Path: path, Status: "download-failed", Message: "boom"}
		case "missing.ocx":
			time.Sleep(10 * time.Millisecond)
			return Result{Path: path, Status: "missing"}
		default:
			return Result{Path: path, Status: "cached"}
		}
	}, files, 3)

	if len(results) != len(files) {
		t.Fatalf("runChecksWith() len = %d, want %d", len(results), len(files))
	}
	for i, path := range files {
		if results[i].Path != path {
			t.Fatalf("runChecksWith()[%d].Path = %q, want %q", i, results[i].Path, path)
		}
	}
	if results[0].Status != "downloaded" || results[1].Status != "cached" || results[2].Status != "download-failed" || results[3].Status != "missing" {
		t.Fatalf("unexpected result statuses: %#v", results)
	}
	if summary.Processed != 4 || summary.Cached != 1 || summary.Downloaded != 1 || summary.Missing != 1 || summary.Failures != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestRunChecksWithParallelismLessThanOneFallsBackToOne(t *testing.T) {
	files := []string{"a.exe", "b.dll"}
	results, summary := runChecksWith(context.Background(), func(path string) Result {
		return Result{Path: path, Status: "missing-debug-info"}
	}, files, 0)

	if len(results) != len(files) {
		t.Fatalf("runChecksWith() len = %d, want %d", len(results), len(files))
	}
	if summary.Processed != 2 || summary.Missing != 2 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestTempFileManagerCleanupStaleRemovesDeadPID(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewTempFileManager()
	if err != nil {
		t.Fatal(err)
	}
	oldPidExists := pidExists
	pidExists = func(pid int) bool { return false }
	defer func() { pidExists = oldPidExists }()
	stale := filepath.Join(dir, "foo.pdb", "ABC", "foo.pdb.symchk.999999.deadbeef.123.tmp")
	if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := mgr.CleanupStale(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp file still exists: %v", err)
	}
}

func TestTempFileManagerCleanupStaleKeepsLivePIDAndForeignNames(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewTempFileManager()
	if err != nil {
		t.Fatal(err)
	}
	oldPidExists := pidExists
	pidExists = func(pid int) bool { return pid == os.Getpid() }
	defer func() { pidExists = oldPidExists }()
	live := filepath.Join(dir, "foo.pdb", "ABC", "foo.pdb.symchk."+strconv.Itoa(os.Getpid())+".session.123.tmp")
	foreign := filepath.Join(dir, "foo.pdb", "ABC", "foo.pdb.random.tmp")
	for _, name := range []string{live, foreign} {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := mgr.CleanupStale(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{live, foreign} {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("expected %s to remain: %v", name, err)
		}
	}
}

func TestDownloadSymbolCancelRemovesTempFile(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "foo.pdb", "ABC123", "foo.pdb")
	mgr, err := NewTempFileManager()
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write([]byte("partial"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- DownloadSymbol(ctx, server.Client(), server.URL, cachePath, mgr)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(cachePath), "*.tmp"))
		if globErr != nil {
			t.Fatal(globErr)
		}
		if len(matches) > 0 {
			cancel()
			err = <-errCh
			if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), context.Canceled.Error()) {
				t.Fatalf("DownloadSymbol() error = %v, want context cancellation", err)
			}
			if _, statErr := os.Stat(cachePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("final cache file exists unexpectedly: %v", statErr)
			}
			remaining, globErr := filepath.Glob(filepath.Join(filepath.Dir(cachePath), "*.tmp"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if len(remaining) != 0 {
				t.Fatalf("temp files remain after cancellation: %v", remaining)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	<-errCh
	t.Fatal("timed out waiting for temp file creation")
}

func TestIsPE(t *testing.T) {
	dir := t.TempDir()
	peFile := filepath.Join(dir, "test.pe")
	nonPEFile := filepath.Join(dir, "test.txt")
	noFile := filepath.Join(dir, "nonexistent")

	if err := os.WriteFile(peFile, []byte("MZ\x90\x00\x03\x00\x00\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nonPEFile, []byte("not a PE file"), 0644); err != nil {
		t.Fatal(err)
	}

	if !IsPE(peFile) {
		t.Error("IsPE(peFile) = false, want true")
	}
	if IsPE(nonPEFile) {
		t.Error("IsPE(nonPEFile) = true, want false")
	}
	if IsPE(noFile) {
		t.Error("IsPE(noFile) = true, want false")
	}
}

func TestDownloadSymbolSuccessLeavesOnlyFinalFile(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "foo.pdb", "ABC123", "foo.pdb")
	mgr, err := NewTempFileManager()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	if err := DownloadSymbol(context.Background(), server.Client(), server.URL, cachePath, mgr); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("final cache file missing: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(cachePath), "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp files remain after success: %v", matches)
	}
}

func TestRunChecksWithStopsSchedulingOnCancel(t *testing.T) {
	files := []string{"a.exe", "b.exe", "c.exe", "d.exe", "e.exe", "f.exe"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan string, len(files))
	var count atomic.Int32
	results, summary := runChecksWith(ctx, func(path string) Result {
		started <- path
		if count.Add(1) == 1 {
			cancel()
		}
		time.Sleep(30 * time.Millisecond)
		return Result{Path: path, Status: "cached"}
	}, files, 3)

	startedCount := len(started)
	if startedCount >= len(files) {
		t.Fatalf("expected cancellation to stop scheduling, started=%d len=%d", startedCount, len(files))
	}
	if len(results) != len(files) {
		t.Fatalf("runChecksWith() len = %d, want %d", len(results), len(files))
	}
	if summary.Processed != len(files) {
		t.Fatalf("summary.Processed = %d, want %d", summary.Processed, len(files))
	}
	for i, result := range results {
		if result.Path != files[i] {
			t.Fatalf("results[%d].Path = %q, want %q", i, result.Path, files[i])
		}
	}
	cancelled := 0
	for _, result := range results {
		if result.Message == context.Canceled.Error() {
			cancelled++
		}
	}
	if cancelled == 0 {
		t.Fatal("expected at least one result to reflect cancellation")
	}
}

func TestReadPDBInfoRealPE(t *testing.T) {
	p := os.Getenv("GOPDB_TEST_PE_FILE")
	if p == "" {
		t.Skip("GOPDB_TEST_PE_FILE not set, skipping PE-dependent test")
	}
	if !IsPE(p) {
		t.Skipf("GOPDB_TEST_PE_FILE is not a PE file: %s", p)
	}

	info, err := ReadPDBInfo(p)
	if err != nil {
		t.Fatalf("ReadPDBInfo(%s): %v", p, err)
	}
	if info.Name == "" {
		t.Error("PDBName is empty")
	}
	if info.GUIDAge == "" {
		t.Error("GUIDAge is empty")
	}
	t.Logf("pdb=%s guidage=%s", info.Name, info.GUIDAge)
}
