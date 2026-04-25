package symdl

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	DefaultSymbolServer      = "https://msdl.microsoft.com/download/symbols"
	imageDirectoryEntryDebug = 6
	imageDebugTypeCodeView   = 2
	tempFileMarker           = ".symchk."
	tempFileSuffix           = ".tmp"
)

type Config struct {
	CacheDir string
	Upstream string
}

type PDBInfo struct {
	Name    string
	GUIDAge string
}

type Result struct {
	Path      string
	Status    string
	Message   string
	PDBName   string
	GUIDAge   string
	CachePath string
	URL       string
}

type Summary struct {
	Processed  int
	Cached     int
	Downloaded int
	Missing    int
	Failures   int
}

type Checker struct {
	Ctx       context.Context
	Config    Config
	Client    *http.Client
	Verbose   bool
	TempFiles *TempFileManager
}

type checkFunc func(string) Result

type checkTask struct {
	index int
	path  string
}

type checkResult struct {
	index  int
	result Result
}

type TempFileManager struct {
	pid     int
	session string

	mu     sync.Mutex
	active map[string]struct{}
}

var pidExists = processExists

func NewTempFileManager() (*TempFileManager, error) {
	session, err := randomToken(8)
	if err != nil {
		return nil, err
	}
	return &TempFileManager{
		pid:     os.Getpid(),
		session: session,
		active:  make(map[string]struct{}),
	}, nil
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (m *TempFileManager) newTempPattern(cachePath string) string {
	base := filepath.Base(cachePath)
	return fmt.Sprintf("%s%s%d.%s.*%s", base, tempFileMarker, m.pid, m.session, tempFileSuffix)
}

func (m *TempFileManager) Register(path string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.active[path] = struct{}{}
	m.mu.Unlock()
}

func (m *TempFileManager) Unregister(path string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.active, path)
	m.mu.Unlock()
}

func (m *TempFileManager) CleanupStale(cacheDir string) error {
	if m == nil || cacheDir == "" {
		return nil
	}
	if _, err := os.Stat(cacheDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	return filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		pid, ok := parseSymchkTempPID(filepath.Base(path))
		if !ok {
			return nil
		}
		if pidExists(pid) {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

func parseSymchkTempPID(name string) (int, bool) {
	if !strings.HasSuffix(name, tempFileSuffix) {
		return 0, false
	}
	idx := strings.Index(name, tempFileMarker)
	if idx < 0 {
		return 0, false
	}
	rest := strings.TrimSuffix(name[idx+len(tempFileMarker):], tempFileSuffix)
	parts := strings.Split(rest, ".")
	if len(parts) < 3 {
		return 0, false
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 0 {
		return 0, false
	}
	if parts[1] == "" {
		return 0, false
	}
	return pid, true
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if err := proc.Signal(syscall.Signal(0)); err == nil {
		return true
	}
	return !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, syscall.ESRCH)
}

func LoadConfig(outputDir string) (Config, error) {
	value := strings.TrimSpace(os.Getenv("NT_SYMBOL_PATH"))
	if value != "" {
		cfg, ok, err := ParseSymbolPath(value)
		if err != nil {
			return Config{}, err
		}
		if ok {
			if outputDir != "" {
				cfg.CacheDir = outputDir
			}
			if cfg.Upstream == "" {
				cfg.Upstream = DefaultSymbolServer
			}
			return cfg, nil
		}
	}

	cacheDir := filepath.Join(".cache", "symbols")
	if outputDir != "" {
		cacheDir = outputDir
	}

	return Config{
		CacheDir: cacheDir,
		Upstream: DefaultSymbolServer,
	}, nil
}

func ParseSymbolPath(value string) (Config, bool, error) {
	entries := strings.Split(value, ";")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		lower := strings.ToLower(entry)
		if strings.HasPrefix(lower, "srv*") {
			parts := strings.Split(entry, "*")
			if len(parts) < 2 {
				return Config{}, false, fmt.Errorf("invalid srv entry %q", entry)
			}

			cacheDir := ""
			upstream := ""
			for _, part := range parts[1:] {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				if cacheDir == "" {
					cacheDir = part
					continue
				}
				if upstream == "" {
					upstream = part
					break
				}
			}
			if cacheDir == "" {
				return Config{}, false, fmt.Errorf("missing cache directory in %q", entry)
			}
			return Config{CacheDir: cacheDir, Upstream: upstream}, true, nil
		}

		if !strings.Contains(entry, "*") {
			return Config{CacheDir: entry}, true, nil
		}
	}

	return Config{}, false, nil
}

func CollectTargets(target string, recurse bool) ([]string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if !isPEPath(target) {
			return nil, fmt.Errorf("%s is not a supported PE file", target)
		}
		return []string{target}, nil
	}

	if !recurse {
		return nil, fmt.Errorf("%s is a directory, use recurse=true to recurse", target)
	}

	var files []string
	err = filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if isPEPath(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

func isPEPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".dll", ".sys", ".ocx", ".drv":
		return true
	default:
		return false
	}
}

func IsPE(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 'M' && magic[1] == 'Z'
}

func RunChecks(checker Checker, files []string, parallelism int) ([]Result, Summary) {
	return runChecksWith(checker.Ctx, checker.Check, files, parallelism)
}

func runChecksWith(ctx context.Context, check checkFunc, files []string, parallelism int) ([]Result, Summary) {
	results := make([]Result, len(files))

	if len(files) == 0 {
		return results, Summary{}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if parallelism < 1 {
		parallelism = 1
	}
	if parallelism > len(files) {
		parallelism = len(files)
	}

	if parallelism == 1 {
		var summary Summary
		for i, path := range files {
			if err := ctx.Err(); err != nil {
				results[i] = Result{Path: path, Status: "download-failed", Message: err.Error()}
				summary.Add(results[i])
				for j := i + 1; j < len(files); j++ {
					results[j] = Result{Path: files[j], Status: "download-failed", Message: err.Error()}
					summary.Add(results[j])
				}
				return results, summary
			}
			result := check(path)
			results[i] = result
			summary.Add(result)
		}
		return results, summary
	}

	tasks := make(chan checkTask)
	out := make(chan checkResult, len(files))
	var wg sync.WaitGroup

	for range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task, ok := <-tasks:
					if !ok {
						return
					}
					out <- checkResult{index: task.index, result: check(task.path)}
				}
			}
		}()
	}

	go func() {
		defer close(tasks)
		for i, path := range files {
			select {
			case <-ctx.Done():
				return
			case tasks <- checkTask{index: i, path: path}:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	var summary Summary
	seen := make([]bool, len(files))
	for item := range out {
		results[item.index] = item.result
		seen[item.index] = true
	}
	for i, result := range results {
		if !seen[i] {
			result = Result{Path: files[i]}
			if err := ctx.Err(); err != nil {
				result.Status = "download-failed"
				result.Message = err.Error()
			}
			results[i] = result
		}
		summary.Add(results[i])
	}
	return results, summary
}

func (c Checker) Check(filePath string) Result {
	result := Result{Path: filePath}
	if c.Ctx == nil {
		c.Ctx = context.Background()
	}
	if err := c.Ctx.Err(); err != nil {
		result.Status = "download-failed"
		result.Message = err.Error()
		return result
	}

	info, err := ReadPDBInfo(filePath)
	if err != nil {
		result.Status = "missing-debug-info"
		result.Message = err.Error()
		return result
	}

	result.PDBName = info.Name
	result.GUIDAge = info.GUIDAge
	result.CachePath = LocalSymbolPath(c.Config.CacheDir, info)
	if c.Config.Upstream != "" {
		result.URL = UpstreamSymbolURL(c.Config.Upstream, info)
	}

	if _, err := os.Stat(result.CachePath); err == nil {
		result.Status = "cached"
		return result
	} else if !errors.Is(err, os.ErrNotExist) {
		result.Status = "download-failed"
		result.Message = err.Error()
		return result
	}

	if c.Config.Upstream == "" {
		result.Status = "missing"
		result.Message = "symbol not in cache and no upstream configured"
		return result
	}

	if err := DownloadSymbol(c.Ctx, c.Client, result.URL, result.CachePath, c.TempFiles); err != nil {
		result.Status = "download-failed"
		result.Message = err.Error()
		return result
	}

	result.Status = "downloaded"
	return result
}

func ReadPDBInfo(filePath string) (PDBInfo, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return PDBInfo{}, err
	}
	defer f.Close()

	var debugDir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) <= imageDirectoryEntryDebug {
			return PDBInfo{}, errors.New("no debug directory")
		}
		debugDir = oh.DataDirectory[imageDirectoryEntryDebug]
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) <= imageDirectoryEntryDebug {
			return PDBInfo{}, errors.New("no debug directory")
		}
		debugDir = oh.DataDirectory[imageDirectoryEntryDebug]
	default:
		return PDBInfo{}, errors.New("unsupported PE optional header")
	}

	if debugDir.VirtualAddress == 0 || debugDir.Size == 0 {
		return PDBInfo{}, errors.New("no debug directory")
	}

	debugOffset, err := rvaToOffset(f, debugDir.VirtualAddress)
	if err != nil {
		return PDBInfo{}, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return PDBInfo{}, err
	}
	defer file.Close()

	entriesSize := binary.Size(imageDebugDirectory{})
	count := int(debugDir.Size) / entriesSize
	for i := 0; i < count; i++ {
		var entry imageDebugDirectory
		if _, err := file.Seek(int64(debugOffset)+int64(i*entriesSize), io.SeekStart); err != nil {
			return PDBInfo{}, err
		}
		if err := binary.Read(file, binary.LittleEndian, &entry); err != nil {
			return PDBInfo{}, err
		}
		if entry.Type != imageDebugTypeCodeView || entry.SizeOfData < 24 {
			continue
		}

		data := make([]byte, entry.SizeOfData)
		if _, err := file.ReadAt(data, int64(entry.PointerToRawData)); err != nil {
			return PDBInfo{}, err
		}
		info, err := parseCodeViewData(data)
		if err == nil {
			return info, nil
		}
	}

	return PDBInfo{}, errors.New("no CodeView RSDS record found")
}

type imageDebugDirectory struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
}

func parseCodeViewData(data []byte) (PDBInfo, error) {
	if len(data) < 24 {
		return PDBInfo{}, errors.New("CodeView data too small")
	}
	if !bytes.Equal(data[:4], []byte("RSDS")) {
		return PDBInfo{}, errors.New("unsupported CodeView signature")
	}

	guidAge := FormatGUIDAge(data[4:20], binary.LittleEndian.Uint32(data[20:24]))
	nameBytes := data[24:]
	idx := bytes.IndexByte(nameBytes, 0)
	if idx >= 0 {
		nameBytes = nameBytes[:idx]
	}
	name := filepath.Base(string(nameBytes))
	if name == "" {
		return PDBInfo{}, errors.New("empty PDB name")
	}

	return PDBInfo{Name: name, GUIDAge: guidAge}, nil
}

func FormatGUIDAge(guid []byte, age uint32) string {
	if len(guid) != 16 {
		return ""
	}
	return fmt.Sprintf("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
		binary.LittleEndian.Uint32(guid[0:4]),
		binary.LittleEndian.Uint16(guid[4:6]),
		binary.LittleEndian.Uint16(guid[6:8]),
		guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15],
		age,
	)
}

func rvaToOffset(f *pe.File, rva uint32) (uint32, error) {
	for _, section := range f.Sections {
		size := section.VirtualSize
		if size == 0 {
			size = section.Size
		}
		start := section.VirtualAddress
		end := start + size
		if rva >= start && rva < end {
			return section.Offset + (rva - start), nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%X not mapped to a section", rva)
}

func LocalSymbolPath(cacheDir string, info PDBInfo) string {
	return filepath.Join(cacheDir, info.Name, info.GUIDAge, info.Name)
}

func UpstreamSymbolURL(base string, info PDBInfo) string {
	base = strings.TrimRight(base, "/")
	relative := path.Join(info.Name, info.GUIDAge, info.Name)
	return base + "/" + relative
}

func DownloadSymbol(ctx context.Context, client *http.Client, symbolURL, cachePath string, tempFiles *TempFileManager) error {
	if client == nil {
		client = http.DefaultClient
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, symbolURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	pattern := filepath.Base(cachePath) + ".*.tmp"
	if tempFiles != nil {
		pattern = tempFiles.newTempPattern(cachePath)
	}
	tmp, err := os.CreateTemp(filepath.Dir(cachePath), pattern)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if tempFiles != nil {
		tempFiles.Register(tmpPath)
		defer tempFiles.Unregister(tmpPath)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, cachePath); err != nil {
		return err
	}
	return nil
}

func (s *Summary) Add(result Result) {
	s.Processed++
	switch result.Status {
	case "cached":
		s.Cached++
	case "downloaded":
		s.Downloaded++
	case "missing", "missing-debug-info":
		s.Missing++
	default:
		s.Failures++
	}
}
